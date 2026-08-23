//! Per-object envelope encryption and KMS boundary.

use crate::{ServiceError, ServiceResult};
use aes_gcm::aead::{Aead, Payload};
use aes_gcm::{Aes256Gcm, KeyInit, Nonce};
use zeroize::Zeroize;

const ENVELOPE_MAGIC: [u8; 4] = *b"RUE1";
const NONCE_BYTES: usize = 12;
const TAG_BYTES: usize = 16;
const MAX_KEY_ID_BYTES: usize = 255;
const MAX_WRAPPED_KEY_BYTES: usize = 64 * 1024;

/// One KMS-wrapped per-object data-encryption key.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WrappedDataKey {
    key_id: String,
    ciphertext: Vec<u8>,
}

impl WrappedDataKey {
    /// Construct a bounded opaque wrapped key returned by a KMS.
    ///
    /// # Errors
    ///
    /// Refuses empty identifiers and oversized key material.
    pub fn new(key_id: String, ciphertext: Vec<u8>) -> ServiceResult<Self> {
        if key_id.is_empty()
            || key_id.len() > MAX_KEY_ID_BYTES
            || ciphertext.is_empty()
            || ciphertext.len() > MAX_WRAPPED_KEY_BYTES
        {
            return Err(ServiceError::Cryptography("invalid wrapped data key"));
        }
        Ok(Self { key_id, ciphertext })
    }

    /// Opaque provider key identifier.
    #[must_use]
    pub fn key_id(&self) -> &str {
        &self.key_id
    }

    /// Provider-specific wrapped key bytes.
    #[must_use]
    pub fn ciphertext(&self) -> &[u8] {
        &self.ciphertext
    }
}

/// Boundary implemented by AWS KMS, GCP KMS, Vault, HSM, or a test provider.
pub trait DataKeyProvider: Send + Sync {
    /// Wrap one fresh 256-bit object key under tenant-bound associated data.
    ///
    /// # Errors
    ///
    /// Returns an error when the provider cannot authenticate the tenant,
    /// access the wrapping key, or produce a bounded wrapped-key envelope.
    fn wrap(&self, tenant: &str, plaintext_key: &[u8; 32]) -> ServiceResult<WrappedDataKey>;

    /// Recover one object key after validating tenant-bound associated data.
    ///
    /// # Errors
    ///
    /// Returns an error when the key identifier is unknown, tenant binding
    /// fails, or the wrapped key cannot be authenticated.
    fn unwrap(&self, tenant: &str, wrapped: &WrappedDataKey) -> ServiceResult<[u8; 32]>;
}

/// In-process AES-GCM key wrapper for tests and single-node development.
///
/// Production deployments should implement [`DataKeyProvider`] with a KMS or
/// HSM so deleting the persisted wrapped DEK makes an object cryptographically
/// unrecoverable outside the service process.
pub struct LocalKeyProvider {
    key_id: String,
    wrapping_key: [u8; 32],
}

impl LocalKeyProvider {
    /// Construct a local provider from an externally protected wrapping key.
    ///
    /// # Errors
    ///
    /// Refuses an empty or oversized key identifier.
    pub fn new(key_id: impl Into<String>, wrapping_key: [u8; 32]) -> ServiceResult<Self> {
        let key_id = key_id.into();
        if key_id.is_empty() || key_id.len() > MAX_KEY_ID_BYTES {
            return Err(ServiceError::Cryptography(
                "invalid wrapping key identifier",
            ));
        }
        Ok(Self {
            key_id,
            wrapping_key,
        })
    }
}

impl Drop for LocalKeyProvider {
    fn drop(&mut self) {
        self.wrapping_key.zeroize();
    }
}

impl DataKeyProvider for LocalKeyProvider {
    fn wrap(&self, tenant: &str, plaintext_key: &[u8; 32]) -> ServiceResult<WrappedDataKey> {
        let cipher = Aes256Gcm::new_from_slice(&self.wrapping_key)
            .map_err(|_| ServiceError::Cryptography("invalid wrapping key"))?;
        let nonce = random_nonce()?;
        let mut ciphertext = nonce.to_vec();
        ciphertext.extend_from_slice(
            &cipher
                .encrypt(
                    Nonce::from_slice(&nonce),
                    Payload {
                        msg: plaintext_key,
                        aad: tenant.as_bytes(),
                    },
                )
                .map_err(|_| ServiceError::Cryptography("data key wrap failed"))?,
        );
        WrappedDataKey::new(self.key_id.clone(), ciphertext)
    }

    fn unwrap(&self, tenant: &str, wrapped: &WrappedDataKey) -> ServiceResult<[u8; 32]> {
        if wrapped.key_id != self.key_id || wrapped.ciphertext.len() != NONCE_BYTES + 32 + TAG_BYTES
        {
            return Err(ServiceError::Cryptography("unknown wrapped data key"));
        }
        let cipher = Aes256Gcm::new_from_slice(&self.wrapping_key)
            .map_err(|_| ServiceError::Cryptography("invalid wrapping key"))?;
        let plaintext = cipher
            .decrypt(
                Nonce::from_slice(&wrapped.ciphertext[..NONCE_BYTES]),
                Payload {
                    msg: &wrapped.ciphertext[NONCE_BYTES..],
                    aad: tenant.as_bytes(),
                },
            )
            .map_err(|_| ServiceError::Cryptography("data key unwrap failed"))?;
        plaintext
            .try_into()
            .map_err(|_| ServiceError::Cryptography("wrong data key length"))
    }
}

pub(crate) struct EncryptedObject {
    wrapped_key: WrappedDataKey,
    nonce: [u8; NONCE_BYTES],
    plaintext_len: usize,
    ciphertext: Vec<u8>,
}

impl EncryptedObject {
    pub(crate) fn seal(
        provider: &dyn DataKeyProvider,
        tenant: &str,
        aad: &[u8],
        plaintext: &[u8],
    ) -> ServiceResult<Self> {
        let mut data_key = [0u8; 32];
        getrandom::getrandom(&mut data_key)
            .map_err(|_| ServiceError::Cryptography("operating-system randomness failed"))?;
        let wrapped_key = provider.wrap(tenant, &data_key)?;
        let cipher = Aes256Gcm::new_from_slice(&data_key)
            .map_err(|_| ServiceError::Cryptography("invalid object key"))?;
        let nonce = random_nonce()?;
        let result = cipher.encrypt(
            Nonce::from_slice(&nonce),
            Payload {
                msg: plaintext,
                aad,
            },
        );
        data_key.zeroize();
        let ciphertext =
            result.map_err(|_| ServiceError::Cryptography("object encryption failed"))?;
        Ok(Self {
            wrapped_key,
            nonce,
            plaintext_len: plaintext.len(),
            ciphertext,
        })
    }

    pub(crate) fn open(
        &self,
        provider: &dyn DataKeyProvider,
        tenant: &str,
        aad: &[u8],
    ) -> ServiceResult<Vec<u8>> {
        let mut data_key = provider.unwrap(tenant, &self.wrapped_key)?;
        let cipher = Aes256Gcm::new_from_slice(&data_key)
            .map_err(|_| ServiceError::Cryptography("invalid object key"))?;
        let result = cipher.decrypt(
            Nonce::from_slice(&self.nonce),
            Payload {
                msg: &self.ciphertext,
                aad,
            },
        );
        data_key.zeroize();
        let plaintext =
            result.map_err(|_| ServiceError::Cryptography("object authentication failed"))?;
        if plaintext.len() != self.plaintext_len {
            return Err(ServiceError::CorruptState("plaintext length mismatch"));
        }
        Ok(plaintext)
    }

    pub(crate) fn encode(&self) -> ServiceResult<Vec<u8>> {
        let key_id_len = u16::try_from(self.wrapped_key.key_id.len())
            .map_err(|_| ServiceError::CorruptState("key identifier is too long"))?;
        let wrapped_len = u32::try_from(self.wrapped_key.ciphertext.len())
            .map_err(|_| ServiceError::CorruptState("wrapped key is too long"))?;
        let plaintext_len = u64::try_from(self.plaintext_len)
            .map_err(|_| ServiceError::CorruptState("object is too large"))?;
        let mut output = Vec::with_capacity(
            31 + self.wrapped_key.key_id.len()
                + self.wrapped_key.ciphertext.len()
                + self.ciphertext.len(),
        );
        output.extend_from_slice(&ENVELOPE_MAGIC);
        output.push(1);
        output.extend_from_slice(&key_id_len.to_le_bytes());
        output.extend_from_slice(&wrapped_len.to_le_bytes());
        output.extend_from_slice(&plaintext_len.to_le_bytes());
        output.extend_from_slice(&self.nonce);
        output.extend_from_slice(self.wrapped_key.key_id.as_bytes());
        output.extend_from_slice(&self.wrapped_key.ciphertext);
        output.extend_from_slice(&self.ciphertext);
        Ok(output)
    }

    pub(crate) fn decode(bytes: &[u8]) -> ServiceResult<Self> {
        if bytes.len() < 31 + TAG_BYTES || bytes[..4] != ENVELOPE_MAGIC || bytes[4] != 1 {
            return Err(ServiceError::CorruptState("invalid object envelope"));
        }
        let key_id_len = usize::from(u16::from_le_bytes([bytes[5], bytes[6]]));
        let wrapped_len = usize::try_from(u32::from_le_bytes(
            bytes[7..11].try_into().unwrap_or([0; 4]),
        ))
        .map_err(|_| ServiceError::CorruptState("wrapped key length overflow"))?;
        let plaintext_len = usize::try_from(u64::from_le_bytes(
            bytes[11..19].try_into().unwrap_or([0; 8]),
        ))
        .map_err(|_| ServiceError::CorruptState("plaintext length overflow"))?;
        if key_id_len == 0 || key_id_len > MAX_KEY_ID_BYTES || wrapped_len > MAX_WRAPPED_KEY_BYTES {
            return Err(ServiceError::CorruptState("invalid envelope lengths"));
        }
        let key_start: usize = 31;
        let wrapped_start = key_start
            .checked_add(key_id_len)
            .ok_or(ServiceError::CorruptState("envelope length overflow"))?;
        let ciphertext_start = wrapped_start
            .checked_add(wrapped_len)
            .ok_or(ServiceError::CorruptState("envelope length overflow"))?;
        if ciphertext_start + TAG_BYTES > bytes.len() {
            return Err(ServiceError::CorruptState("truncated object envelope"));
        }
        let key_id = core::str::from_utf8(&bytes[key_start..wrapped_start])
            .map_err(|_| ServiceError::CorruptState("key identifier is not UTF-8"))?;
        let wrapped_key = WrappedDataKey::new(
            key_id.to_owned(),
            bytes[wrapped_start..ciphertext_start].to_vec(),
        )?;
        let mut nonce = [0u8; NONCE_BYTES];
        nonce.copy_from_slice(&bytes[19..31]);
        Ok(Self {
            wrapped_key,
            nonce,
            plaintext_len,
            ciphertext: bytes[ciphertext_start..].to_vec(),
        })
    }
}

fn random_nonce() -> ServiceResult<[u8; NONCE_BYTES]> {
    let mut nonce = [0u8; NONCE_BYTES];
    getrandom::getrandom(&mut nonce)
        .map_err(|_| ServiceError::Cryptography("operating-system randomness failed"))?;
    Ok(nonce)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn envelope_binds_tenant_uri_and_ciphertext() {
        let provider = LocalKeyProvider::new("test", [0x51; 32]).unwrap();
        let plaintext = b"sensitive context";
        let aad = b"ruv://example.com/acme/user/alice/resources/docs/item?rev=sha256:00";
        let sealed = EncryptedObject::seal(&provider, "acme", aad, plaintext).unwrap();
        let encoded = sealed.encode().unwrap();
        let decoded = EncryptedObject::decode(&encoded).unwrap();
        assert_eq!(decoded.open(&provider, "acme", aad).unwrap(), plaintext);
        assert!(decoded.open(&provider, "other", aad).is_err());
        assert!(decoded.open(&provider, "acme", b"different-uri").is_err());

        let mut tampered = encoded;
        let last = tampered.len() - 1;
        tampered[last] ^= 1;
        let decoded = EncryptedObject::decode(&tampered).unwrap();
        assert!(decoded.open(&provider, "acme", aad).is_err());
    }
}
