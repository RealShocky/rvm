//! REDB schema and bounded wire codecs.

use crate::{ServiceError, ServiceResult};
use redb::{Database, TableDefinition};
use rvm_context::{AliasGeneration, AliasSnapshot, PinnedRuvUri, Revision, RuvUri};
use sha2::{Digest, Sha256};
use std::path::Path;
use std::sync::Arc;

pub(crate) const OBJECTS: TableDefinition<&str, &[u8]> = TableDefinition::new("context_objects_v1");
pub(crate) const ALIASES: TableDefinition<&str, &[u8]> = TableDefinition::new("context_aliases_v1");
pub(crate) const INDEX_JOBS: TableDefinition<&str, &[u8]> =
    TableDefinition::new("context_index_jobs_v1");
pub(crate) const PURGE_JOBS: TableDefinition<&str, &[u8]> =
    TableDefinition::new("context_purge_jobs_v1");

const ALIAS_BYTES: usize = 41;
const MAX_JOB_URI_BYTES: usize = 4096;
const MAX_JOB_DIMENSIONS: usize = 4096;

pub(crate) struct Store {
    pub(crate) db: Arc<Database>,
}

impl Store {
    pub(crate) fn open(path: impl AsRef<Path>) -> ServiceResult<Self> {
        let db = Arc::new(Database::create(path).map_err(ServiceError::database)?);
        let transaction = db.begin_write().map_err(ServiceError::database)?;
        {
            let _ = transaction
                .open_table(OBJECTS)
                .map_err(ServiceError::database)?;
            let _ = transaction
                .open_table(ALIASES)
                .map_err(ServiceError::database)?;
            let _ = transaction
                .open_table(INDEX_JOBS)
                .map_err(ServiceError::database)?;
            let _ = transaction
                .open_table(PURGE_JOBS)
                .map_err(ServiceError::database)?;
        }
        transaction.commit().map_err(ServiceError::database)?;
        Ok(Self { db })
    }
}

pub(crate) fn logical_key(uri: &RuvUri) -> String {
    let mut key = format!(
        "ruv://{}/{}/{}/{}/{}",
        uri.authority(),
        uri.tenant(),
        uri.subject().kind(),
        uri.subject().id(),
        uri.collection()
    );
    for segment in uri.path() {
        key.push('/');
        key.push_str(segment.as_str());
    }
    key
}

pub(crate) fn parse_pinned(value: &str) -> ServiceResult<PinnedRuvUri> {
    value
        .parse()
        .map_err(|_| ServiceError::CorruptState("stored pinned URI is invalid"))
}

pub(crate) fn encode_alias(snapshot: &AliasSnapshot) -> [u8; ALIAS_BYTES] {
    let mut bytes = [0u8; ALIAS_BYTES];
    bytes[..32].copy_from_slice(snapshot.revision().as_bytes());
    bytes[32..40].copy_from_slice(&snapshot.generation().get().to_le_bytes());
    bytes[40] = u8::from(snapshot.is_tombstone());
    bytes
}

pub(crate) fn decode_alias(alias: RuvUri, bytes: &[u8]) -> ServiceResult<AliasSnapshot> {
    if bytes.len() != ALIAS_BYTES || bytes[40] > 1 {
        return Err(ServiceError::CorruptState("invalid alias record"));
    }
    let mut revision = [0u8; 32];
    revision.copy_from_slice(&bytes[..32]);
    let generation = AliasGeneration::new(u64::from_le_bytes(
        bytes[32..40].try_into().unwrap_or([0; 8]),
    ))
    .ok_or(ServiceError::CorruptState("zero alias generation"))?;
    AliasSnapshot::new(
        alias,
        Revision::from_bytes(revision),
        generation,
        bytes[40] == 1,
    )
    .map_err(|_| ServiceError::CorruptState("invalid alias identity"))
}

pub(crate) fn point_id(pinned: &PinnedRuvUri) -> String {
    let mut hash = Sha256::new();
    hash.update(b"RUV-CONTEXT-ACTIVE-POINT-V1\0");
    hash.update(pinned.to_string().as_bytes());
    let digest = hash.finalize();
    let mut output = String::with_capacity(64);
    for byte in digest {
        use core::fmt::Write as _;
        let _ = write!(output, "{byte:02x}");
    }
    output
}

pub(crate) enum IndexJob {
    Erase,
    Upsert {
        pinned: PinnedRuvUri,
        vector: Vec<f32>,
    },
}

impl IndexJob {
    pub(crate) fn encode(&self) -> ServiceResult<Vec<u8>> {
        match self {
            Self::Erase => Ok(vec![0]),
            Self::Upsert { pinned, vector } => {
                let uri = pinned.to_string();
                if uri.len() > MAX_JOB_URI_BYTES || vector.len() > MAX_JOB_DIMENSIONS {
                    return Err(ServiceError::CorruptState("index job exceeds bounds"));
                }
                let uri_len = u16::try_from(uri.len())
                    .map_err(|_| ServiceError::CorruptState("index URI is too long"))?;
                let dimensions = u16::try_from(vector.len())
                    .map_err(|_| ServiceError::CorruptState("index vector is too large"))?;
                let mut bytes = Vec::with_capacity(5 + uri.len() + vector.len() * 4);
                bytes.push(1);
                bytes.extend_from_slice(&uri_len.to_le_bytes());
                bytes.extend_from_slice(&dimensions.to_le_bytes());
                bytes.extend_from_slice(uri.as_bytes());
                for value in vector {
                    bytes.extend_from_slice(&value.to_bits().to_le_bytes());
                }
                Ok(bytes)
            }
        }
    }

    pub(crate) fn decode(bytes: &[u8]) -> ServiceResult<Self> {
        if bytes == [0] {
            return Ok(Self::Erase);
        }
        if bytes.len() < 5 || bytes[0] != 1 {
            return Err(ServiceError::CorruptState("invalid index job"));
        }
        let uri_len = usize::from(u16::from_le_bytes([bytes[1], bytes[2]]));
        let dimensions = usize::from(u16::from_le_bytes([bytes[3], bytes[4]]));
        let vector_bytes = dimensions
            .checked_mul(4)
            .ok_or(ServiceError::CorruptState("index vector length overflow"))?;
        let expected = 5_usize
            .checked_add(uri_len)
            .and_then(|value| value.checked_add(vector_bytes))
            .ok_or(ServiceError::CorruptState("index job length overflow"))?;
        if uri_len == 0
            || uri_len > MAX_JOB_URI_BYTES
            || dimensions == 0
            || dimensions > MAX_JOB_DIMENSIONS
            || bytes.len() != expected
        {
            return Err(ServiceError::CorruptState("invalid index job lengths"));
        }
        let uri = core::str::from_utf8(&bytes[5..5 + uri_len])
            .map_err(|_| ServiceError::CorruptState("index URI is not UTF-8"))?;
        let pinned = parse_pinned(uri)?;
        let vector = bytes[5 + uri_len..]
            .chunks_exact(4)
            .map(|chunk| f32::from_bits(u32::from_le_bytes(chunk.try_into().unwrap_or([0; 4]))))
            .collect::<Vec<_>>();
        if vector.iter().any(|value| !value.is_finite()) {
            return Err(ServiceError::CorruptState("non-finite persisted vector"));
        }
        Ok(Self::Upsert { pinned, vector })
    }
}
