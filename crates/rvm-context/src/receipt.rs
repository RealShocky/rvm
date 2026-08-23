//! Signed epoch receipts bridging the RVM witness ring to RVF witnesses.
//!
//! The hot RVM log is deliberately small and lossy. A context epoch receipt
//! seals a contiguous, non-wrapped slice with SHA-256, binds it to the active
//! namespace, policy, detail commitment, and RVF identity, then signs the
//! result with the full 64-byte signer from `rvm-proof`. The resulting receipt
//! can be committed into the canonical 73-byte RVF witness shape without
//! pretending that RVF and RVM use the same record format.

use alloc::vec::Vec;
use rvm_proof::{SignatureError, WitnessSigner};
use rvm_types::{ActionKind, WitnessRecord};
use rvm_witness::{
    compute_chain_hash, record_to_bytes, verify_chain_from, ChainIntegrityError,
    SnapshotSinceError, WitnessCheckpoint, WitnessLog,
};
use sha2::{Digest, Sha256};
use sha3::digest::{ExtendableOutput, Update, XofReader};

/// Version of the signed context epoch receipt wire contract.
pub const CONTEXT_RECEIPT_VERSION: u16 = 1;

/// Fixed size of an encoded signed receipt.
pub const CONTEXT_RECEIPT_ENCODED_SIZE: usize = 352;

/// Fixed size of one canonical RVF witness entry.
pub const RVF_WITNESS_ENTRY_SIZE: usize = 73;

/// RVF witness type for a computation commitment.
pub const RVF_WITNESS_COMPUTATION: u8 = 0x02;

/// Maximum records sealed by one context epoch.
///
/// This matches the documented default RVM witness ring and bounds receipt
/// scratch plus Merkle memory even when [`ContextEpochReceipt::seal`] is
/// called directly with an arbitrary slice.
pub const MAX_CONTEXT_EPOCH_RECORDS: usize = rvm_witness::DEFAULT_RING_CAPACITY;

const MAGIC: [u8; 4] = *b"RUCR";
const SIGNING_DOMAIN: &[u8] = b"RUV-CONTEXT-EPOCH-RECEIPT-V1";
const SIGNED_ID_DOMAIN: &[u8] = b"RUV-CONTEXT-EPOCH-RECEIPT-ID-V1";
const LEAF_DOMAIN: &[u8] = b"RUV-CONTEXT-WITNESS-LEAF-V1";
const NODE_DOMAIN: &[u8] = b"RUV-CONTEXT-WITNESS-NODE-V1";

/// Failure while sealing or validating a context epoch receipt.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ContextReceiptError {
    /// An epoch must contain at least one witnessed decision.
    EmptyEpoch,
    /// More records were supplied than the bounded epoch ceiling permits.
    TooManyRecords,
    /// The record sequence range does not match its declared count.
    SequenceRange,
    /// The encoded or reproduced timestamp bounds are inconsistent.
    TimestampBounds,
    /// The RVM witness chain is incomplete or corrupt.
    Chain(ChainIntegrityError),
    /// The requested epoch is unavailable from the hot ring.
    Snapshot(SnapshotSinceError),
    /// The receipt signer does not match the signer identifier in the record.
    SignerMismatch,
    /// The 64-byte receipt signature did not verify.
    Signature(SignatureError),
    /// Encoded bytes violate the fixed receipt schema.
    Encoding(&'static str),
    /// Supplied records do not reproduce the committed Merkle root.
    WitnessRootMismatch,
    /// A verified receipt is not the required genesis or direct successor.
    ReceiptContinuity,
}

impl core::fmt::Display for ContextReceiptError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::EmptyEpoch => f.write_str("context epoch is empty"),
            Self::TooManyRecords => f.write_str("context epoch has too many records"),
            Self::SequenceRange => f.write_str("context epoch sequence range is invalid"),
            Self::TimestampBounds => f.write_str("context epoch timestamp bounds do not match"),
            Self::Chain(error) => write!(f, "context witness chain is invalid: {error}"),
            Self::Snapshot(error) => write!(f, "context witness snapshot failed: {error}"),
            Self::SignerMismatch => f.write_str("context receipt signer does not match"),
            Self::Signature(error) => write!(f, "context receipt signature failed: {error:?}"),
            Self::Encoding(message) => write!(f, "context receipt encoding is invalid: {message}"),
            Self::WitnessRootMismatch => f.write_str("context witness root does not match"),
            Self::ReceiptContinuity => f.write_str("context receipt continuity is invalid"),
        }
    }
}

impl From<ChainIntegrityError> for ContextReceiptError {
    fn from(error: ChainIntegrityError) -> Self {
        Self::Chain(error)
    }
}

impl From<SnapshotSinceError> for ContextReceiptError {
    fn from(error: SnapshotSinceError) -> Self {
        Self::Snapshot(error)
    }
}

/// Unsigned, canonical content of one context witness epoch.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ContextEpochReceipt {
    /// Monotonic epoch identifier derived by the governed runtime.
    epoch_id: u64,
    /// First RVM witness sequence covered by this epoch.
    first_sequence: u64,
    /// Last RVM witness sequence covered by this epoch.
    last_sequence: u64,
    /// Number of RVM records committed by `witness_root`.
    record_count: u32,
    /// Minimum timestamp observed in the epoch.
    started_ns: u64,
    /// Maximum timestamp observed in the epoch.
    ended_ns: u64,
    /// Full RVM chain hash immediately before `first_sequence`.
    initial_chain_hash: u64,
    /// SHA-256 identifier of the previous signed context receipt.
    previous_receipt: [u8; 32],
    /// Commitment to the alias and tombstone state after this epoch.
    namespace_root: [u8; 32],
    /// RVF identity whose context profile governed the epoch.
    rvf_identity: [u8; 32],
    /// Commitment to the authorization and retention policy.
    policy_hash: [u8; 32],
    /// Commitment to encrypted detailed search or trajectory evidence.
    detail_root: [u8; 32],
    /// SHA-256 Merkle root of canonical 64-byte RVM witness records.
    witness_root: [u8; 32],
}

impl ContextEpochReceipt {
    /// Return the monotonic epoch identifier.
    #[must_use]
    pub const fn epoch_id(&self) -> u64 {
        self.epoch_id
    }

    /// Return the first covered RVM witness sequence.
    #[must_use]
    pub const fn first_sequence(&self) -> u64 {
        self.first_sequence
    }

    /// Return the last covered RVM witness sequence.
    #[must_use]
    pub const fn last_sequence(&self) -> u64 {
        self.last_sequence
    }

    /// Return the number of covered witness records.
    #[must_use]
    pub const fn record_count(&self) -> u32 {
        self.record_count
    }

    /// Return the minimum timestamp observed in the epoch.
    #[must_use]
    pub const fn started_ns(&self) -> u64 {
        self.started_ns
    }

    /// Return the maximum timestamp observed in the epoch.
    #[must_use]
    pub const fn ended_ns(&self) -> u64 {
        self.ended_ns
    }

    /// Return the full chain hash immediately before this epoch.
    #[must_use]
    pub const fn initial_chain_hash(&self) -> u64 {
        self.initial_chain_hash
    }

    /// Return the previous signed receipt identifier.
    #[must_use]
    pub const fn previous_receipt(&self) -> &[u8; 32] {
        &self.previous_receipt
    }

    /// Return the namespace state commitment.
    #[must_use]
    pub const fn namespace_root(&self) -> &[u8; 32] {
        &self.namespace_root
    }

    /// Return the governed whole-RVF identity.
    #[must_use]
    pub const fn rvf_identity(&self) -> &[u8; 32] {
        &self.rvf_identity
    }

    /// Return the authorization and retention policy commitment.
    #[must_use]
    pub const fn policy_hash(&self) -> &[u8; 32] {
        &self.policy_hash
    }

    /// Return the encrypted detail commitment.
    #[must_use]
    pub const fn detail_root(&self) -> &[u8; 32] {
        &self.detail_root
    }

    /// Return the Merkle root of canonical witness records.
    #[must_use]
    pub const fn witness_root(&self) -> &[u8; 32] {
        &self.witness_root
    }

    /// Seal a supplied record slice beginning at `checkpoint`.
    ///
    /// # Errors
    ///
    /// Refuses empty, non-contiguous, corrupt, or oversized slices. Sequence
    /// and chain coordinates define record order; timestamps are committed as
    /// observed minimum and maximum bounds. No incomplete receipt is returned.
    #[allow(clippy::too_many_arguments)]
    pub fn seal(
        epoch_id: u64,
        checkpoint: WitnessCheckpoint,
        records: &[WitnessRecord],
        previous_receipt: [u8; 32],
        namespace_root: [u8; 32],
        rvf_identity: [u8; 32],
        policy_hash: [u8; 32],
        detail_root: [u8; 32],
    ) -> Result<Self, ContextReceiptError> {
        if records.is_empty() {
            return Err(ContextReceiptError::EmptyEpoch);
        }
        if records.len() > MAX_CONTEXT_EPOCH_RECORDS {
            return Err(ContextReceiptError::TooManyRecords);
        }
        let record_count =
            u32::try_from(records.len()).map_err(|_| ContextReceiptError::TooManyRecords)?;
        verify_chain_from(records, checkpoint.chain_hash(), checkpoint.next_sequence())?;

        let first = records[0];
        let last = records[records.len() - 1];
        let (started_ns, ended_ns) = timestamp_bounds(records);
        let expected_last = first
            .sequence
            .checked_add(u64::from(record_count) - 1)
            .ok_or(ContextReceiptError::SequenceRange)?;
        if last.sequence != expected_last {
            return Err(ContextReceiptError::SequenceRange);
        }
        Ok(Self {
            epoch_id,
            first_sequence: first.sequence,
            last_sequence: last.sequence,
            record_count,
            started_ns,
            ended_ns,
            initial_chain_hash: checkpoint.chain_hash(),
            previous_receipt,
            namespace_root,
            rvf_identity,
            policy_hash,
            detail_root,
            witness_root: merkle_root(records),
        })
    }

    /// Atomically snapshot and seal records emitted after `checkpoint`.
    ///
    /// # Errors
    ///
    /// In addition to [`Self::seal`] failures, refuses a wrapped epoch or an
    /// undersized scratch slice through [`ContextReceiptError::Snapshot`].
    #[allow(clippy::too_many_arguments)]
    pub fn seal_from_log<const N: usize>(
        epoch_id: u64,
        log: &WitnessLog<N>,
        checkpoint: WitnessCheckpoint,
        scratch: &mut [WitnessRecord],
        previous_receipt: [u8; 32],
        namespace_root: [u8; 32],
        rvf_identity: [u8; 32],
        policy_hash: [u8; 32],
        detail_root: [u8; 32],
    ) -> Result<(Self, WitnessCheckpoint), ContextReceiptError> {
        let snapshot = log.snapshot_since(checkpoint, scratch)?;
        let receipt = Self::seal(
            epoch_id,
            checkpoint,
            &scratch[..snapshot.count()],
            previous_receipt,
            namespace_root,
            rvf_identity,
            policy_hash,
            detail_root,
        )?;
        Ok((receipt, snapshot.end_checkpoint()))
    }

    /// Verify that `records` reproduce this receipt's sequence and Merkle root.
    ///
    /// # Errors
    ///
    /// Refuses a count/range or timestamp-bound mismatch, broken RVM chain, or
    /// different root.
    pub fn verify_records(&self, records: &[WitnessRecord]) -> Result<(), ContextReceiptError> {
        let expected_count =
            usize::try_from(self.record_count).map_err(|_| ContextReceiptError::SequenceRange)?;
        if expected_count > MAX_CONTEXT_EPOCH_RECORDS {
            return Err(ContextReceiptError::TooManyRecords);
        }
        if records.len() != expected_count || records.is_empty() {
            return Err(ContextReceiptError::SequenceRange);
        }
        if records[0].sequence != self.first_sequence
            || records[records.len() - 1].sequence != self.last_sequence
        {
            return Err(ContextReceiptError::SequenceRange);
        }
        if timestamp_bounds(records) != (self.started_ns, self.ended_ns) {
            return Err(ContextReceiptError::TimestampBounds);
        }
        verify_chain_from(records, self.initial_chain_hash, self.first_sequence)?;
        if merkle_root(records) != self.witness_root {
            return Err(ContextReceiptError::WitnessRootMismatch);
        }
        Ok(())
    }

    /// Sign this receipt with a full `rvm-proof` signer.
    #[must_use]
    pub fn sign<S: WitnessSigner>(&self, signer: &S) -> SignedContextEpochReceipt {
        let signer_id = signer.signer_id();
        let digest = self.signing_digest(&signer_id);
        SignedContextEpochReceipt {
            receipt: self.clone(),
            signer_id,
            signature: signer.sign(&digest),
        }
    }

    fn signing_digest(&self, signer_id: &[u8; 32]) -> [u8; 32] {
        let mut hasher = Sha256::new();
        Digest::update(&mut hasher, SIGNING_DOMAIN);
        Digest::update(&mut hasher, self.encode_unsigned());
        Digest::update(&mut hasher, signer_id);
        finalize_sha256(hasher)
    }

    fn encode_unsigned(&self) -> [u8; 256] {
        let mut out = [0u8; 256];
        out[0..4].copy_from_slice(&MAGIC);
        out[4..6].copy_from_slice(&CONTEXT_RECEIPT_VERSION.to_le_bytes());
        out[8..16].copy_from_slice(&self.epoch_id.to_le_bytes());
        out[16..24].copy_from_slice(&self.first_sequence.to_le_bytes());
        out[24..32].copy_from_slice(&self.last_sequence.to_le_bytes());
        out[32..36].copy_from_slice(&self.record_count.to_le_bytes());
        out[40..48].copy_from_slice(&self.started_ns.to_le_bytes());
        out[48..56].copy_from_slice(&self.ended_ns.to_le_bytes());
        out[56..64].copy_from_slice(&self.initial_chain_hash.to_le_bytes());
        out[64..96].copy_from_slice(&self.previous_receipt);
        out[96..128].copy_from_slice(&self.namespace_root);
        out[128..160].copy_from_slice(&self.rvf_identity);
        out[160..192].copy_from_slice(&self.policy_hash);
        out[192..224].copy_from_slice(&self.detail_root);
        out[224..256].copy_from_slice(&self.witness_root);
        out
    }
}

/// A context epoch receipt with signer identity and a 64-byte signature.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignedContextEpochReceipt {
    /// Canonical unsigned fields.
    receipt: ContextEpochReceipt,
    /// Typed signer identifier supplied by `rvm-proof`.
    signer_id: [u8; 32],
    /// Signature over the domain-separated receipt digest.
    signature: [u8; 64],
}

impl SignedContextEpochReceipt {
    /// Return the canonical unsigned receipt fields.
    #[must_use]
    pub const fn receipt(&self) -> &ContextEpochReceipt {
        &self.receipt
    }

    /// Return the typed receipt signer identifier.
    #[must_use]
    pub const fn signer_id(&self) -> &[u8; 32] {
        &self.signer_id
    }

    /// Return the full receipt signature.
    #[must_use]
    pub const fn signature(&self) -> &[u8; 64] {
        &self.signature
    }

    /// Verify signer identity and signature.
    ///
    /// # Errors
    ///
    /// Returns a signer mismatch before attempting cryptographic verification,
    /// or wraps the signer's signature error.
    pub fn verify<'a, S: WitnessSigner>(
        &'a self,
        signer: &S,
    ) -> Result<VerifiedContextEpochReceipt<'a>, ContextReceiptError> {
        if signer.signer_id() != self.signer_id {
            return Err(ContextReceiptError::SignerMismatch);
        }
        let digest = self.receipt.signing_digest(&self.signer_id);
        signer
            .verify(&digest, &self.signature)
            .map_err(ContextReceiptError::Signature)?;
        Ok(VerifiedContextEpochReceipt { signed: self })
    }

    /// Encode the complete signed receipt in its fixed 352-byte form.
    #[must_use]
    pub fn to_bytes(&self) -> [u8; CONTEXT_RECEIPT_ENCODED_SIZE] {
        let mut out = [0u8; CONTEXT_RECEIPT_ENCODED_SIZE];
        out[..256].copy_from_slice(&self.receipt.encode_unsigned());
        out[256..288].copy_from_slice(&self.signer_id);
        out[288..352].copy_from_slice(&self.signature);
        out
    }

    /// Decode a fixed signed receipt.
    ///
    /// This checks structural invariants but cannot authenticate the signature;
    /// call [`Self::verify`] with a trusted signer after decoding.
    ///
    /// # Errors
    ///
    /// Refuses wrong magic, version, reserved bytes, empty or oversized ranges,
    /// and count mismatches.
    pub fn from_bytes(data: &[u8]) -> Result<Self, ContextReceiptError> {
        if data.len() != CONTEXT_RECEIPT_ENCODED_SIZE {
            return Err(ContextReceiptError::Encoding("wrong byte length"));
        }
        if data[..4] != MAGIC {
            return Err(ContextReceiptError::Encoding("wrong magic"));
        }
        if read_u16(data, 4) != CONTEXT_RECEIPT_VERSION {
            return Err(ContextReceiptError::Encoding("unsupported version"));
        }
        if data[6..8].iter().any(|byte| *byte != 0) || data[36..40].iter().any(|byte| *byte != 0) {
            return Err(ContextReceiptError::Encoding("reserved bytes are nonzero"));
        }

        let first_sequence = read_u64(data, 16);
        let last_sequence = read_u64(data, 24);
        let record_count = read_u32(data, 32);
        let decoded_count =
            usize::try_from(record_count).map_err(|_| ContextReceiptError::TooManyRecords)?;
        if decoded_count > MAX_CONTEXT_EPOCH_RECORDS {
            return Err(ContextReceiptError::TooManyRecords);
        }
        let sequence_count = last_sequence
            .checked_sub(first_sequence)
            .and_then(|distance| distance.checked_add(1));
        if record_count == 0 || sequence_count != Some(u64::from(record_count)) {
            return Err(ContextReceiptError::SequenceRange);
        }
        let started_ns = read_u64(data, 40);
        let ended_ns = read_u64(data, 48);
        if ended_ns < started_ns {
            return Err(ContextReceiptError::TimestampBounds);
        }

        let receipt = ContextEpochReceipt {
            epoch_id: read_u64(data, 8),
            first_sequence,
            last_sequence,
            record_count,
            started_ns,
            ended_ns,
            initial_chain_hash: read_u64(data, 56),
            previous_receipt: array32(data, 64),
            namespace_root: array32(data, 96),
            rvf_identity: array32(data, 128),
            policy_hash: array32(data, 160),
            detail_root: array32(data, 192),
            witness_root: array32(data, 224),
        };
        let mut signature = [0u8; 64];
        signature.copy_from_slice(&data[288..352]);
        Ok(Self {
            receipt,
            signer_id: array32(data, 256),
            signature,
        })
    }

    /// SHA-256 identifier of the complete signed receipt.
    #[must_use]
    pub fn receipt_id(&self) -> [u8; 32] {
        let mut hasher = Sha256::new();
        Digest::update(&mut hasher, SIGNED_ID_DOMAIN);
        Digest::update(&mut hasher, self.to_bytes());
        finalize_sha256(hasher)
    }
}

/// A signed epoch receipt authenticated by a trusted signer.
///
/// This typestate prevents bytes decoded from an untrusted source from being
/// committed into RVF or the live witness trail before verification.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VerifiedContextEpochReceipt<'a> {
    signed: &'a SignedContextEpochReceipt,
}

impl VerifiedContextEpochReceipt<'_> {
    /// Return the authenticated signed receipt.
    #[must_use]
    pub const fn signed(&self) -> &SignedContextEpochReceipt {
        self.signed
    }

    /// Verify that this receipt is the canonical witness-log genesis.
    ///
    /// Genesis begins at epoch and sequence zero, has the zero initial chain
    /// hash, and does not link to a prior signed receipt.
    ///
    /// # Errors
    ///
    /// Returns [`ContextReceiptError::ReceiptContinuity`] when any genesis
    /// coordinate is nonzero.
    pub fn verify_genesis(&self) -> Result<(), ContextReceiptError> {
        let receipt = &self.signed.receipt;
        if receipt.epoch_id != 0
            || receipt.first_sequence != 0
            || receipt.initial_chain_hash != 0
            || receipt.previous_receipt != [0; 32]
        {
            return Err(ContextReceiptError::ReceiptContinuity);
        }
        Ok(())
    }

    /// Verify that this receipt directly follows `previous`.
    ///
    /// Both values must already have authenticated signatures. Continuity
    /// requires the exact previous signed-receipt identifier, checked epoch
    /// increment, checked sequence adjacency, and the full chain hash obtained
    /// by applying [`compute_chain_hash`] across every prior sequence.
    /// Timestamps are deliberately excluded from ordering authority.
    ///
    /// # Errors
    ///
    /// Returns [`ContextReceiptError::ReceiptContinuity`] for a fork, replay,
    /// skipped/overflowed epoch, or skipped/overflowed sequence.
    pub fn verify_successor(
        &self,
        previous: &VerifiedContextEpochReceipt<'_>,
    ) -> Result<(), ContextReceiptError> {
        let receipt = &self.signed.receipt;
        let prior = &previous.signed.receipt;
        let expected_epoch = prior
            .epoch_id
            .checked_add(1)
            .ok_or(ContextReceiptError::ReceiptContinuity)?;
        let expected_sequence = prior
            .last_sequence
            .checked_add(1)
            .ok_or(ContextReceiptError::ReceiptContinuity)?;
        let mut expected_initial_chain_hash = prior.initial_chain_hash;
        for offset in 0..u64::from(prior.record_count) {
            let sequence = prior
                .first_sequence
                .checked_add(offset)
                .ok_or(ContextReceiptError::ReceiptContinuity)?;
            expected_initial_chain_hash = compute_chain_hash(expected_initial_chain_hash, sequence);
        }
        if receipt.previous_receipt != previous.signed.receipt_id()
            || receipt.epoch_id != expected_epoch
            || receipt.first_sequence != expected_sequence
            || receipt.initial_chain_hash != expected_initial_chain_hash
        {
            return Err(ContextReceiptError::ReceiptContinuity);
        }
        Ok(())
    }

    /// Encode a commitment to this receipt as one canonical RVF witness entry.
    ///
    /// `previous_entry_hash` is zero for a genesis entry, otherwise it is
    /// SHAKE-256 of the preceding 73-byte entry.
    #[must_use]
    pub fn to_rvf_witness_entry(&self, previous_entry_hash: [u8; 32]) -> [u8; 73] {
        let mut entry = [0u8; RVF_WITNESS_ENTRY_SIZE];
        entry[..32].copy_from_slice(&previous_entry_hash);
        entry[32..64].copy_from_slice(&shake256(&self.signed.to_bytes()));
        entry[64..72].copy_from_slice(&self.signed.receipt.ended_ns.to_le_bytes());
        entry[72] = RVF_WITNESS_COMPUTATION;
        entry
    }

    /// Emit the authenticated epoch seal into the next RVM witness epoch.
    #[must_use]
    pub fn emit_seal<const N: usize>(
        &self,
        log: &WitnessLog<N>,
        actor_partition_id: u32,
        capability_hash: u32,
        timestamp_ns: u64,
    ) -> u64 {
        let id = self.signed.receipt_id();
        let mut record = WitnessRecord::zeroed();
        record.action_kind = ActionKind::ContextEpochSeal as u8;
        // Receipt signature verification authenticates the signer but does
        // not itself run the P2 policy engine. Record the actual P1 runtime
        // authorization rather than overstating the assurance tier.
        record.proof_tier = 1;
        record.actor_partition_id = actor_partition_id;
        record.target_object_id = u64::from_le_bytes(id[..8].try_into().unwrap_or([0; 8]));
        record.capability_hash = capability_hash;
        record.payload = self.signed.receipt.last_sequence.to_le_bytes();
        record
            .aux
            .copy_from_slice(&self.signed.receipt.witness_root[..8]);
        record.timestamp_ns = timestamp_ns;
        log.append(record)
    }
}

/// SHAKE-256 hash of one serialized RVF witness entry.
#[must_use]
pub fn rvf_witness_entry_hash(entry: &[u8; RVF_WITNESS_ENTRY_SIZE]) -> [u8; 32] {
    shake256(entry)
}

fn merkle_root(records: &[WitnessRecord]) -> [u8; 32] {
    let mut level: Vec<[u8; 32]> = records
        .iter()
        .map(|record| {
            let mut hasher = Sha256::new();
            Digest::update(&mut hasher, LEAF_DOMAIN);
            Digest::update(&mut hasher, record_to_bytes(record));
            finalize_sha256(hasher)
        })
        .collect();

    while level.len() > 1 {
        let current_len = level.len();
        let parent_count = current_len.div_ceil(2);
        for parent in 0..parent_count {
            let left_index = parent * 2;
            let right = if left_index + 1 < current_len {
                level[left_index + 1]
            } else {
                level[left_index]
            };
            let mut hasher = Sha256::new();
            Digest::update(&mut hasher, NODE_DOMAIN);
            Digest::update(&mut hasher, level[left_index]);
            Digest::update(&mut hasher, right);
            level[parent] = finalize_sha256(hasher);
        }
        level.truncate(parent_count);
    }
    level.first().copied().unwrap_or([0; 32])
}

fn timestamp_bounds(records: &[WitnessRecord]) -> (u64, u64) {
    let initial = records.first().map_or(0, |record| record.timestamp_ns);
    records
        .iter()
        .fold((initial, initial), |(minimum, maximum), record| {
            (
                minimum.min(record.timestamp_ns),
                maximum.max(record.timestamp_ns),
            )
        })
}

fn finalize_sha256(hasher: Sha256) -> [u8; 32] {
    let digest = hasher.finalize();
    let mut out = [0u8; 32];
    out.copy_from_slice(&digest);
    out
}

fn shake256(data: &[u8]) -> [u8; 32] {
    let mut hasher = sha3::Shake256::default();
    hasher.update(data);
    let mut out = [0u8; 32];
    hasher.finalize_xof().read(&mut out);
    out
}

fn read_u16(data: &[u8], offset: usize) -> u16 {
    u16::from_le_bytes(data[offset..offset + 2].try_into().unwrap_or([0; 2]))
}

fn read_u32(data: &[u8], offset: usize) -> u32 {
    u32::from_le_bytes(data[offset..offset + 4].try_into().unwrap_or([0; 4]))
}

fn read_u64(data: &[u8], offset: usize) -> u64 {
    u64::from_le_bytes(data[offset..offset + 8].try_into().unwrap_or([0; 8]))
}

fn array32(data: &[u8], offset: usize) -> [u8; 32] {
    let mut out = [0u8; 32];
    out.copy_from_slice(&data[offset..offset + 32]);
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use rvm_proof::HmacSha256WitnessSigner;

    fn context_record(kind: ActionKind, target: u64, timestamp_ns: u64) -> WitnessRecord {
        let mut record = WitnessRecord::zeroed();
        record.action_kind = kind as u8;
        record.actor_partition_id = 7;
        record.target_object_id = target;
        record.timestamp_ns = timestamp_ns;
        record
    }

    fn sealed() -> (
        SignedContextEpochReceipt,
        Vec<WitnessRecord>,
        HmacSha256WitnessSigner,
    ) {
        let log = WitnessLog::<16>::new();
        let checkpoint = log.checkpoint();
        log.append(context_record(ActionKind::ContextResolve, 1, 10));
        log.append(context_record(ActionKind::ContextRead, 2, 11));
        let mut records = [WitnessRecord::zeroed(); 4];
        let (receipt, _) = ContextEpochReceipt::seal_from_log(
            9,
            &log,
            checkpoint,
            &mut records,
            [0; 32],
            [1; 32],
            [2; 32],
            [3; 32],
            [4; 32],
        )
        .unwrap();
        let signer = HmacSha256WitnessSigner::new([0x55; 32]);
        (receipt.sign(&signer), records[..2].to_vec(), signer)
    }

    #[test]
    fn signed_receipt_round_trips_and_reproduces_records() {
        let (sealed_receipt, records, authenticator) = sealed();
        sealed_receipt.verify(&authenticator).unwrap();
        sealed_receipt.receipt.verify_records(&records).unwrap();
        let decoded = SignedContextEpochReceipt::from_bytes(&sealed_receipt.to_bytes()).unwrap();
        assert_eq!(decoded, sealed_receipt);
        decoded.verify(&authenticator).unwrap();
    }

    #[test]
    fn one_bit_tamper_fails_signature() {
        let (sealed_receipt, _, authenticator) = sealed();
        let mut bytes = sealed_receipt.to_bytes();
        bytes[128] ^= 1;
        let tampered = SignedContextEpochReceipt::from_bytes(&bytes).unwrap();
        assert!(matches!(
            tampered.verify(&authenticator),
            Err(ContextReceiptError::Signature(_))
        ));
    }

    #[test]
    fn adversarial_sequence_span_is_rejected_without_overflow() {
        let (signed, _, _) = sealed();
        let mut bytes = signed.to_bytes();
        bytes[16..24].copy_from_slice(&0u64.to_le_bytes());
        bytes[24..32].copy_from_slice(&u64::MAX.to_le_bytes());
        assert_eq!(
            SignedContextEpochReceipt::from_bytes(&bytes),
            Err(ContextReceiptError::SequenceRange)
        );
    }

    #[test]
    fn decoded_record_count_cannot_exceed_epoch_limit() {
        let (signed, _, _) = sealed();
        let mut bytes = signed.to_bytes();
        let count = u32::try_from(MAX_CONTEXT_EPOCH_RECORDS + 1).unwrap();
        bytes[16..24].copy_from_slice(&0u64.to_le_bytes());
        bytes[24..32].copy_from_slice(&(u64::from(count) - 1).to_le_bytes());
        bytes[32..36].copy_from_slice(&count.to_le_bytes());
        assert_eq!(
            SignedContextEpochReceipt::from_bytes(&bytes),
            Err(ContextReceiptError::TooManyRecords)
        );
    }

    #[test]
    fn sequence_order_accepts_non_monotonic_timestamps_and_commits_bounds() {
        let log = WitnessLog::<8>::new();
        let checkpoint = log.checkpoint();
        log.append(context_record(ActionKind::ContextResolve, 1, 30));
        log.append(context_record(ActionKind::ContextRead, 2, 10));
        log.append(context_record(ActionKind::ContextRead, 3, 20));
        let mut scratch = [WitnessRecord::zeroed(); 3];
        let (receipt, _) = ContextEpochReceipt::seal_from_log(
            0,
            &log,
            checkpoint,
            &mut scratch,
            [0; 32],
            [1; 32],
            [2; 32],
            [3; 32],
            [4; 32],
        )
        .unwrap();

        assert_eq!(receipt.started_ns(), 10);
        assert_eq!(receipt.ended_ns(), 30);
        receipt.verify_records(&scratch).unwrap();
    }

    #[test]
    fn record_tamper_fails_committed_root() {
        let (signed, mut records, _) = sealed();
        records[0].target_object_id ^= 1;
        assert!(signed.receipt.verify_records(&records).is_err());
    }

    #[test]
    fn different_signer_is_rejected_before_signature_check() {
        let (signed, _, _) = sealed();
        let other = HmacSha256WitnessSigner::new([0x56; 32]);
        assert_eq!(
            signed.verify(&other),
            Err(ContextReceiptError::SignerMismatch)
        );
    }

    #[test]
    fn wrapped_epoch_is_never_partially_sealed() {
        let log = WitnessLog::<2>::new();
        let checkpoint = log.checkpoint();
        for sequence in 0..3 {
            log.append(context_record(ActionKind::ContextRead, sequence, sequence));
        }
        let mut records = [WitnessRecord::zeroed(); 3];
        let result = ContextEpochReceipt::seal_from_log(
            1,
            &log,
            checkpoint,
            &mut records,
            [0; 32],
            [0; 32],
            [0; 32],
            [0; 32],
            [0; 32],
        );
        assert_eq!(
            result,
            Err(ContextReceiptError::Snapshot(
                SnapshotSinceError::RecordsOverwritten
            ))
        );
    }

    #[test]
    fn direct_seal_rejects_more_than_the_default_ring_capacity() {
        let records = alloc::vec![
            WitnessRecord::zeroed();
            MAX_CONTEXT_EPOCH_RECORDS + 1
        ];
        let checkpoint = WitnessLog::<1>::new().checkpoint();
        assert_eq!(
            ContextEpochReceipt::seal(
                1, checkpoint, &records, [0; 32], [0; 32], [0; 32], [0; 32], [0; 32],
            ),
            Err(ContextReceiptError::TooManyRecords)
        );
    }

    #[test]
    #[allow(clippy::too_many_lines)]
    fn verified_receipts_enforce_genesis_and_successor_continuity() {
        let signer = HmacSha256WitnessSigner::new([0x77; 32]);
        let log = WitnessLog::<8>::new();
        let genesis = log.checkpoint();
        log.append(context_record(ActionKind::ContextResolve, 1, 30));
        let mut first_records = [WitnessRecord::zeroed(); 1];
        let (first, next) = ContextEpochReceipt::seal_from_log(
            0,
            &log,
            genesis,
            &mut first_records,
            [0; 32],
            [1; 32],
            [2; 32],
            [3; 32],
            [4; 32],
        )
        .unwrap();
        let first_signed = first.sign(&signer);
        let first_verified = first_signed.verify(&signer).unwrap();
        first_verified.verify_genesis().unwrap();

        log.append(context_record(ActionKind::ContextRead, 2, 10));
        let mut second_records = [WitnessRecord::zeroed(); 1];
        let (second, after_second) = ContextEpochReceipt::seal_from_log(
            1,
            &log,
            next,
            &mut second_records,
            first_signed.receipt_id(),
            [1; 32],
            [2; 32],
            [3; 32],
            [4; 32],
        )
        .unwrap();
        let second_signed = second.sign(&signer);
        let second_verified = second_signed.verify(&signer).unwrap();
        second_verified.verify_successor(&first_verified).unwrap();

        log.append(context_record(ActionKind::ContextRead, 3, 20));
        let mut skipped_records = [WitnessRecord::zeroed(); 1];
        let (skipped, _) = ContextEpochReceipt::seal_from_log(
            1,
            &log,
            after_second,
            &mut skipped_records,
            first_signed.receipt_id(),
            [1; 32],
            [2; 32],
            [3; 32],
            [4; 32],
        )
        .unwrap();
        let skipped_signed = skipped.sign(&signer);
        let skipped_verified = skipped_signed.verify(&signer).unwrap();
        assert_eq!(
            skipped_verified.verify_genesis(),
            Err(ContextReceiptError::ReceiptContinuity)
        );
        assert_eq!(
            skipped_verified.verify_successor(&first_verified),
            Err(ContextReceiptError::ReceiptContinuity)
        );

        let wrong_link = ContextEpochReceipt::seal(
            1,
            next,
            &second_records,
            [9; 32],
            [1; 32],
            [2; 32],
            [3; 32],
            [4; 32],
        )
        .unwrap()
        .sign(&signer);
        assert_eq!(
            wrong_link
                .verify(&signer)
                .unwrap()
                .verify_successor(&first_verified),
            Err(ContextReceiptError::ReceiptContinuity)
        );

        let mut wrong_initial_chain = second.clone();
        wrong_initial_chain.initial_chain_hash ^= 1;
        let wrong_initial_chain = wrong_initial_chain.sign(&signer);
        assert_eq!(
            wrong_initial_chain
                .verify(&signer)
                .unwrap()
                .verify_successor(&first_verified),
            Err(ContextReceiptError::ReceiptContinuity)
        );

        let skipped_epoch = ContextEpochReceipt::seal(
            2,
            next,
            &second_records,
            first_signed.receipt_id(),
            [1; 32],
            [2; 32],
            [3; 32],
            [4; 32],
        )
        .unwrap()
        .sign(&signer);
        assert_eq!(
            skipped_epoch
                .verify(&signer)
                .unwrap()
                .verify_successor(&first_verified),
            Err(ContextReceiptError::ReceiptContinuity)
        );

        let overflowed_prior = ContextEpochReceipt::seal(
            u64::MAX,
            genesis,
            &first_records,
            [0; 32],
            [1; 32],
            [2; 32],
            [3; 32],
            [4; 32],
        )
        .unwrap()
        .sign(&signer);
        assert_eq!(
            second_verified.verify_successor(&overflowed_prior.verify(&signer).unwrap()),
            Err(ContextReceiptError::ReceiptContinuity)
        );
    }

    #[test]
    fn rvf_entry_is_exact_and_chain_linked() {
        let (sealed_receipt, _, authenticator) = sealed();
        let verified = sealed_receipt.verify(&authenticator).unwrap();
        let first = verified.to_rvf_witness_entry([0; 32]);
        assert_eq!(first.len(), RVF_WITNESS_ENTRY_SIZE);
        assert_eq!(first[72], RVF_WITNESS_COMPUTATION);
        let previous = rvf_witness_entry_hash(&first);
        let second = verified.to_rvf_witness_entry(previous);
        assert_eq!(&second[..32], &previous);
        assert_ne!(&second[32..64], &[0; 32]);
    }

    #[test]
    fn seal_event_belongs_to_the_next_epoch() {
        let (sealed_receipt, _, authenticator) = sealed();
        let verified = sealed_receipt.verify(&authenticator).unwrap();
        let log = WitnessLog::<4>::new();
        let sequence = verified.emit_seal(&log, 7, 99, 12);
        assert_eq!(sequence, 0);
        assert_eq!(
            log.get(0).unwrap().action_kind,
            ActionKind::ContextEpochSeal as u8
        );
        assert_eq!(log.get(0).unwrap().proof_tier, 1);
    }

    #[test]
    fn atomic_end_checkpoint_prevents_records_falling_between_epochs() {
        let log = WitnessLog::<8>::new();
        let genesis = log.checkpoint();
        log.append(context_record(ActionKind::ContextResolve, 1, 10));
        let mut first_records = [WitnessRecord::zeroed(); 4];
        let (first, next) = ContextEpochReceipt::seal_from_log(
            1,
            &log,
            genesis,
            &mut first_records,
            [0; 32],
            [1; 32],
            [2; 32],
            [3; 32],
            [4; 32],
        )
        .unwrap();

        log.append(context_record(ActionKind::ContextRead, 2, 11));
        let mut second_records = [WitnessRecord::zeroed(); 4];
        let (second, end) = ContextEpochReceipt::seal_from_log(
            2,
            &log,
            next,
            &mut second_records,
            first
                .sign(&HmacSha256WitnessSigner::new([9; 32]))
                .receipt_id(),
            [1; 32],
            [2; 32],
            [3; 32],
            [4; 32],
        )
        .unwrap();

        assert_eq!((first.first_sequence, first.last_sequence), (0, 0));
        assert_eq!((second.first_sequence, second.last_sequence), (1, 1));
        assert_eq!(end, log.checkpoint());
    }
}
