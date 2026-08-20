//! Anchoring a verified receipt into the witness chain.
//!
//! The anchor-record shape implements `ruflo.anchor-record/v1`, a
//! **`PROPOSED-EXTENSION`** of the witness/receipt contract (§9): ADR-322C
//! is silent on cross-repo anchoring, and this format is a PIR proposal
//! pending ruflo review, not an established contract. See ADR-156.
//!
//! # Assurance honesty (ADR-285)
//!
//! A ruflo receipt is produced service-side — by a normal process with
//! ambient authority — and anchoring a commitment to it into a
//! hypervisor-side witness chain does **not** upgrade it. The rule is
//! encoded the way `rvm-host` encodes isolation claims: the only
//! constructor for anchoring a ruflo receipt stamps
//! [`AssuranceLevel::ServiceSide`]; there is no parameter through which a
//! caller could assert `hypervisor-side` for a record this crate verified
//! out of a foreign repo.

use alloc::string::String;

use rvm_types::{fnv1a_32, ActionKind, WitnessRecord};
use rvm_witness::WitnessLog;

use crate::jcs::Json;
use crate::receipt::{content_id, is_timestamp, sha256_str, VerifiedReceipt};

/// Schema version of the anchor record (`PROPOSED-EXTENSION`, §9).
pub const ANCHOR_SCHEMA_VERSION: &str = "ruflo.anchor-record/v1";

/// Assurance the anchored record itself carries — never the assurance of
/// the chain it landed in (checklist C4; ADR-285).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AssuranceLevel {
    /// Produced by an ordinary process with ambient authority.
    ServiceSide,
    /// Produced under hypervisor-enforced isolation. No path in this
    /// crate constructs it for a foreign service-side record.
    HypervisorSide,
}

impl AssuranceLevel {
    /// The contract's string form.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::ServiceSide => "service-side",
            Self::HypervisorSide => "hypervisor-side",
        }
    }
}

/// A `ruflo.anchor-record/v1` payload (`PROPOSED-EXTENSION`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AnchorRecordV1 {
    /// Content ID of the anchored record (`sha256:<hex>` of a receipt).
    pub anchored_content_id: String,
    /// `schemaVersion` of the anchored record.
    pub anchored_schema_version: String,
    /// Identifier of this witness chain.
    pub chain_id: String,
    /// Witness-chain sequence of the anchoring record.
    pub position: u64,
    /// What the anchored record carries (see [`AssuranceLevel`]).
    pub assurance_level: AssuranceLevel,
    /// When the anchoring happened (`YYYY-MM-DDTHH:mm:ss.sssZ`).
    pub anchored_at: String,
}

impl AnchorRecordV1 {
    /// The payload as contract JSON.
    #[must_use]
    pub fn to_json(&self) -> Json {
        let position = i64::try_from(self.position).unwrap_or(i64::MAX);
        Json::Obj(alloc::vec![
            (String::from("schemaVersion"), Json::Str(String::from(ANCHOR_SCHEMA_VERSION))),
            (
                String::from("anchoredContentId"),
                Json::Str(self.anchored_content_id.clone()),
            ),
            (
                String::from("anchoredSchemaVersion"),
                Json::Str(self.anchored_schema_version.clone()),
            ),
            (
                String::from("chain"),
                Json::Obj(alloc::vec![
                    (String::from("chainId"), Json::Str(self.chain_id.clone())),
                    (String::from("position"), Json::Int(position)),
                ]),
            ),
            (
                String::from("assuranceLevel"),
                Json::Str(String::from(self.assurance_level.as_str())),
            ),
            (String::from("anchoredAt"), Json::Str(self.anchored_at.clone())),
        ])
    }

    /// JCS canonical bytes of the payload.
    #[must_use]
    pub fn canonical_payload(&self) -> String {
        self.to_json().canonicalize()
    }

    /// SHA-256 over the canonical payload: the commitment the witness
    /// record binds.
    #[must_use]
    pub fn commitment(&self) -> [u8; 32] {
        sha256_str(&self.canonical_payload())
    }

    /// The commitment as an ADR-322C content ID string.
    #[must_use]
    pub fn content_id(&self) -> String {
        content_id(&self.commitment())
    }
}

/// A completed anchoring: the witness sequence, the anchor record to
/// persist alongside the chain, and the commitment the witness record
/// carries.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AnchorOutcome {
    /// Sequence of the emitted witness record.
    pub sequence: u64,
    /// The anchor record; persist it wherever chain sidecar data lives —
    /// the witness record only carries its commitment.
    pub record: AnchorRecordV1,
    /// SHA-256 of the anchor record's canonical payload.
    pub commitment: [u8; 32],
}

/// Why an anchoring attempt was refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AnchorError {
    /// `chain_id` is empty.
    EmptyChainId,
    /// `anchored_at` is not a contract timestamp.
    BadTimestamp,
    /// Another record was appended between position capture and append,
    /// so the recorded position would lie. Retry under serialization.
    SequenceRaced,
}

impl core::fmt::Display for AnchorError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::EmptyChainId => write!(f, "chain id is empty"),
            Self::BadTimestamp => write!(f, "anchored_at is not a contract timestamp"),
            Self::SequenceRaced => write!(f, "witness sequence advanced during anchoring"),
        }
    }
}

/// Anchor a commitment to a verified ruflo receipt into the witness log.
///
/// Emits one ADR-134 record with [`ActionKind::AnchorExternalReceipt`]:
///
/// | field | content |
/// |---|---|
/// | `target_object_id` | big-endian first 8 bytes of the receipt ID |
/// | `payload` | bytes 0..8 of the anchor-record commitment |
/// | `aux` | bytes 8..16 of the anchor-record commitment |
/// | `capability_hash` | FNV-1a-32 of the full 32-byte commitment |
///
/// The full commitment is recomputable from the returned
/// [`AnchorRecordV1`] by any verifier, so the 64-byte record binds the
/// anchor record (and transitively the receipt ID, version pins, and
/// assurance level) without widening ADR-134's layout.
///
/// The assurance level is always [`AssuranceLevel::ServiceSide`]: ruflo
/// receipts are service-side artifacts and anchoring must not upgrade
/// them (ADR-285; checklist C4).
///
/// # Errors
///
/// [`AnchorError`] for an empty chain id, a malformed timestamp, or a
/// sequence race with a concurrent append.
pub fn anchor_verified_receipt<const N: usize>(
    log: &WitnessLog<N>,
    receipt: &VerifiedReceipt,
    chain_id: &str,
    anchored_at: &str,
    actor_partition_id: u32,
    timestamp_ns: u64,
) -> Result<AnchorOutcome, AnchorError> {
    if chain_id.is_empty() {
        return Err(AnchorError::EmptyChainId);
    }
    if !is_timestamp(anchored_at) {
        return Err(AnchorError::BadTimestamp);
    }

    let position = log.total_emitted();
    let record = AnchorRecordV1 {
        anchored_content_id: content_id(&receipt.receipt_id),
        anchored_schema_version: receipt.schema_version.clone(),
        chain_id: String::from(chain_id),
        position,
        assurance_level: AssuranceLevel::ServiceSide,
        anchored_at: String::from(anchored_at),
    };
    let commitment = record.commitment();

    let mut witness = WitnessRecord::zeroed();
    witness.action_kind = ActionKind::AnchorExternalReceipt as u8;
    witness.proof_tier = 1;
    witness.actor_partition_id = actor_partition_id;
    witness.timestamp_ns = timestamp_ns;
    witness.target_object_id = u64::from_be_bytes(
        receipt.receipt_id[0..8]
            .try_into()
            .unwrap_or([0u8; 8]),
    );
    witness.payload.copy_from_slice(&commitment[0..8]);
    witness.aux.copy_from_slice(&commitment[8..16]);
    witness.capability_hash = fnv1a_32(&commitment);

    let sequence = log.append(witness);
    if sequence != position {
        // The payload already carries `position`; a race would make the
        // persisted record disagree with where it landed. Refuse.
        return Err(AnchorError::SequenceRaced);
    }

    Ok(AnchorOutcome {
        sequence,
        record,
        commitment,
    })
}

/// Recheck that a witness record is the anchoring record for `anchor`:
/// same action kind, and payload/aux/capability-hash all match the
/// recomputed commitment. This is what an auditor runs when walking the
/// chain (checklist C1 pairs it with `rvm_witness::verify_chain`).
#[must_use]
pub fn witness_matches_anchor(witness: &WitnessRecord, anchor: &AnchorRecordV1) -> bool {
    let commitment = anchor.commitment();
    let mut expected_payload = [0u8; 8];
    expected_payload.copy_from_slice(&commitment[0..8]);
    let mut expected_aux = [0u8; 8];
    expected_aux.copy_from_slice(&commitment[8..16]);
    witness.action_kind == ActionKind::AnchorExternalReceipt as u8
        && witness.sequence == anchor.position
        && witness.payload == expected_payload
        && witness.aux == expected_aux
        && witness.capability_hash == fnv1a_32(&commitment)
}
