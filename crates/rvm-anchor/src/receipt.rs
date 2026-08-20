//! `ruflo.flywheel-receipt/v1` verification (witness-receipt-contract.md §6).
//!
//! Implements the consumer side of the contract: strict structural
//! validation (the schema's `additionalProperties: false`, checklist A1),
//! content-ID recomputation (§3), Ed25519 signature verification over
//! domain-prefixed bytes (§4), statistical recomputation (§6.1, in
//! [`crate::stats`]), corpus-role disjointness (B7), expiry (B8), and
//! evidence grading (§5, B9).
//!
//! One deliberate divergence from the JSON Schema: the schema marks the
//! `signature` member optional so unsigned historical payloads still
//! validate structurally, but this verifier exists to *anchor* receipts,
//! and anchoring an unsigned receipt would commit the witness chain to a
//! record nobody attested. [`verify_receipt`] therefore refuses a missing
//! signature ([`ReceiptError::SignatureMissing`]).

use alloc::string::String;
use alloc::vec::Vec;

use ed25519_dalek::{Signature, VerifyingKey};
use sha2::{Digest, Sha256};

use crate::jcs::{Json, JsonError};
use crate::stats;

/// The one schema version this crate implements. Exact-match, never a
/// range (contract §8; checklist F1/F2).
pub const SUPPORTED_SCHEMA_VERSION: &str = "ruflo.flywheel-receipt/v1";

/// The one gate version whose statistical rule this crate can recompute.
/// A receipt under any other gate is refused rather than best-effort
/// judged under the wrong rule (checklist F1/F3).
pub const SUPPORTED_GATE_VERSION: &str = "ruflo.flywheel-gate/v1";

/// Ed25519 domain-separation prefix for receipts (contract §4).
pub const RECEIPT_DOMAIN: &str = "ruflo/flywheel-receipt/v1";

/// ADR-322C evidence grade for one authorizing term (contract §5).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EvidenceGrade {
    /// The verifier reproduced the term from data inside or
    /// content-addressed by the receipt.
    Recomputed,
    /// The term is cryptographically bound to an identified attestor.
    SignatureVerified,
    /// A bare claim; blocks the "independently verified" label unless
    /// its named attestor is in the approved set.
    TrustedAssertion,
}

/// One authorizing term with its grade and (for assertions) attestor.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TermGrade {
    /// The authorizing term's name.
    pub term: String,
    /// The grade the receipt claims for it.
    pub grade: EvidenceGrade,
    /// Attestor named by a `trusted-assertion` entry.
    pub attestor: Option<String>,
}

/// The result of a successful verification, carrying exactly what the
/// anchoring step needs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedReceipt {
    /// The receipt's content ID digest (the 32 bytes after `sha256:`),
    /// recomputed and matched against the recorded `receiptId`.
    pub receipt_id: [u8; 32],
    /// `schemaVersion` string, pinned to [`SUPPORTED_SCHEMA_VERSION`].
    pub schema_version: String,
    /// `gateVersion` string, pinned to [`SUPPORTED_GATE_VERSION`].
    pub gate_version: String,
    /// Raw Ed25519 public key that signed the receipt (matched against
    /// the trusted set).
    pub signer_public_key: [u8; 32],
    /// Recomputed promotion decision (`true` = `accepted`).
    pub accepted: bool,
    /// Grade of every authorizing term (contract §6 step 8).
    pub term_grades: Vec<TermGrade>,
    /// `true` only when no authorizing term is an unapproved assertion
    /// (ADR-322C §Verification; checklist B9).
    pub independently_verified: bool,
}

/// Why a receipt was refused.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ReceiptError {
    /// The document is not JSON in the contract's number domain.
    Json(JsonError),
    /// A field the schema does not whitelist (checklist A1 / gap G3).
    UnknownField(String),
    /// A required field is missing, has the wrong type, or fails its
    /// pattern. The message names the field and rule.
    Structure(&'static str),
    /// `schemaVersion` is not [`SUPPORTED_SCHEMA_VERSION`] (F2).
    UnsupportedSchemaVersion,
    /// `gateVersion` or `statistics.ruleVersion` is not
    /// [`SUPPORTED_GATE_VERSION`] — this verifier cannot recompute an
    /// unknown gate's rule, so it refuses rather than guesses (F1/F3).
    UnsupportedGateVersion,
    /// A recomputed content ID does not match the recorded one (B1).
    ContentIdMismatch(&'static str),
    /// No `signature` member. Structurally legal, but unanchorable.
    SignatureMissing,
    /// Malformed signature envelope: wrong `algorithm`, wrong `domain`
    /// (B4 replay defence), bad PEM, or a `signatureBase64` outside the
    /// hardened `^[A-Za-z0-9+/]{86}==$` bound.
    SignatureMalformed(&'static str),
    /// The signing key is not in the caller's trusted set (B3).
    UntrustedSigner,
    /// Ed25519 verification failed over the domain-prefixed bytes.
    SignatureInvalid,
    /// The statistical decision does not recompute (§6.1, B5). Note
    /// contract gap G5 when triaging: a legitimate ruflo receipt whose
    /// mean needs more than twelve decimals fails this way too.
    Statistics(&'static str),
    /// A task ID serves as both selection and promotion holdout (B7).
    CorpusRolesOverlap,
    /// A gate marked `true` has no `termVerification` entry (A7).
    GateWithoutTermVerification,
    /// `expiresAt <= now` (B8).
    Expired,
}

impl From<JsonError> for ReceiptError {
    fn from(e: JsonError) -> Self {
        Self::Json(e)
    }
}

impl core::fmt::Display for ReceiptError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Json(e) => write!(f, "receipt is not conforming JSON: {e}"),
            Self::UnknownField(name) => write!(f, "unknown field: {name}"),
            Self::Structure(msg) => write!(f, "structural violation: {msg}"),
            Self::UnsupportedSchemaVersion => write!(f, "unsupported schemaVersion"),
            Self::UnsupportedGateVersion => write!(f, "unsupported gateVersion"),
            Self::ContentIdMismatch(which) => write!(f, "{which} content ID mismatch"),
            Self::SignatureMissing => write!(f, "receipt carries no signature"),
            Self::SignatureMalformed(msg) => write!(f, "malformed signature: {msg}"),
            Self::UntrustedSigner => write!(f, "signer not in trusted set"),
            Self::SignatureInvalid => write!(f, "Ed25519 signature does not verify"),
            Self::Statistics(msg) => write!(f, "statistical decision does not recompute: {msg}"),
            Self::CorpusRolesOverlap => write!(f, "corpus roles are not disjoint"),
            Self::GateWithoutTermVerification => {
                write!(f, "passing gate lacks a termVerification entry")
            }
            Self::Expired => write!(f, "receipt is expired"),
        }
    }
}

/// Verify a `ruflo.flywheel-receipt/v1` document end to end.
///
/// `trusted_keys` are the raw Ed25519 public keys the caller accepts
/// receipts from; `approved_attestors` is the set a `trusted-assertion`
/// term may name and still count toward the "independently verified"
/// label; `now_utc` is the caller's clock as a contract timestamp
/// (`YYYY-MM-DDTHH:mm:ss.sssZ`) — the fixed-width format makes the expiry
/// comparison a plain string comparison.
///
/// # Errors
///
/// Any deviation from the contract refuses the receipt with the specific
/// [`ReceiptError`]; nothing is flagged-but-accepted.
pub fn verify_receipt(
    text: &str,
    trusted_keys: &[[u8; 32]],
    approved_attestors: &[&str],
    now_utc: &str,
) -> Result<VerifiedReceipt, ReceiptError> {
    if !is_timestamp(now_utc) {
        return Err(ReceiptError::Structure("now_utc is not a contract timestamp"));
    }
    let doc = Json::parse(text)?;
    validate_structure(&doc)?;

    let payload = doc.get("payload").ok_or(ReceiptError::Structure("payload missing"))?;

    // Content IDs (§3). candidateId = SHA-256(JCS(candidatePolicy));
    // receiptId = SHA-256(JCS(payload with receiptId omitted)).
    let policy = payload
        .get("candidatePolicy")
        .ok_or(ReceiptError::Structure("candidatePolicy missing"))?;
    let candidate_digest = sha256_str(&policy.canonicalize());
    let recorded_candidate = payload
        .get("candidateId")
        .and_then(Json::as_str)
        .ok_or(ReceiptError::Structure("candidateId missing"))?;
    if content_id(&candidate_digest) != recorded_candidate {
        return Err(ReceiptError::ContentIdMismatch("candidate"));
    }

    let payload_pairs = payload.as_obj().ok_or(ReceiptError::Structure("payload not an object"))?;
    let without_receipt_id: Vec<(String, Json)> = payload_pairs
        .iter()
        .filter(|(k, _)| k != "receiptId")
        .cloned()
        .collect();
    let receipt_digest = sha256_str(&Json::Obj(without_receipt_id).canonicalize());
    let recorded_receipt = payload
        .get("receiptId")
        .and_then(Json::as_str)
        .ok_or(ReceiptError::Structure("receiptId missing"))?;
    if content_id(&receipt_digest) != recorded_receipt {
        return Err(ReceiptError::ContentIdMismatch("receipt"));
    }

    // Signature (§4): Ed25519 over UTF8(domain) || 0x00 || JCS(payload),
    // where payload here INCLUDES receiptId.
    let signature = doc.get("signature").ok_or(ReceiptError::SignatureMissing)?;
    let public_key = extract_signer_key(signature)?;
    if !trusted_keys.contains(&public_key) {
        return Err(ReceiptError::UntrustedSigner);
    }
    let signature_bytes = decode_signature(signature)?;
    let canonical_payload = payload.canonicalize();
    let mut signed_bytes =
        Vec::with_capacity(RECEIPT_DOMAIN.len() + 1 + canonical_payload.len());
    signed_bytes.extend_from_slice(RECEIPT_DOMAIN.as_bytes());
    signed_bytes.push(0x00);
    signed_bytes.extend_from_slice(canonical_payload.as_bytes());
    let verifying_key = VerifyingKey::from_bytes(&public_key)
        .map_err(|_| ReceiptError::SignatureMalformed("public key is not a valid Ed25519 point"))?;
    let signature = Signature::from_bytes(&signature_bytes);
    verifying_key
        .verify_strict(&signed_bytes, &signature)
        .map_err(|_| ReceiptError::SignatureInvalid)?;

    // Statistics (§6.1): recompute the decision from the encoded values.
    let accepted = stats::verify_statistics(payload)?;

    // Preconditions and evidence checks the contract puts on verifiers.
    check_expiry(payload, now_utc)?;
    check_corpus_roles(payload)?;
    let term_grades = collect_term_grades(payload)?;
    check_gate_coverage(payload, &term_grades)?;
    let independently_verified = term_grades.iter().all(|t| match t.grade {
        EvidenceGrade::Recomputed | EvidenceGrade::SignatureVerified => true,
        EvidenceGrade::TrustedAssertion => t
            .attestor
            .as_deref()
            .is_some_and(|a| approved_attestors.contains(&a)),
    });

    let schema_version = payload
        .get("schemaVersion")
        .and_then(Json::as_str)
        .ok_or(ReceiptError::Structure("schemaVersion missing"))?;
    let gate_version = payload
        .get("gateVersion")
        .and_then(Json::as_str)
        .ok_or(ReceiptError::Structure("gateVersion missing"))?;

    Ok(VerifiedReceipt {
        receipt_id: receipt_digest,
        schema_version: String::from(schema_version),
        gate_version: String::from(gate_version),
        signer_public_key: public_key,
        accepted,
        term_grades,
        independently_verified,
    })
}

// ── structural validation (the schema's rules, enforced fail-closed) ────

const PAYLOAD_REQUIRED: &[&str] = &[
    "schemaVersion",
    "receiptId",
    "lineageId",
    "candidateId",
    "evaluationRunId",
    "baselineRef",
    "expectedLedgerHead",
    "candidatePolicy",
    "gateVersion",
    "policySchemaVersion",
    "safetyEnvelopeRef",
    "requestedProposer",
    "effectiveProposer",
    "corpusVersion",
    "corpusHash",
    "baselineScore",
    "candidateScore",
    "heldOutDeltas",
    "statistics",
    "gates",
    "resourceEvidence",
    "evidence",
    "termVerification",
    "decision",
    "issuedAt",
    "expiresAt",
];

const PAYLOAD_OPTIONAL: &[&str] = &["anchorRef", "proposerSubstitution", "pairedOutcomes"];

// A linear transcription of the schema's field rules; splitting it would
// scatter the whitelist the unknown-field defence depends on.
#[allow(clippy::too_many_lines)]
fn validate_structure(doc: &Json) -> Result<(), ReceiptError> {
    let top = doc.as_obj().ok_or(ReceiptError::Structure("document is not an object"))?;
    for (key, _) in top {
        if key != "payload" && key != "signature" {
            return Err(ReceiptError::UnknownField(key.clone()));
        }
    }
    let payload = doc.get("payload").ok_or(ReceiptError::Structure("payload missing"))?;
    let pairs = payload.as_obj().ok_or(ReceiptError::Structure("payload not an object"))?;

    for (key, _) in pairs {
        if !PAYLOAD_REQUIRED.contains(&key.as_str()) && !PAYLOAD_OPTIONAL.contains(&key.as_str()) {
            return Err(ReceiptError::UnknownField(key.clone()));
        }
    }
    for required in PAYLOAD_REQUIRED {
        if payload.get(required).is_none() {
            return Err(ReceiptError::Structure("required payload field missing"));
        }
    }

    if payload.get("schemaVersion").and_then(Json::as_str) != Some(SUPPORTED_SCHEMA_VERSION) {
        return Err(ReceiptError::UnsupportedSchemaVersion);
    }
    if payload.get("gateVersion").and_then(Json::as_str) != Some(SUPPORTED_GATE_VERSION) {
        return Err(ReceiptError::UnsupportedGateVersion);
    }

    check_pattern(payload, "receiptId", is_content_id, "receiptId is not a content ID")?;
    check_pattern(payload, "candidateId", is_content_id, "candidateId is not a content ID")?;
    check_pattern(payload, "baselineRef", is_content_id, "baselineRef is not a content ID")?;
    check_pattern(
        payload,
        "expectedLedgerHead",
        is_content_id,
        "expectedLedgerHead is not a content ID",
    )?;
    check_pattern(payload, "safetyEnvelopeRef", is_content_id, "safetyEnvelopeRef is not a content ID")?;
    check_pattern(payload, "corpusHash", is_content_id, "corpusHash is not a content ID")?;
    check_pattern(payload, "lineageId", is_uuid_v7, "lineageId is not a UUIDv7")?;
    check_pattern(payload, "evaluationRunId", is_uuid_v7, "evaluationRunId is not a UUIDv7")?;
    check_pattern(payload, "issuedAt", is_timestamp, "issuedAt is not a contract timestamp")?;
    check_pattern(payload, "expiresAt", is_timestamp, "expiresAt is not a contract timestamp")?;
    check_pattern(payload, "baselineScore", is_decimal_string, "baselineScore is not a decimal string")?;
    check_pattern(
        payload,
        "candidateScore",
        is_decimal_string,
        "candidateScore is not a decimal string",
    )?;
    if let Some(anchor_ref) = payload.get("anchorRef") {
        if !anchor_ref.as_str().is_some_and(is_content_id) {
            return Err(ReceiptError::Structure("anchorRef is not a content ID"));
        }
    }
    if payload.get("candidatePolicy").and_then(Json::as_obj).is_none() {
        return Err(ReceiptError::Structure("candidatePolicy is not an object"));
    }
    check_nonempty_str(payload, "policySchemaVersion")?;
    check_nonempty_str(payload, "corpusVersion")?;
    if let Some(substitution) = payload.get("proposerSubstitution") {
        if !substitution.as_str().is_some_and(|s| !s.is_empty()) {
            return Err(ReceiptError::Structure("proposerSubstitution is empty"));
        }
    }

    let requested = payload.get("requestedProposer").and_then(Json::as_str);
    if !matches!(requested, Some("auto" | "local" | "darwin")) {
        return Err(ReceiptError::Structure("requestedProposer outside enum"));
    }
    let effective = payload.get("effectiveProposer").and_then(Json::as_str);
    if !matches!(effective, Some("local" | "darwin")) {
        return Err(ReceiptError::Structure("effectiveProposer outside enum"));
    }
    let decision = payload.get("decision").and_then(Json::as_str);
    if !matches!(decision, Some("accepted" | "rejected")) {
        return Err(ReceiptError::Structure("decision outside enum"));
    }

    let deltas = payload
        .get("heldOutDeltas")
        .and_then(Json::as_arr)
        .ok_or(ReceiptError::Structure("heldOutDeltas is not an array"))?;
    if !deltas.iter().all(|d| d.as_str().is_some_and(is_decimal_string)) {
        return Err(ReceiptError::Structure("heldOutDeltas entry is not a decimal string"));
    }

    if let Some(outcomes) = payload.get("pairedOutcomes") {
        let outcomes = outcomes
            .as_arr()
            .ok_or(ReceiptError::Structure("pairedOutcomes is not an array"))?;
        // ADR-381: task-level evidence mirrors the aggregate deltas.
        if outcomes.len() != deltas.len() {
            return Err(ReceiptError::Structure("pairedOutcomes length differs from heldOutDeltas"));
        }
        for outcome in outcomes {
            validate_exact_object(
                outcome,
                &["taskId", "baselineScore", "candidateScore"],
                &[],
                "pairedOutcomes entry",
            )?;
            if !outcome.get("taskId").and_then(Json::as_str).is_some_and(|s| !s.is_empty()) {
                return Err(ReceiptError::Structure("pairedOutcomes taskId is empty"));
            }
            for score in ["baselineScore", "candidateScore"] {
                if !outcome.get(score).and_then(Json::as_str).is_some_and(is_decimal_string) {
                    return Err(ReceiptError::Structure("pairedOutcomes score is not decimal"));
                }
            }
        }
    }

    validate_statistics(payload)?;
    validate_resource_evidence(payload)?;
    validate_gates(payload)?;
    validate_evidence(payload)?;
    validate_term_verification(payload)?;
    if let Some(signature) = doc.get("signature") {
        validate_signature_envelope(signature)?;
    }
    Ok(())
}

fn validate_statistics(payload: &Json) -> Result<(), ReceiptError> {
    let statistics = payload
        .get("statistics")
        .ok_or(ReceiptError::Structure("statistics missing"))?;
    validate_exact_object(
        statistics,
        &[
            "ruleVersion",
            "relativeLift",
            "pairedBootstrapProbability",
            "pairedBootstrapDeltaCILow95",
            "frozenAnchorRegression",
            "iterations",
            "seedHex",
            "significant",
            "accepted",
        ],
        &[],
        "statistics",
    )?;
    // ruleVersion pins the statistical rule this crate recomputes.
    if statistics.get("ruleVersion").and_then(Json::as_str) != Some(SUPPORTED_GATE_VERSION) {
        return Err(ReceiptError::UnsupportedGateVersion);
    }
    for field in [
        "relativeLift",
        "pairedBootstrapProbability",
        "pairedBootstrapDeltaCILow95",
        "frozenAnchorRegression",
    ] {
        if !statistics.get(field).and_then(Json::as_str).is_some_and(is_decimal_string) {
            return Err(ReceiptError::Structure("statistics field is not a decimal string"));
        }
    }
    if !statistics.get("iterations").and_then(Json::as_int).is_some_and(|i| i >= 100) {
        return Err(ReceiptError::Structure("statistics.iterations below 100"));
    }
    let seed_hex = statistics.get("seedHex").and_then(Json::as_str);
    if !seed_hex.is_some_and(|s| s.len() == 64 && s.bytes().all(is_lower_hex)) {
        return Err(ReceiptError::Structure("statistics.seedHex is not 64 lowercase hex"));
    }
    for field in ["significant", "accepted"] {
        if statistics.get(field).and_then(Json::as_bool).is_none() {
            return Err(ReceiptError::Structure("statistics flag is not a boolean"));
        }
    }
    Ok(())
}

fn validate_resource_evidence(payload: &Json) -> Result<(), ReceiptError> {
    let resource = payload
        .get("resourceEvidence")
        .ok_or(ReceiptError::Structure("resourceEvidence missing"))?;
    validate_exact_object(
        resource,
        &[
            "p95LatencyMicros",
            "costMicrosPerTask",
            "tokensPerTask",
            "failureRate",
            "evaluationCostMicros",
            "currency",
        ],
        &["energyMicrojoules"],
        "resourceEvidence",
    )?;
    for field in [
        "p95LatencyMicros",
        "costMicrosPerTask",
        "tokensPerTask",
        "evaluationCostMicros",
    ] {
        if !resource.get(field).and_then(Json::as_int).is_some_and(|i| i >= 0) {
            return Err(ReceiptError::Structure("resourceEvidence integer is negative or missing"));
        }
    }
    if let Some(energy) = resource.get("energyMicrojoules") {
        if !energy.as_int().is_some_and(|i| i >= 0) {
            return Err(ReceiptError::Structure("energyMicrojoules is negative or not an integer"));
        }
    }
    if !resource.get("failureRate").and_then(Json::as_str).is_some_and(is_decimal_string) {
        return Err(ReceiptError::Structure("failureRate is not a decimal string"));
    }
    let currency = resource.get("currency").and_then(Json::as_str);
    if !currency.is_some_and(|c| c.len() == 3 && c.bytes().all(|b| b.is_ascii_uppercase())) {
        return Err(ReceiptError::Structure("currency is not ISO 4217"));
    }
    Ok(())
}

fn validate_gates(payload: &Json) -> Result<(), ReceiptError> {
    let gates = payload
        .get("gates")
        .and_then(Json::as_obj)
        .ok_or(ReceiptError::Structure("gates is not an object"))?;
    if gates.is_empty() {
        return Err(ReceiptError::Structure("gates is empty"));
    }
    if !gates.iter().all(|(_, v)| v.as_bool().is_some()) {
        return Err(ReceiptError::Structure("gates value is not a boolean"));
    }
    Ok(())
}

fn validate_evidence(payload: &Json) -> Result<(), ReceiptError> {
    let evidence = payload
        .get("evidence")
        .ok_or(ReceiptError::Structure("evidence missing"))?;
    validate_exact_object(evidence, &["corpusRoles", "verification", "canary"], &[], "evidence")?;
    let roles = evidence
        .get("corpusRoles")
        .ok_or(ReceiptError::Structure("corpusRoles missing"))?;
    validate_exact_object(
        roles,
        &["selectionTaskIds", "promotionHoldoutTaskIds", "guardTaskIds"],
        &[],
        "corpusRoles",
    )?;
    for field in ["selectionTaskIds", "promotionHoldoutTaskIds", "guardTaskIds"] {
        let ids = roles
            .get(field)
            .and_then(Json::as_arr)
            .ok_or(ReceiptError::Structure("corpus role list is not an array"))?;
        if !ids.iter().all(|id| id.as_str().is_some()) {
            return Err(ReceiptError::Structure("corpus role entry is not a string"));
        }
    }
    // `verification` and `canary` are free-form objects per the schema.
    for field in ["verification", "canary"] {
        if evidence.get(field).and_then(Json::as_obj).is_none() {
            return Err(ReceiptError::Structure("evidence sub-object is not an object"));
        }
    }
    Ok(())
}

fn validate_term_verification(payload: &Json) -> Result<(), ReceiptError> {
    let entries = payload
        .get("termVerification")
        .and_then(Json::as_arr)
        .ok_or(ReceiptError::Structure("termVerification is not an array"))?;
    for entry in entries {
        validate_exact_object(
            entry,
            &["term", "verification", "evidenceRef"],
            &["attestor"],
            "termVerification entry",
        )?;
        if !entry.get("term").and_then(Json::as_str).is_some_and(|s| !s.is_empty()) {
            return Err(ReceiptError::Structure("termVerification term is empty"));
        }
        if !entry.get("evidenceRef").and_then(Json::as_str).is_some_and(|s| !s.is_empty()) {
            return Err(ReceiptError::Structure("termVerification evidenceRef is empty"));
        }
        let grade = entry.get("verification").and_then(Json::as_str);
        match grade {
            Some("recomputed" | "signature-verified") => {}
            Some("trusted-assertion") => {
                // A bare assertion must name its attestor (contract §5).
                if !entry.get("attestor").and_then(Json::as_str).is_some_and(|s| !s.is_empty()) {
                    return Err(ReceiptError::Structure("trusted-assertion names no attestor"));
                }
            }
            _ => return Err(ReceiptError::Structure("verification outside evidence grades")),
        }
    }
    Ok(())
}

fn validate_signature_envelope(signature: &Json) -> Result<(), ReceiptError> {
    validate_exact_object(
        signature,
        &["algorithm", "domain", "publicKeyPem", "signatureBase64"],
        &[],
        "signature",
    )?;
    if signature.get("algorithm").and_then(Json::as_str) != Some("ed25519") {
        return Err(ReceiptError::SignatureMalformed("algorithm is not ed25519"));
    }
    // Exact-domain check: the replay defence (B4). A signature valid
    // under any other ruflo domain must not verify as a receipt.
    if signature.get("domain").and_then(Json::as_str) != Some(RECEIPT_DOMAIN) {
        return Err(ReceiptError::SignatureMalformed("domain is not the receipt domain"));
    }
    let pem = signature.get("publicKeyPem").and_then(Json::as_str);
    if !pem.is_some_and(|p| p.starts_with("-----BEGIN PUBLIC KEY-----")) {
        return Err(ReceiptError::SignatureMalformed("publicKeyPem is not SPKI PEM"));
    }
    // Hardened bound: exactly 86 base64 characters plus "==" padding —
    // one Ed25519 signature, nothing longer.
    let sig = signature.get("signatureBase64").and_then(Json::as_str);
    if !sig.is_some_and(is_signature_base64) {
        return Err(ReceiptError::SignatureMalformed(
            "signatureBase64 outside ^[A-Za-z0-9+/]{86}==$",
        ));
    }
    Ok(())
}

fn validate_exact_object(
    value: &Json,
    required: &[&str],
    optional: &[&str],
    what: &'static str,
) -> Result<(), ReceiptError> {
    let pairs = value.as_obj().ok_or(ReceiptError::Structure(what))?;
    for (key, _) in pairs {
        if !required.contains(&key.as_str()) && !optional.contains(&key.as_str()) {
            return Err(ReceiptError::UnknownField(key.clone()));
        }
    }
    for field in required {
        if value.get(field).is_none() {
            return Err(ReceiptError::Structure(what));
        }
    }
    Ok(())
}

// ── verifier-side evidence checks ───────────────────────────────────────

fn check_expiry(payload: &Json, now_utc: &str) -> Result<(), ReceiptError> {
    let expires = payload
        .get("expiresAt")
        .and_then(Json::as_str)
        .ok_or(ReceiptError::Structure("expiresAt missing"))?;
    // Both strings are fixed-width YYYY-MM-DDTHH:mm:ss.sssZ, so string
    // order is chronological order.
    if expires <= now_utc {
        return Err(ReceiptError::Expired);
    }
    Ok(())
}

fn check_corpus_roles(payload: &Json) -> Result<(), ReceiptError> {
    let roles = payload
        .get("evidence")
        .and_then(|e| e.get("corpusRoles"))
        .ok_or(ReceiptError::Structure("corpusRoles missing"))?;
    let selection = roles
        .get("selectionTaskIds")
        .and_then(Json::as_arr)
        .ok_or(ReceiptError::Structure("selectionTaskIds missing"))?;
    let holdout = roles
        .get("promotionHoldoutTaskIds")
        .and_then(Json::as_arr)
        .ok_or(ReceiptError::Structure("promotionHoldoutTaskIds missing"))?;
    for task in selection {
        if holdout.iter().any(|h| h.as_str() == task.as_str()) {
            return Err(ReceiptError::CorpusRolesOverlap);
        }
    }
    Ok(())
}

fn collect_term_grades(payload: &Json) -> Result<Vec<TermGrade>, ReceiptError> {
    let entries = payload
        .get("termVerification")
        .and_then(Json::as_arr)
        .ok_or(ReceiptError::Structure("termVerification missing"))?;
    let mut grades = Vec::with_capacity(entries.len());
    for entry in entries {
        let term = entry
            .get("term")
            .and_then(Json::as_str)
            .ok_or(ReceiptError::Structure("term missing"))?;
        let grade = match entry.get("verification").and_then(Json::as_str) {
            Some("recomputed") => EvidenceGrade::Recomputed,
            Some("signature-verified") => EvidenceGrade::SignatureVerified,
            Some("trusted-assertion") => EvidenceGrade::TrustedAssertion,
            _ => return Err(ReceiptError::Structure("verification outside evidence grades")),
        };
        let attestor = entry.get("attestor").and_then(Json::as_str).map(String::from);
        grades.push(TermGrade {
            term: String::from(term),
            grade,
            attestor,
        });
    }
    Ok(grades)
}

fn check_gate_coverage(payload: &Json, grades: &[TermGrade]) -> Result<(), ReceiptError> {
    let gates = payload
        .get("gates")
        .and_then(Json::as_obj)
        .ok_or(ReceiptError::Structure("gates missing"))?;
    for (gate, passed) in gates {
        if passed.as_bool() == Some(true) && !grades.iter().any(|g| g.term == *gate) {
            return Err(ReceiptError::GateWithoutTermVerification);
        }
    }
    Ok(())
}

// ── signature envelope decoding ─────────────────────────────────────────

/// DER prefix of an Ed25519 `SubjectPublicKeyInfo` (RFC 8410): a fixed
/// 12-byte header followed by the raw 32-byte key.
const ED25519_SPKI_PREFIX: [u8; 12] = [
    0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00,
];

fn extract_signer_key(signature: &Json) -> Result<[u8; 32], ReceiptError> {
    let pem = signature
        .get("publicKeyPem")
        .and_then(Json::as_str)
        .ok_or(ReceiptError::SignatureMalformed("publicKeyPem missing"))?;
    let body: String = pem
        .lines()
        .filter(|line| !line.starts_with("-----"))
        .collect();
    let der = base64_decode(&body).ok_or(ReceiptError::SignatureMalformed("publicKeyPem base64"))?;
    if der.len() != 44 || der[..12] != ED25519_SPKI_PREFIX {
        return Err(ReceiptError::SignatureMalformed("publicKeyPem is not Ed25519 SPKI"));
    }
    let mut key = [0u8; 32];
    key.copy_from_slice(&der[12..]);
    Ok(key)
}

fn decode_signature(signature: &Json) -> Result<[u8; 64], ReceiptError> {
    let text = signature
        .get("signatureBase64")
        .and_then(Json::as_str)
        .ok_or(ReceiptError::SignatureMalformed("signatureBase64 missing"))?;
    if !is_signature_base64(text) {
        return Err(ReceiptError::SignatureMalformed(
            "signatureBase64 outside ^[A-Za-z0-9+/]{86}==$",
        ));
    }
    let bytes = base64_decode(text).ok_or(ReceiptError::SignatureMalformed("signature base64"))?;
    let mut out = [0u8; 64];
    if bytes.len() != 64 {
        return Err(ReceiptError::SignatureMalformed("signature is not 64 bytes"));
    }
    out.copy_from_slice(&bytes);
    Ok(out)
}

/// Standard base64 (RFC 4648, with padding) decoder.
#[allow(clippy::cast_possible_truncation)] // byte extraction from a 24-bit accumulator
fn base64_decode(text: &str) -> Option<Vec<u8>> {
    fn value(b: u8) -> Option<u32> {
        match b {
            b'A'..=b'Z' => Some(u32::from(b - b'A')),
            b'a'..=b'z' => Some(u32::from(b - b'a') + 26),
            b'0'..=b'9' => Some(u32::from(b - b'0') + 52),
            b'+' => Some(62),
            b'/' => Some(63),
            _ => None,
        }
    }
    let bytes = text.as_bytes();
    if bytes.len() % 4 != 0 {
        return None;
    }
    let mut out = Vec::with_capacity(bytes.len() / 4 * 3);
    for chunk in bytes.chunks(4) {
        let pad = chunk.iter().rev().take_while(|&&b| b == b'=').count();
        if pad > 2 || chunk[..4 - pad].iter().any(|&b| value(b).is_none()) {
            return None;
        }
        let mut acc: u32 = 0;
        for &b in &chunk[..4 - pad] {
            acc = (acc << 6) | value(b)?;
        }
        acc <<= 6 * pad as u32;
        out.push((acc >> 16) as u8);
        if pad < 2 {
            out.push((acc >> 8) as u8);
        }
        if pad < 1 {
            out.push(acc as u8);
        }
    }
    Some(out)
}

// ── patterns and small helpers ──────────────────────────────────────────

pub(crate) fn sha256_str(text: &str) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(text.as_bytes());
    hasher.finalize().into()
}

/// Render a digest as an ADR-322C content ID: `sha256:<lowercase-hex>`.
#[must_use]
pub fn content_id(digest: &[u8; 32]) -> String {
    let mut out = String::with_capacity(7 + 64);
    out.push_str("sha256:");
    for byte in digest {
        let _ = core::fmt::write(&mut out, format_args!("{byte:02x}"));
    }
    out
}

fn is_lower_hex(b: u8) -> bool {
    b.is_ascii_digit() || (b'a'..=b'f').contains(&b)
}

fn is_content_id(s: &str) -> bool {
    s.len() == 71 && s.starts_with("sha256:") && s.as_bytes()[7..].iter().all(|&b| is_lower_hex(b))
}

fn is_uuid_v7(s: &str) -> bool {
    let b = s.as_bytes();
    if b.len() != 36 {
        return false;
    }
    for (i, &c) in b.iter().enumerate() {
        match i {
            8 | 13 | 18 | 23 => {
                if c != b'-' {
                    return false;
                }
            }
            14 => {
                if c != b'7' {
                    return false;
                }
            }
            19 => {
                if !matches!(c, b'8' | b'9' | b'a' | b'b') {
                    return false;
                }
            }
            _ => {
                if !is_lower_hex(c) {
                    return false;
                }
            }
        }
    }
    true
}

pub(crate) fn is_timestamp(s: &str) -> bool {
    let b = s.as_bytes();
    if b.len() != 24 {
        return false;
    }
    for (i, &c) in b.iter().enumerate() {
        match i {
            4 | 7 => {
                if c != b'-' {
                    return false;
                }
            }
            10 => {
                if c != b'T' {
                    return false;
                }
            }
            13 | 16 => {
                if c != b':' {
                    return false;
                }
            }
            19 => {
                if c != b'.' {
                    return false;
                }
            }
            23 => {
                if c != b'Z' {
                    return false;
                }
            }
            _ => {
                if !c.is_ascii_digit() {
                    return false;
                }
            }
        }
    }
    true
}

fn is_decimal_string(s: &str) -> bool {
    // ^-?(0|[1-9][0-9]*)(\.[0-9]+)?$
    let s = s.strip_prefix('-').unwrap_or(s);
    let (int_part, frac_part) = match s.split_once('.') {
        Some((i, f)) => (i, Some(f)),
        None => (s, None),
    };
    let int_ok = int_part == "0"
        || (!int_part.is_empty()
            && int_part.as_bytes()[0] != b'0'
            && int_part.bytes().all(|b| b.is_ascii_digit()));
    let frac_ok = match frac_part {
        None => true,
        Some(f) => !f.is_empty() && f.bytes().all(|b| b.is_ascii_digit()),
    };
    int_ok && frac_ok
}

fn is_signature_base64(s: &str) -> bool {
    let b = s.as_bytes();
    b.len() == 88
        && b[..86]
            .iter()
            .all(|&c| c.is_ascii_alphanumeric() || c == b'+' || c == b'/')
        && b[86] == b'='
        && b[87] == b'='
}

fn check_pattern(
    payload: &Json,
    field: &str,
    pattern: fn(&str) -> bool,
    msg: &'static str,
) -> Result<(), ReceiptError> {
    if payload.get(field).and_then(Json::as_str).is_some_and(pattern) {
        Ok(())
    } else {
        Err(ReceiptError::Structure(msg))
    }
}

fn check_nonempty_str(payload: &Json, field: &str) -> Result<(), ReceiptError> {
    if payload.get(field).and_then(Json::as_str).is_some_and(|s| !s.is_empty()) {
        Ok(())
    } else {
        Err(ReceiptError::Structure("required string field empty or missing"))
    }
}
