//! Statistical recomputation (contract §6.1; ADR-322C §Update 2026-08-19).
//!
//! The decision is *recomputed*, never read (checklist B5): seed, PRNG,
//! resampling, and decimal encoding follow the normative procedure, and
//! every recomputed value must reproduce the receipt's `statistics`
//! byte-for-byte at scale 12.
//!
//! Inputs are parsed from the receipt's *encoded* decimal strings — the
//! only form a verifier ever has — which sidesteps contract gap G5 on the
//! verifying side. IEEE-754 doubles are used throughout, matching both
//! the producing implementation and the `recompute_reference.py` oracle.

use alloc::string::String;
use alloc::vec::Vec;
use core::fmt::Write as _;

use sha2::{Digest, Sha256};

use crate::jcs::Json;
use crate::receipt::ReceiptError;

/// Seed-derivation prefix. A domain-separation string for the bootstrap
/// PRNG, **not** an Ed25519 signing domain (contract §1).
pub const BOOTSTRAP_SEED_PREFIX: &str = "ruflo/bootstrap/v1";

/// Recompute the statistical decision for a structurally valid payload
/// and compare it against the recorded `statistics`. Returns the
/// recomputed `accepted` conjunct on success.
///
/// # Errors
///
/// [`ReceiptError::Statistics`] naming the first field that fails to
/// reproduce.
#[allow(clippy::too_many_lines)]
pub fn verify_statistics(payload: &Json) -> Result<bool, ReceiptError> {
    let statistics = payload
        .get("statistics")
        .ok_or(ReceiptError::Structure("statistics missing"))?;

    let deltas: Vec<f64> = payload
        .get("heldOutDeltas")
        .and_then(Json::as_arr)
        .ok_or(ReceiptError::Structure("heldOutDeltas missing"))?
        .iter()
        .map(|d| parse_decimal(d.as_str().unwrap_or("")))
        .collect::<Option<Vec<f64>>>()
        .ok_or(ReceiptError::Statistics("heldOutDeltas parse"))?;
    let baseline = decimal_field(payload, "baselineScore")?;
    let candidate = decimal_field(payload, "candidateScore")?;
    let frozen_anchor = decimal_field(statistics, "frozenAnchorRegression")?;
    let iterations = statistics
        .get("iterations")
        .and_then(Json::as_int)
        .ok_or(ReceiptError::Structure("iterations missing"))?;
    let iterations = usize::try_from(iterations)
        .map_err(|_| ReceiptError::Statistics("iterations out of range"))?;

    // Seed: SHA-256 over the concatenation, no separator; PRNG state is
    // the first four bytes, big-endian.
    let corpus_hash = str_field(payload, "corpusHash")?;
    let candidate_id = str_field(payload, "candidateId")?;
    let baseline_ref = str_field(payload, "baselineRef")?;
    let evaluation_run_id = str_field(payload, "evaluationRunId")?;
    let mut hasher = Sha256::new();
    hasher.update(BOOTSTRAP_SEED_PREFIX.as_bytes());
    hasher.update(corpus_hash.as_bytes());
    hasher.update(candidate_id.as_bytes());
    hasher.update(baseline_ref.as_bytes());
    hasher.update(evaluation_run_id.as_bytes());
    let digest: [u8; 32] = hasher.finalize().into();
    let seed_hex = hex(&digest);
    if str_field(statistics, "seedHex")? != seed_hex {
        return Err(ReceiptError::Statistics("seedHex"));
    }
    let mut state = u32::from_be_bytes([digest[0], digest[1], digest[2], digest[3]]);

    // LCG bootstrap: exactly n draws per resample, consumed in sequence.
    let n = deltas.len();
    let mut means = Vec::with_capacity(iterations);
    for _ in 0..iterations {
        if n == 0 {
            means.push(0.0);
            continue;
        }
        let mut total = 0.0_f64;
        for _ in 0..n {
            state = state.wrapping_mul(1_664_525).wrapping_add(1_013_904_223);
            let draw = f64::from(state) / 4_294_967_296.0;
            #[allow(clippy::cast_precision_loss, clippy::cast_possible_truncation, clippy::cast_sign_loss)]
            let index = (draw * n as f64) as usize;
            total += deltas[index];
        }
        #[allow(clippy::cast_precision_loss)]
        means.push(total / n as f64);
    }

    #[allow(clippy::cast_precision_loss)]
    let probability = means.iter().filter(|&&m| m > 0.0).count() as f64 / iterations as f64;
    let mut sorted = means;
    sorted.sort_by(f64::total_cmp);
    #[allow(clippy::cast_precision_loss, clippy::cast_possible_truncation, clippy::cast_sign_loss)]
    let ci_low = sorted[(0.025 * iterations as f64) as usize];

    let metric_epsilon = 1e-12_f64;
    let relative_lift = (candidate - baseline) / baseline.abs().max(metric_epsilon);
    let significant = probability >= 0.95 && ci_low > 0.0;
    let accepted = relative_lift >= 0.02 && significant && frozen_anchor <= 0.0;

    // Byte-for-byte comparison at scale 12 (checklist B5).
    for (field, recomputed) in [
        ("relativeLift", relative_lift),
        ("pairedBootstrapProbability", probability),
        ("pairedBootstrapDeltaCILow95", ci_low),
        ("frozenAnchorRegression", frozen_anchor),
    ] {
        let recorded = statistics
            .get(field)
            .and_then(Json::as_str)
            .ok_or(ReceiptError::Statistics("statistics field missing"))?;
        if decimal12(recomputed) != recorded {
            return Err(match field {
                "relativeLift" => ReceiptError::Statistics("relativeLift"),
                "pairedBootstrapProbability" => {
                    ReceiptError::Statistics("pairedBootstrapProbability")
                }
                "pairedBootstrapDeltaCILow95" => {
                    ReceiptError::Statistics("pairedBootstrapDeltaCILow95")
                }
                _ => ReceiptError::Statistics("frozenAnchorRegression"),
            });
        }
    }
    if statistics.get("significant").and_then(Json::as_bool) != Some(significant) {
        return Err(ReceiptError::Statistics("significant"));
    }
    if statistics.get("accepted").and_then(Json::as_bool) != Some(accepted) {
        return Err(ReceiptError::Statistics("accepted"));
    }

    // The decision conjoins the statistical rule with every named gate.
    let gates_all_pass = payload
        .get("gates")
        .and_then(Json::as_obj)
        .ok_or(ReceiptError::Structure("gates missing"))?
        .iter()
        .all(|(_, v)| v.as_bool() == Some(true));
    let decision = if accepted && gates_all_pass {
        "accepted"
    } else {
        "rejected"
    };
    if payload.get("decision").and_then(Json::as_str) != Some(decision) {
        return Err(ReceiptError::Statistics("decision"));
    }

    Ok(accepted)
}

/// Encode a value at scale 12 with trailing zeros stripped, matching the
/// normative encoding: `""` and `"-0"` collapse to `"0"`.
#[must_use]
pub fn decimal12(value: f64) -> String {
    let mut rendered = String::new();
    let _ = write!(rendered, "{value:.12}");
    if rendered.contains('.') {
        while rendered.ends_with('0') {
            rendered.pop();
        }
        if rendered.ends_with('.') {
            rendered.pop();
        }
    }
    if rendered.is_empty() || rendered == "-0" {
        rendered = String::from("0");
    }
    rendered
}

fn parse_decimal(text: &str) -> Option<f64> {
    if text.is_empty() {
        return None;
    }
    text.parse::<f64>().ok()
}

fn decimal_field(value: &Json, field: &str) -> Result<f64, ReceiptError> {
    value
        .get(field)
        .and_then(Json::as_str)
        .and_then(parse_decimal)
        .ok_or(ReceiptError::Statistics("decimal field parse"))
}

fn str_field<'a>(value: &'a Json, field: &str) -> Result<&'a str, ReceiptError> {
    value
        .get(field)
        .and_then(Json::as_str)
        .ok_or(ReceiptError::Structure("required string field missing"))
}

fn hex(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        let _ = write!(out, "{byte:02x}");
    }
    out
}
