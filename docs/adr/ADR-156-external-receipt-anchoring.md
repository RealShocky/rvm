# ADR-156: External Receipt Anchoring into the Witness Chain

**Status**: Proposed
**Date**: 2026-08-20
**Authors**: Claude Code (PIR WP8, `ruvnet/rvm#35`)
**Supersedes**: None
**Related**: ADR-134 (Witness Schema), RuVector ADR-285 (Hosted RVM Security Boundary), ruflo ADR-322C via `v3/docs/spec/witness-receipt-contract.md` (tracked by `ruvnet/ruflo#3066`)

---

## Context

The Perpetual Intelligence Runtime program needs promoted mutations to be
traceable end to end in one witness-chain query. ruflo's flywheel emits the
evaluation evidence for those promotions as `ruflo.flywheel-receipt/v1`
records, whose format and verification algorithm are now a language-neutral
contract on ruflo `main`: `v3/docs/spec/witness-receipt-contract.md`, three
JSON Schemas, implementation-generated fixtures, and a conformance checklist
(merged via ruvnet/ruflo#3067).

RVM's witness chain (ADR-134) records privileged actions in 64-byte
hash-chained records. For the program's traceability query to include ruflo
promotions, RVM must be able to (a) independently verify a receipt against
the contract and (b) anchor a commitment to it into the chain — without
pretending the anchored record gains anything by being there.

Facts from the contract that shape the design:

- ADR-322C defines exactly **two** Ed25519 signing domains:
  `ruflo/flywheel-receipt/v1` (implemented) and
  `ruflo/flywheel-ledger-head/v1` (specified but **not implemented** on
  ruflo `main`, contract gap G2). Anchoring the ledger head would anchor a
  signature that does not exist; the receipt is the anchorable record
  (checklist C3). A third `…/v1` string, `ruflo/bootstrap/v1`, is a
  PRNG-seed prefix, not a signing domain.
- The contract's canonical form is RFC 8785 JCS + SHA-256 content IDs +
  Ed25519 over `UTF8(domain) || 0x00 || JCS(payload)`, with fractional
  values as decimal strings and floats forbidden.
- The **anchor-record format is not part of ADR-322C.** The contract's §9
  publishes `ruflo.anchor-record/v1` — including the `assuranceLevel` field
  and the `ruflo/flywheel-anchor/v1` domain — explicitly as a
  `PROPOSED-EXTENSION`: a PIR proposal pending ruflo review that requires
  its own ADR before anything depends on it. This ADR is the RVM-side half
  of that record; its **Proposed** status is deliberate and should not move
  to Accepted before the extension is ratified on the ruflo side.

## Decision

1. **New crate `rvm-anchor`** (no_std + alloc) implements the consumer side
   of the contract:
   - a JCS canonicalizer restricted to the contract's number domain
     (integers only; floats, exponents, and `-0` are refused, which is
     stricter than RFC 8785 and exactly as strict as the contract);
   - strict structural validation equivalent to the schema's
     `additionalProperties: false` — unknown fields are refused (checklist
     A1, contract gap G3);
   - content-ID recomputation, exact-domain Ed25519 verification against a
     caller-supplied trusted-key set, statistical recomputation per the
     normative bootstrap (ADR-322C §Update 2026-08-19), corpus-role
     disjointness, expiry, and evidence grading (checklist B1–B9).
2. **One new `ActionKind`**: `AnchorExternalReceipt = 0xB0`, opening the
   0xB0–0xBF "external anchoring" subsystem range. The 64-byte witness
   record binds the anchor record by commitment: `payload` and `aux` carry
   the first 16 bytes of `SHA-256(JCS(anchor payload))`,
   `capability_hash` its FNV-1a-32, and `target_object_id` the first 8
   bytes of the anchored receipt ID. The full anchor record is sidecar
   data; any verifier recomputes the commitment from it.
3. **Version policy — pin strings, not SHAs.** The crate pins
   `schemaVersion = "ruflo.flywheel-receipt/v1"` and
   `gateVersion = "ruflo.flywheel-gate/v1"` as exact strings and refuses
   anything else. No ruflo git SHA appears anywhere: a SHA pin would couple
   RVM's release cadence to ruflo's commit history, violating the program's
   release-train rule. This is the recommendation put to `ruvnet/rvm#35`
   for ratification (checklist F1–F3).
4. **Assurance honesty (RuVector ADR-285).** A ruflo receipt is a
   service-side artifact. `anchor_verified_receipt` stamps
   `assuranceLevel: "service-side"` unconditionally — the API has no
   parameter through which a caller could claim `hypervisor-side` for a
   record verified out of a foreign repo. Anchoring records provenance; it
   confers nothing (checklist C4).
5. **No dependency edge to `autogenous`.** Both repos consume the ruflo
   contract independently (checklist C5).

## Consequences

- The PIR traceability query can join ruflo promotions to RVM witness
  records via `receiptId` → `AnchorExternalReceipt` commitments.
- Conformance is tested against the ruflo fixtures **verbatim** (copied at
  ruflo merge commit `df0c9821984b2b0f76ea0ea6eb6cfe5abda5bd54`), including
  the discriminating bootstrap-reference fixture, so the statistical
  recomputation is checked against an implementation-generated oracle, not
  against this crate's own output.
- If ruflo ratifies a different anchor-record shape, `rvm-anchor`'s
  `anchor` module changes with it; the verification half (`receipt`,
  `stats`, `jcs`) tracks ADR-322C itself and is insulated from that
  outcome.
- A receipt under a future `gateVersion` is refused until this crate
  implements that gate's rule — fail-closed by design, at the cost of a
  release to adopt each new gate.
