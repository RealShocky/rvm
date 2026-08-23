# ADR-157: Capability-Governed `ruv://` Context Namespace

**Status**: Proposed
**Date**: 2026-08-22
**Authors**: RVM Contributors
**Supersedes**: None
**Related**: ADR-134 (Witness Schema), ADR-149 (RVF Integration), ADR-155
(RVF Execution Contract), ADR-156 (External Receipt Anchoring), ADR-158
(Durable Hosted `ruv://` Context Service)

---

## Context

Agents need one stable way to name resources, memories, and skills without
turning a path into ambient authority. A useful context name must work across
processes and hosts, cite immutable bytes when reproducibility matters, support
human-friendly mutable aliases, expose progressively larger representations,
and remain safe when the named content is hostile.

OpenViking demonstrates several useful product patterns: one inspectable
context hierarchy for resources, memories, and skills; progressively disclosed
representations; directory-aware retrieval; and observable retrieval paths.
Those patterns motivate this work. This repository does not import, translate,
or derive code from OpenViking. The implementation is a clean RVM-native design
under this repository's MIT OR Apache-2.0 license. This separation is
intentional because the main OpenViking repository is AGPL-3.0 licensed.

The RVM and RVF boundaries impose stronger requirements than a virtual
filesystem alone:

1. A name cannot grant access. RVM capabilities are the authority.
2. Authorization must happen before a RuVector or other retrieval backend can
   enumerate candidates. Filtering an already searched shared index is not an
   authorization boundary.
3. A reproducible citation must bind all bytes in the RVF, not a mutable path
   or a truncated segment hash.
4. Inspecting or reading a skill must never execute it. Execution is a distinct
   operation with distinct authority.
5. Mutable names need an atomic compare-and-swap rule. In-place updates would
   permit lost updates, rollback, and alias races.
6. Every allow and denial must enter the RVM witness trail before a resolver or
   retrieval backend is called.
7. The 64-byte RVM witness ring is bounded. A durable context audit story must
   seal ranges into signed receipts before the ring wraps.

The current RVF segment registry has suitable `PROFILE` (`0x0B`) and `WITNESS`
(`0x0A`) segment types, but no ratified generic context, tree, or representation
wire discriminants. RVM must not invent private segment numbers that canonical
RVF readers do not understand. The RVF root also contains a one-byte
`profile_id` used by existing hardware and domain profiles, so assigning a new
root profile number in this repository would create a cross-repository
collision risk.

## Decision

RVM adds a `no_std`, safe-Rust crate named `rvm-context`. It defines a strict
`ruv://` name, a versioned context profile carried inside the existing RVF
`PROFILE` segment, capability-scoped operations, a bounded in-memory reference
resolver, immutable RVF revisions, compare-and-swap aliases, progressive
representations, explicit execution permits, and signed epoch receipts.

`ruv://` is a logical identifier, not a transport protocol and not a public URI
scheme registration. Network discovery, federation, persistent resolver
storage, and IANA registration are outside this decision. ADR-158 specifies the
hosted durable adapter without changing this core contract.

## Specification

The version 1 contract has five load-bearing invariants:

1. One byte string has at most one namespace interpretation; the parser never
   repairs or normalizes noncanonical input.
2. A URI is a name only. Live RVM capability state and a trusted context grant
   are the authority.
3. Immutable identity is SHA-256 over the complete RVF bytes. A mutable alias
   is an explicit, generation-bearing pointer to that identity.
4. Authorization and its witness record precede every resolver call, including
   search candidate enumeration.
5. Reading and executing are independent operations. Execution requires an
   immutable target and explicit `EXECUTE` authority.

### 1. Canonical URI Grammar

The version 1 grammar is:

```text
ruv-uri = "ruv://" authority "/" tenant "/" subject-kind "/"
          subject-id "/" collection [ "/" path ] [ "?" query ]

subject-kind = "agent" | "user" | "service" | "team"
collection   = "memory" | "resources" | "skills"
path         = path-segment *( "/" path-segment )
query        = revision
             | view
             | revision "&" view
revision     = "rev=sha256:" 64-lowercase-hex
view         = "view=abstract" | "view=overview" | "view=content"
```

Example alias:

```text
ruv://context.cognitum.one/acme/agent/researcher/skills/web-search?view=overview
```

Example immutable citation:

```text
ruv://context.cognitum.one/acme/agent/researcher/skills/web-search?rev=sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa&view=overview
```

Canonicalization is deliberately strict rather than corrective:

| Component | Rule |
|---|---|
| Scheme | Exactly lowercase `ruv://` |
| Authority | Lowercase ASCII DNS form, 1 through 253 bytes; labels are 1 through 63 bytes, start and end with `[a-z0-9]`, and may contain interior `-` |
| Tenant and subject ID | Lowercase ASCII slug, 1 through 63 bytes, start and end with `[a-z0-9]`, interior characters `[a-z0-9-]` |
| Subject kind | Exactly `agent`, `user`, `service`, or `team` |
| Collection | Exactly `memory`, `resources`, or `skills` |
| Path | 1 through 32 optional segments; each segment is 1 through 128 bytes from ASCII unreserved `[A-Za-z0-9._~-]`; case is preserved; joined path is at most 1,024 bytes including separators |
| Revision | Exactly `sha256:` followed by 64 lowercase hexadecimal characters; it is the SHA-256 identity of the complete RVF byte stream |
| View | `abstract`, `overview`, or `content` |
| Query ordering | `rev` precedes `view`; no other ordering is canonical |
| Total length | At most 2,048 bytes |

The parser rejects non-ASCII input, percent encoding, fragments, credentials,
ports, empty or trailing path segments, literal `.` and `..` segments, unknown
or duplicate query parameters, empty keys or values, uppercase structural
tokens, uppercase revision hex, and `view` before `rev`. Rejection of every
percent sign prevents encoded separators, double decoding, encoded NUL, and
normalization disagreement from entering the namespace.

The same valid string always parses to the same typed `RuvUri`, and serializing
that value reproduces the same canonical string. Callers do not receive a
"mostly equivalent" normalized name.

### 2. Names and Authority Are Separate

A `RuvUri` contains no token, credential, secret, or grant. Authority is
carried out of band by an `AuthorizedRequest`, which references a
kernel-resident context capability and a context grant.

A grant binds all of the following:

1. Exact authority.
2. Exact tenant.
3. Exact subject kind and subject ID.
4. Exact collection.
5. A path-segment prefix, not a raw string prefix.
6. The allowed progressive views.
7. The RVM rights and revocation state represented by the capability.

This creates a new `CapType::Context`. A grant is narrower than its parent and
cannot infer authority from a URI. Context grant tables are const-bounded, as
are resolver object and alias tables, so worst-case memory use remains explicit
in `no_std` deployments.

The operation-to-rights mapping is total and default-deny:

| Context operation | Required RVM rights |
|---|---|
| Resolve, List, Tree, Read, Search, History | `READ` |
| Verify | `READ | PROVE` |
| Put, CompareAndSwapAlias, Forget | `WRITE` |
| Execute | `EXECUTE` |
| Grant | `GRANT` |
| Revoke | `REVOKE` |
| SealReceipt | `PROVE` |

`Execute` intentionally does not imply `READ`, and `READ` does not imply
`EXECUTE`. A runtime can authorize execution of a pinned artifact without
disclosing its content bytes, while an inspector can read a skill without
obtaining permission to run it.

Every allow or denial is appended to the RVM witness trail before the runtime
calls `ContextResolver`. In particular, `Search` authorizes the complete scope
before candidate enumeration. An unauthorized caller therefore cannot use
result counts, candidate identifiers, or backend-specific errors as an
existence oracle.

### 3. Immutable Revisions and Mutable Aliases

The `rev` value is the SHA-256 digest of the complete RVF byte stream. A URI
with `rev` is a `PinnedRuvUri`. Pinned references are required for `Put`,
`Execute`, receipts, durable citations, and mutation parents. Registered bytes
under a pinned revision are never overwritten.

A URI without `rev` is a mutable alias. Resolution returns both the current
revision and an `AliasGeneration`. Alias mutation uses compare-and-swap against
the complete prior `AliasSnapshot`, including its revision and generation:

```text
compare_and_swap(alias, expected_snapshot, new_revision):
    require WRITE on alias scope
    require alias has no rev
    witness authorization decision
    current = resolver.read_alias(alias)
    if current != expected_snapshot:
        return Conflict
    next_generation = checked_add(current.generation, 1)
    resolver.replace_alias(alias, new_revision, next_generation)
```

The first alias generation is 1. Checked generation increment rejects wrap.
Comparing generation and revision prevents an ABA sequence from making a stale
snapshot look current. Two writers racing from the same snapshot can produce
at most one winner.

`Forget` does not rewrite a pinned object. It appends a domain-separated
tombstone object as a new immutable revision and compare-and-swap advances the
versionless alias to that revision. Subsequent alias resolution reports the
tombstone. Cryptographic erasure of payload keys, removal from replicas, and
purging derived indexes are storage-adapter responsibilities and remain release
gates for a production multi-tenant service.

### 4. RVF Context Profile Without a Format Fork

The context contract reuses canonical RVF v1 segment discriminants:

| Existing RVF segment | Context use |
|---|---|
| `PROFILE` (`0x0B`) | Carries the versioned `ContextProfile` descriptor |
| `VEC` and `INDEX` | Rebuildable semantic retrieval material |
| Existing data segments | Hold bytes selected by profile view references; `rvm-context` treats them as inert data |
| `META` | Optional non-authoritative labels and provenance hints |
| `WITNESS` (`0x0A`) | Canonical 73-byte entries committing signed receipt sidecars |
| `MANIFEST` | Canonical RVF segment inventory and root state |
| `CRYPTO` | RVF trust material where supplied by the producer |

No `CONTENT`, `TREE`, `REPRESENTATION`, or private context segment number is
added by this ADR. No new value is written into the root `profile_id` byte.
That keeps ordinary RVF readers forward-compatible and avoids creating an RVM
fork of the canonical registry.

`ContextProfile` has its own payload magic and version inside `PROFILE`. It
describes progressive views by segment ordinal and payload digest. The profile
does not duplicate a whole-file identity field: `VerifiedContextProfile` binds
the decoded profile to the caller-supplied expected revision and to the full
RVF identity in a passing `rvm-rvf` report. `DerivedView` provenance binds a
derived representation to its source digest, generator identity, model
identity, prompt digest, and policy digest. A generated abstract or overview
therefore cannot silently replace source content or be reused under a
different generation policy.

Profile verification follows this order:

```text
verify_profile(rvf_bytes, claimed_revision):
    reject len(rvf_bytes) > MAX_RVF_BYTES
    report = rvm_rvf.verify(rvf_bytes, expected_identity = claimed_revision)
    require report has no failed check
    locate exactly one supported ContextProfile in a PROFILE segment
    parse only inert profile bytes
    bind profile to claimed_revision == report.rvf_identity == sha256(rvf_bytes)
    apply TrustedSignature or PinnedIdentity trust posture explicitly
    verify each declared view reference and digest
    return VerifiedContextProfile(profile, report.rvf_identity)
```

Exactly one unencrypted, uncompressed `PROFILE` segment is accepted. The
profile must contain one `content` view and may contain one `abstract` and one
`overview` view. Referenced view segments are unique and uncompressed;
non-content derived views cannot reference executable segments. Under
`TrustedSignature`, the profile segment must have a passing trusted Ed25519
signature check in the verification report. Under `PinnedIdentity`, an
unsigned profile is acceptable only because the complete RVF identity was
authenticated out of band and supplied as the expected revision. The trust
posture is always explicit.

The current reference ceiling is `MAX_RVF_BYTES = 16 MiB`. This is a context
ingress bound, not a new RVF wire-format maximum. Larger artifacts require a
different deployment policy or a future streaming profile.

The pinned complete-file identity is the reliable cross-repository integrity
binding. A signature proves publisher identity, not content safety, and the
presence of a signed executable never bypasses an RVM execution check.

### 5. Progressive Views

Version 1 exposes three semantic views:

| View | Intended use |
|---|---|
| `abstract` | Small routing summary used to decide whether the object is relevant |
| `overview` | Structured navigation context, relationships, and a fuller summary |
| `content` | The selected source or full representation referenced by the profile |

These are semantic representations, not mutable sibling files and not three
hard-coded storage tiers. Each view is independently capability-scoped. A grant
may allow `abstract` while denying `content`.

When no `view` is present, version 1 uses the operation's least documented
representation: Resolve, List, Tree, History, and Verify require manifest
metadata; Read requires content; Search requires overview. Mutation,
execution, delegation, revocation, and receipt sealing accept no view selector.

The resolver does not rank or generate representations. Context compilers
produce them, RVF binds them, RuVector or another authorized backend retrieves
them, and RVM decides whether the requested view may be observed or executed.

## Architecture

The implementation divides responsibility so no storage or retrieval adapter
can accidentally become the policy authority:

| Component | Owns | Does not own |
|---|---|---|
| `RuvUri` and typed components | Strict parsing, canonical formatting, pinned-versus-alias shape | Credentials, network transport, discovery |
| `ContextGrantTable` | Trusted binding from live Context capabilities to exact scopes and views | Artifact storage or ranking |
| `ContextRuntime` | Immutable authenticated actor, trusted clock, receipt-chain cursor, operation-to-rights mapping, request-shape rules, authorize/witness/call ordering | RVF parsing or backend enumeration |
| `ContextResolver` | Immutable objects, alias snapshots and CAS, history, scoped retrieval | Capability decisions or execution |
| `VerifiedContextProfile` | Full-RVF identity and progressive-view integrity binding | Publisher trust beyond the selected posture, semantic safety |
| Epoch receipt bridge | Contiguous RVM range commitments, signatures, RVF witness entry | A second runtime audit truth or automatic durable storage |

### 6. Resolver and Runtime Boundaries

`ContextResolver` owns immutable registration, alias lookup, scoped listing,
history, and candidate retrieval. The reference implementation is
`MemoryResolver<MAX_OBJECTS, MAX_ALIASES>`. It is deterministic and bounded,
but is not presented as durable or distributed storage.

`ContextRuntime` owns ordering:

```text
handle(request):
    actor = runtime.authenticated_actor
    observed_time = runtime.trusted_clock.next()
    uri = parse_canonical(request.uri)
    operation = request.operation
    capability = grant_table.lookup(request.capability_handle)
    decision = authorize(capability, uri, operation, requested_view)
    witness(decision, uri_commitment, operation)
    if decision is Deny:
        return AccessDenied

    if operation is Search:
        require request.limit <= MAX_SEARCH_RESULTS

    return resolver.perform(operation, uri)
```

Runtime construction is the trusted kernel-dispatch boundary. The actor is
authenticated out of band and bound immutably for the runtime's lifetime; its
clock is likewise runtime-owned. An untrusted `ContextRequest` contains only a
capability handle, operation, and canonical target. It cannot select an actor
or witness timestamp, and neither has a request-facing setter. Authorization,
witness actor fields, delegation callers, and execution permits all use the
runtime-bound actor.

`MAX_SEARCH_RESULTS` is 64. The limit applies before allocation and before the
resolver call. Resolver errors do not widen authority. API layers should map
forbidden and hidden-object outcomes to the same externally observable class
unless the caller has audit authority.

`Put` requires a pinned URI and a verified profile whose full RVF identity
equals the revision. Compare-and-swap and Forget require a versionless alias.
`Execute` requires a pinned URI and returns an `ExecutionPermit`; it does not
execute bytes inside the resolver. The existing RVF verify-before-load and RVM
launch boundaries remain responsible for actual execution.

### 7. Witnessing and Epoch Receipts

The governed namespace uses the `0xC0` through `0xCF` witness subsystem:

| Action kind | Meaning |
|---|---|
| `ContextResolve` (`0xC0`) | Resolve, list, tree, history, or verify authorization |
| `ContextRead` (`0xC1`) | Progressive view read authorization |
| `ContextSearch` (`0xC2`) | Search authorization before enumeration |
| `ContextPut` (`0xC3`) | Immutable registration authorization |
| `ContextAliasUpdate` (`0xC4`) | Compare-and-swap authorization |
| `ContextForget` (`0xC5`) | Tombstone-and-advance authorization |
| `ContextExecute` (`0xC6`) | Execution-permit authorization |
| `ContextEpochSeal` (`0xC7`) | Signed receipt commitment for a witness range |

Witness records contain commitments, stable discriminants, and bounded
coordinates, not context plaintext, query text, credentials, or personal data.
Allowed requests use the operation action above. Denials use the existing
`ProofRejected` action with the requested operation in the flags field. Both
are evidence and are recorded before returning or calling the resolver.

The ring retention horizon is `N / event_rate` seconds for
`WitnessLog<N>`. The `rvm-witness` library constant
`DEFAULT_RING_CAPACITY = 262,144` is 16 MiB at 64 bytes per record and wraps in
approximately 262 seconds at 1,000 events per second. The current integrated
`rvm-kernel` log uses `WitnessLog<256>`, which wraps in approximately 0.256
seconds at the same rate. A deployment must size and drain the actual `N`; the
library default is not a service guarantee.

`ContextEpochReceipt` binds a runtime-derived epoch ID; first and last sequence;
record count; minimum and maximum observed timestamps; the full RVM chain hash
immediately before the range; previous signed-receipt ID; namespace root; full
RVF identity; policy hash; optional encrypted-detail root; and a SHA-256 Merkle
root of the canonical 64-byte RVM records. A `WitnessSigner` signs a
domain-separated digest that also binds its 32-byte signer ID. The canonical
signed encoding is 352 bytes and carries a 64-byte signature. Sealing also
returns the next checkpoint captured under the same witness-log lock as the
snapshot, preventing a concurrent append from falling between epochs.

The public runtime owns a `ReceiptChainState` containing the exact next
checkpoint, next epoch ID, and previous signed-receipt ID. Genesis is fixed to
epoch 0, sequence 0, zero initial chain hash, and a zero previous-receipt link.
`seal_epoch` derives all three coordinates from that state; request payloads
cannot provide them. The state advances only after the receipt is signed and
its signature verifies, and must be persisted atomically with the durable
receipt. Recovery uses the explicit `trusted_resume` administrative boundary
after authenticating persisted state.

The full signed receipt is retained as durable sidecar evidence. Its canonical
73-byte RVF witness entry contains the preceding entry hash, a SHAKE-256
commitment to the signed receipt, the maximum observed timestamp, and the
existing RVF computation-witness type. This entry is stored in the existing
RVF `WITNESS` segment; no new segment discriminant is needed.
`ContextEpochSeal` is emitted only through an authenticated receipt typestate
into the next RVM epoch, so the receipt never claims to cover its own seal. Its
recorded tier is the actual P1 authorization; signature verification alone is
not mislabeled as P2 policy assurance. Sealing refuses an empty,
discontinuous, corrupt, partially
overwritten, already wrapped, or larger-than-262,144-record range. Merkle
construction reduces one leaf vector in place, bounding its largest permitted
leaf allocation at 8 MiB.

Sequence and chain coordinates are the ordering authority. Timestamps are
non-authoritative observed metadata, so a backwards or extreme observation
does not make a valid range unsealable; the receipt commits the recomputed
minimum and maximum as defense in depth. Offline verified typestate checks
genesis or an exact successor: signed-receipt link, checked epoch increment,
exact sequence adjacency, and the full chain hash obtained by applying
`rvm_witness::compute_chain_hash` across every sequence of the prior receipt.

The bridge preserves assurance honesty:

1. RVM records remain the runtime decision log.
2. The RVF receipt is durable sidecar evidence over a specific RVM range.
3. Anchoring does not upgrade service-side evidence to hardware-backed
   evidence.
4. Verification recomputes the sequence, RVM chain, Merkle root, signer
   identity, and signature offline.
5. A seal must complete before the covered records are overwritten.

High-volume search traces should commit one bounded trajectory or epoch rather
than emit one kernel record per vector candidate. Authorization decisions
remain individually witnessed; the receipt's namespace and detail roots bind
post-operation state and any separately retained encrypted trajectory detail.

### 8. Threat Model

| Threat | Control in this decision | Residual risk |
|---|---|---|
| Traversal, encoded separators, Unicode ambiguity, parser differentials | ASCII-only strict parser; all percent encoding, dot segments, fragments, credentials, and non-canonical query order rejected | Future Unicode or URL-library adapters require separate conformance work |
| Cross-tenant search leakage | Capability scope checked and witnessed before resolver call or candidate enumeration | A backend that bypasses `ContextRuntime` is non-conforming |
| Actor or timestamp spoofing in requests | Actor and clock are immutable/runtime-owned trusted dispatch state; request payload contains only handle, operation, and target | Trusted kernel or host construction must authenticate the actor and clock source |
| URI used as a bearer credential | No credentials in URI; capability handle and grant are out of band | Application logs must still protect URI-derived business identifiers |
| Mutable alias race or rollback | Full-snapshot CAS, generation starts at 1, checked increment, immutable revisions | Distributed persistence must provide linearizable CAS |
| Hash or segment substitution | Revision is full RVF SHA-256; verified profile is paired with that report identity; per-view digests verified | SHA-256 is fixed for contract v1 and requires a versioned migration to change |
| Signed malicious skill | Inspection and read do not execute; `Execute` requires a pinned URI and `EXECUTE` capability | RVM constrains authority, but cannot establish semantic truth or remove prompt injection |
| Grant confused across scopes | Exact structured fields and segment-prefix comparison | Incorrect grant issuance remains an operator risk |
| Search amplification or memory exhaustion | Const-bounded tables, URI and path limits, 64-result top-K buffer, linear-time matcher, 16 MiB context RVF ceiling | Persistent adapters need quotas, rate limits, and admission control |
| Audit loss on ring wrap | Signed contiguous epoch receipts sealed before overwrite | Drainer outage can exhaust the retention window; production needs backpressure |
| Personal data retained by immutable history | Tombstone alias and digest-only witnesses | Key destruction, replica purge, backup retention, and derived-index deletion are not implemented by the reference resolver |
| Existence leakage through errors | Deny before resolver and recommend uniform external errors | Timing isolation across shared physical infrastructure requires service-level testing |
| Receipt replay, truncation, or partial ring snapshot | Runtime-owned chain state, verified genesis/successor checks, domain separation, explicit range coordinates, previous-receipt link, chain and Merkle commitments, signer verification, fail-closed wrap detection | Durable receipt ordering across multiple hosts is future federation work |

### 9. Reference Limits

| Limit | Value | Reason |
|---|---:|---|
| URI bytes | 2,048 | Bounds parser work and log-safe identifiers |
| Authority bytes | 253 | DNS maximum textual length |
| Authority label bytes | 63 | DNS label maximum |
| Tenant or subject slug bytes | 63 | Fixed operational identifier bound |
| Path segments | 32 | Bounds prefix checks and resolver traversal |
| Path segment bytes | 128 | Bounds per-component work |
| Joined path bytes | 1,024 | Bounds canonical URI storage |
| Search results | 64 | Prevents unbounded result allocation and enumeration |
| Search query bytes | 4,096 | Bounds the reference conformance scan; hosted adapters may tighten it |
| Context RVF bytes | 16 MiB | Reference in-memory verifier ceiling |
| Progressive views per profile | At most 3 | At most one each of abstract, overview, and content; content is required |
| Reference resolver objects | 64 by default | Const-generic `MemoryResolver` object capacity |
| Reference resolver aliases | 64 by default | Const-generic `MemoryResolver` alias capacity |
| `rvm-witness` library default records | 262,144 | 16 MiB reference ring; actual `WitnessLog<N>` may differ |
| Context epoch receipt records | 262,144 | Bounds direct sealing and in-place Merkle leaf allocation to 8 MiB |
| Current integrated `rvm-kernel` records | 256 | Existing kernel choice; requires a correspondingly shorter drain interval |

Persistent or hosted adapters may tighten these limits. They must not silently
widen them for a contract-v1 request.

## Pseudocode Summary

### Resolve or read

```text
resolve(request):
    uri = parse(request.uri)
    require request.operation in {Resolve, List, Tree, Read, Search, History}
    grant = grants.lookup(request.capability_handle)
    decision = grant.authorize(uri, READ, uri.view)
    witness_before_resolver(decision)
    require decision == Allow

    pinned = if uri.rev exists:
        resolver.resolve_pinned(uri)
    else:
        snapshot = resolver.resolve_alias(uri)
        uri.with_revision(snapshot.revision)

    require resolved RVF identity == pinned.rev
    return pinned result
```

### Put and alias advance

```text
put_and_advance(pinned_uri, rvf, alias, expected):
    require pinned_uri.rev exists
    authorize_and_witness(WRITE, pinned_uri)
    profile = verify_profile(rvf, pinned_uri.rev)
    resolver.put_immutable(pinned_uri, profile)

    require alias.rev is absent
    authorize_and_witness(WRITE, alias)
    resolver.compare_and_swap(alias, expected, pinned_uri.rev)
```

The immutable put and alias CAS are separate observable operations. If CAS
loses a race, the new pinned object remains valid but is not the alias head.
Garbage collection of unreachable immutable objects is a storage policy, not a
namespace mutation.

### Execute

```text
permit_execution(request):
    uri = parse(request.uri)
    require uri.rev exists
    authorize_and_witness(EXECUTE, uri)
    resolved = resolver.resolve_pinned(uri)
    require resolved.profile is verified
    return ExecutionPermit(uri, resolved.rvf_identity, capability_commitment)
```

Producing `ExecutionPermit` still does not map or invoke an executable segment.
The RVF loader and launch path consume the permit under ADR-155.

## Requirements-to-Evidence Matrix

This matrix defines planned acceptance evidence. It does not assert that the
commands or tests have passed in this proposal.

| Requirement | Planned automated evidence | Release evidence |
|---|---|---|
| Canonical valid URIs round-trip exactly | URI table tests and parse-format-parse property test | Cross-language conformance vectors |
| Hostile bytes never panic or become a second name | Property test over arbitrary byte strings; explicit percent, NUL, dot-segment, duplicate-query, and case vectors | One million randomized parser cases with zero acceptance ambiguity |
| Full RVF identity is the revision | One-bit RVF tamper and claimed-revision mismatch tests | Independent host resolves same pinned URI to same digest |
| Pinned bytes are immutable | Duplicate put with different profile or bytes is refused | Store replay shows no overwrite for an existing revision |
| Alias updates are atomic and ABA-safe | Stale snapshot, generation mismatch, simulated two-writer, and generation-wrap tests | Linearizability test against persistent adapter |
| URI never grants access | Missing, wrong-type, revoked, expired, cross-tenant, cross-subject, wrong-prefix, and wrong-view grant tests | Mixed-scope red-team run with zero unauthorized success |
| Authorization precedes enumeration | Spy resolver asserts zero calls after denied Search, List, Tree, and History | Backend traces show no candidate enumeration on denial |
| Operation mapping is total | Exhaustive operation-to-rights tests | API conformance report |
| Read and execute are independent | READ-only skill can be inspected but not executed; EXECUTE-only request yields a permit without content disclosure | Malicious-skill scenario cannot execute under READ grant |
| Derived views bind provenance | Tamper source, generator, model, prompt, and policy fields independently | Offline verifier reproduces view commitment |
| Every allow and denial is witnessed first | Sequence and spy-resolver ordering tests for each operation | Witness query correlates all request outcomes |
| Receipt covers an exact contiguous range | Round-trip, wrong range, chain tamper, Merkle tamper, signer mismatch, signature tamper, truncation, and wrap-refusal tests | Offline receipt plus full record-range verification after ring drain |
| Tombstone does not overwrite pinned bytes | Forget creates new revision; stale CAS and pinned historic lookup tests | Storage erasure and derived-index purge report |
| Resource limits fail closed | Boundary tests for every table in section 9 | Load test records bounded memory and result count |
| No RVF wire discriminant fork | Fixture uses canonical `PROFILE` and `WITNESS` types and rejects unknown context profile version | RuVector reader preserves the artifact byte-for-byte |
| `no_std`, safe Rust, and MSRV remain valid | `cargo check -p rvm-context --no-default-features`, clippy, unsafe-code lint, and Rust 1.77 build | CI artifacts attached to the release |

Planned workspace gates are:

```text
cargo fmt --all --check
cargo check --workspace --locked
cargo test --workspace --locked
cargo clippy --workspace --locked -- -D warnings
cargo clippy -p rvm-context --all-targets --locked -- -D warnings
cargo check --target aarch64-unknown-none -p rvm-context --no-default-features --locked
cargo +1.77.2 check -p rvm-context --all-features --locked
cargo audit
```

Benchmarks must measure canonical URI parsing, rejected maximum-length input,
authorization plus witness emission, pinned resolution, alias CAS, profile
verification, and receipt sealing. A same-host Criterion baseline is required;
the existing nightly script has no committed historical baseline and cannot by
itself establish that this change caused no regression.

## Rejected Alternatives

### Copy or embed OpenViking

Rejected. It would create license coupling and make RVM depend on another
project's storage, authentication, and execution assumptions. We adopt useful
patterns through an independent contract, not its code.

### Make the URI a capability

Rejected. URLs routinely enter logs, prompts, telemetry, and chat transcripts.
Embedding bearer authority would turn ordinary context sharing into credential
leakage and make revocation difficult.

### Authorize after vector search

Rejected. Post-filtering can leak candidate existence, timing, counts, and
shared-index structure. The backend must not observe an unauthorized query.

### Treat every name as mutable

Rejected. Reproducible citations, receipts, checkpoints, and execution permits
need stable bytes. Mutable aliases exist only as explicit pointers to immutable
revisions.

### Update aliases with last-write-wins

Rejected. It loses concurrent writes and permits rollback and ABA errors. Full
snapshot compare-and-swap provides a deterministic conflict.

### Make READ imply EXECUTE

Rejected. Context is untrusted input. Inspection must remain safe, and a signed
skill proves publisher identity rather than safety.

### Add private RVF segment types

Rejected. New discriminants in RVM alone would fork the canonical RVF format.
The context profile is versioned inside the existing `PROFILE` payload, and
receipts use the existing `WITNESS` segment.

### Put the context profile in the RVF root `profile_id`

Rejected. Existing hardware and domain profile enums share that byte. A new
value requires cross-repository format governance, not a unilateral RVM change.

### Write one RVF witness entry per candidate

Rejected. Audit volume would scale with internal retrieval work and exhaust the
RVM ring rapidly. RVM witnesses decisions and mutations, then seals bounded
detail into epoch receipts.

### Accept general URL normalization

Rejected. Percent decoding, Unicode normalization, default ports, and query
reordering vary across libraries. Contract v1 uses a strict ASCII language and
rejects all alternative spellings.

## Rollout

### Phase 1: Reference contract

Land `rvm-context`, its in-memory resolver, profile verifier, capability and
witness bindings, epoch receipt types, conformance vectors, and this ADR. Keep
the ADR Proposed while interoperability evidence is collected.

### Phase 2: Hosted integration

ADR-158 implements an authorized, physically sharded RuVector adapter and a
canonical RVF context compiler. Denied searches have zero backend touches. Its
HTTPS gateway and MCP/CLI surfaces preserve canonical URIs unchanged. Hosted
isolation remains operating-system sandbox plus WASM, not bare-metal partition
assurance.

### Phase 3: Durable service

ADR-158 adds a linearizable REDB alias store, per-object envelope encryption
behind a KMS provider boundary, transactional receipt draining with
backpressure, replica/cache purge outboxes, exact-scope tenant indexes,
recovery tests, quotas, and service-level timing baselines. Production
deployments must supply the concrete KMS and purge adapters for their own
infrastructure.

### Phase 4: Interoperability and registration

Publish language-neutral conformance vectors and independent implementations.
Only after durable cross-vendor use exists should the project consider an IANA
provisional URI scheme registration. Until then, `ruv://` remains an
experimental rUv ecosystem identifier with HTTPS as the network transport.

### Rollback

Disable external resolver and alias-write surfaces, revoke their Context
capabilities, and retain pinned RVFs plus signed receipts for audit. Because
version 1 adds no RVF segment discriminant or root profile ID, ordinary RVF
readers can preserve the artifacts while ignoring the versioned profile
payload. A rollback never rewrites a pinned revision or reuses an alias
generation. Re-enabling the feature starts from the last valid alias snapshots
or from explicitly reconstructed aliases under a new witnessed policy epoch.

## Consequences

### Positive

1. A context citation can bind exact RVF bytes across hosts.
2. Human-friendly aliases remain available without weakening immutable
   references.
3. Cross-tenant authorization is centralized and testable before retrieval.
4. Skills can be inspected without creating an execution surface.
5. Progressive views reduce disclosure and token use while retaining explicit
   provenance.
6. Audit volume has a bounded path from runtime records to durable RVF
   receipts.
7. The implementation does not fork RVF's segment registry or copy AGPL code.

### Negative

1. Contract v1 is intentionally strict and ASCII-only.
2. SHA-256 is fixed in the URI revision syntax for version 1; algorithm
   agility needs a future contract version.
3. Compare-and-swap makes concurrent alias conflicts visible to callers.
4. A 16 MiB in-memory RVF ceiling excludes large context artifacts until a
   streaming profile is specified.
5. Every decision adds witness pressure, so production deployment requires a
   receipt drainer and backpressure.
6. The reference resolver is neither persistent nor distributed.

### Residual Risks

1. This contract governs authority and integrity, not semantic truth. Prompt
   injection and poisoned memories remain application risks.
2. A capability issuer can still grant an overly broad scope.
3. Cryptographic erasure, replicas, backups, caches, and derived indexes are
   not solved by an alias tombstone alone.
4. Service-level timing may reveal shared-infrastructure load even when result
   errors are uniform.
5. RVF manifest-signature enforcement is not uniform across every current
   reader. Pinned full-file identity is therefore the required integrity
   binding; deployments must not claim stronger publisher authentication than
   they actually verify.
6. An RVM-only implementation would risk ecosystem fragmentation. MCP, HTTPS,
   public vectors, and independent implementations are needed before the
   namespace is a broadly useful protocol.

## Planned Acceptance

The ADR may move from Proposed to Accepted only when two independent hosts can
resolve the same pinned `ruv://` URI to the same RVF and view digests; one-bit
tampering is refused; a denied search invokes no retrieval backend; READ can
inspect but cannot execute a malicious skill; EXECUTE returns a permit only for
a pinned revision; two writers racing one alias snapshot produce exactly one
winner; a tombstone advances the alias without changing historic pinned bytes;
and a signed epoch receipt verifies offline after its RVM witness range has
been drained.
