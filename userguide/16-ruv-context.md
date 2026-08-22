# Governed `ruv://` Context

RVM uses `ruv://` to name agent resources, memories, and skills without making
the name itself a credential. A canonical URI identifies context. A separate
RVM capability decides whether a caller may resolve, inspect, search, mutate,
prove, or execute it.

This chapter explains the version 1 namespace defined by
[ADR-157](../docs/adr/ADR-157-ruv-context-namespace.md). For the underlying
capability model, read [Capabilities and Proofs](05-capabilities-proofs.md).
For the hot audit trail, read [Witness and Audit](06-witness-audit.md).

---

## 1. Mental Model

A context object has two useful names:

| Name | Example | Meaning |
|---|---|---|
| Versionless alias | `ruv://context.example/acme/agent/researcher/skills/web-search` | A mutable pointer intended for discovery and human workflows |
| Pinned URI | The same path with `?rev=sha256:<64 lowercase hex>` | An immutable citation to the SHA-256 identity of the complete RVF byte stream |

Aliases provide friendly names. Pinned URIs provide reproducibility. An alias
can advance only through compare-and-swap (CAS), while bytes registered under a
pinned revision are never overwritten.

The namespace is not a filesystem mount, a network transport, or an ambient
authority system. In particular:

- parsing a URI grants no rights;
- resolving a skill does not execute it;
- a signed artifact is not automatically safe content;
- `ruv://` does not define how bytes move between hosts; and
- the reference `MemoryResolver` is bounded in-memory state, not a durable or
  distributed database.

---

## 2. Canonical URI Contract

The only accepted version 1 form is:

```text
ruv://authority/tenant/subject-kind/subject-id/collection[/path...][?query]
```

The structural choices are fixed:

| Component | Accepted values |
|---|---|
| `subject-kind` | `agent`, `user`, `service`, `team` |
| `collection` | `memory`, `resources`, `skills` |
| `view` | `abstract`, `overview`, `content` |
| `rev` | `sha256:` followed by exactly 64 lowercase hexadecimal characters |
| Query | absent, `rev` only, `view` only, or canonical `rev&view` |

Examples:

```text
# Collection root
ruv://context.example/acme/team/platform/resources

# Versionless alias with a progressive view
ruv://context.example/acme/agent/researcher/memory/project-orion?view=abstract

# Immutable content citation
ruv://context.example/acme/agent/researcher/skills/web-search?rev=sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa&view=content
```

The parser is intentionally strict. It does not normalize alternative URL
spellings:

| Limit | Contract |
|---|---|
| Complete URI | At most 2,048 ASCII bytes |
| Authority | Lowercase DNS form, at most 253 bytes; labels at most 63 bytes |
| Tenant and subject ID | Lowercase slugs, 1 through 63 bytes |
| Optional path | At most 32 segments and 1,024 joined bytes |
| Path segment | 1 through 128 ASCII unreserved characters `[A-Za-z0-9._~-]` |

Any non-ASCII byte, percent sign, fragment, authority credential or port,
empty segment, trailing slash, `.` or `..` segment, duplicate or unknown query
key, empty query value, noncanonical case, or `view` before `rev` is rejected.
Path case is preserved; structural tokens, authorities, slugs, and revision hex
must use the case specified above.

Use the typed parser instead of a general-purpose URL normalizer:

```rust
use rvm_context::{PinnedRuvUri, RuvUri, UriError};

fn parse_names() -> Result<(), UriError> {
    let alias = RuvUri::parse(
        "ruv://context.example/acme/agent/researcher/skills/web-search?view=overview",
    )?;
    assert!(!alias.is_pinned());

    let pinned: PinnedRuvUri = concat!(
        "ruv://context.example/acme/agent/researcher/skills/web-search",
        "?rev=sha256:",
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        "&view=content",
    )
    .parse()?;
    assert_eq!(pinned.to_string(), pinned.as_uri().to_string());
    Ok(())
}
```

In a `no_std` caller, formatting to an owned string requires `alloc`; parsing
and typed inspection remain part of the `rvm-context` API.

---

## 3. Progressive Views

A context profile can expose three semantic representations:

| View | Typical use | Disclosure |
|---|---|---|
| `abstract` | Routing summary or relevance decision | Smallest |
| `overview` | Structure, relationships, and fuller summary | Intermediate |
| `content` | Source or full representation selected by the profile | Largest |

These are capability-scoped representations, not interchangeable filenames.
A grant may permit an abstract while denying the content. When a view is
derived, its provenance binds the source digest and generation inputs so that
changing the source, generator, model, prompt, or policy changes the derived
commitment.

If `view` is omitted, Resolve, List, Tree, History, and Verify require manifest
metadata; Read requires content; and Search requires overview. Mutation,
execution, delegation, revocation, and receipt sealing accept no view selector.
An adapter must not silently broaden a grant to a larger representation.

---

## 4. Capabilities Are Out of Band

An untrusted `ContextRequest` carries only a capability handle, operation, and
canonical `RuvUri`. It has no actor or timestamp field. `ContextRuntime`
construction is the trusted kernel-dispatch boundary: an authenticated
`PartitionId` is bound immutably to the runtime, and a runtime-owned
`ContextClock` stamps witness observations. There is no actor setter. The safe
default is a monotonic logical clock; trusted host code may inject a clock or
resume it explicitly.

After authorization, the runtime privately creates `AuthorizedRequest`.
`ContextScope` binds exact namespace fields, a path-segment prefix, and the
permitted manifest/progressive-view mask. A raw string prefix is never used for
path authorization: `team/a` cannot accidentally authorize `team/alpha`.

The rights mapping is total and default-deny:

| Operation | Required rights |
|---|---|
| Resolve, List, Tree, Read, Search, History | `READ` |
| Verify | `READ | PROVE` |
| Put, CompareAndSwapAlias, Forget | `WRITE` |
| Execute | `EXECUTE` |
| Grant | `GRANT` |
| Revoke | `REVOKE` |
| SealReceipt | `PROVE` |

`READ` and `EXECUTE` are independent. A reviewer can inspect a hostile skill
without being allowed to run it. Conversely, a narrowly controlled executor
can receive an execution permit for a pinned artifact without receiving its
content view.

Every authorization result, including a denial, is appended to the RVM
witness log before the resolver is called. Search, List, Tree, and History
therefore authorize the whole requested scope before candidate enumeration.
Do not build an adapter that searches a shared index first and filters results
afterward; that leaks existence, counts, timing, or index structure.

---

## 5. RVF Representation

The revision is SHA-256 over the complete RVF bytes. It is not a segment hash
or a digest of only the selected view. `rvm-rvf` verifies that full identity
before a pinned object can enter the context resolver. The `ContextProfile`
payload maps views to segment ordinals and digests; it does not serialize a
second whole-file identity. `VerifiedContextProfile` pairs the decoded profile
with the expected revision and a passing full-RVF verification report.

The profile and receipt design reuses canonical RVF version 1 segment types:

| RVF segment | Use by the context contract |
|---|---|
| `PROFILE` (`0x0B`) | Versioned `ContextProfile` payload and view bindings |
| Existing data segments | Inert bytes selected by profile references |
| `VEC` / `INDEX` | Rebuildable authorized retrieval material |
| `WITNESS` (`0x0A`) | Canonical witness entry committing a signed epoch receipt |
| `META`, `MANIFEST`, `CRYPTO` | Existing RVF metadata, inventory, and producer trust material |

No private context, content, tree, or representation segment discriminant is
introduced. The context profile has its own magic and version inside an
existing `PROFILE` payload; it does not allocate a new RVF root `profile_id`.
This avoids creating an RVM-only RVF format fork.

Exactly one unencrypted, uncompressed profile segment is accepted. Content is
required; abstract and overview are optional. View segment IDs must be unique,
the referenced bytes must be uncompressed and match their payload digest, and
a derived non-content view cannot point at executable bytes. Callers choose an
explicit trust posture: a passing trusted signature on the profile segment, or
a pinned whole-RVF identity authenticated out of band.

A valid publisher signature proves an identity statement under the verifier's
trust policy. It does not prove that memory content is true, that a prompt is
safe, or that executable behavior is benign. Pinned full-file identity and RVM
execution authority remain mandatory even when signatures are present.

---

## 6. Publish and Advance an Alias

Publishing is deliberately two-stage:

1. Build the RVF and its versioned context profile.
2. Compute SHA-256 over the complete, final RVF bytes.
3. Construct a pinned URI whose `rev` equals that digest.
4. Authorize `Put` with `WRITE`; the decision is witnessed.
5. Verify the RVF identity and profile, then register the immutable object.
6. Resolve the versionless alias to an `AliasSnapshot`.
7. Authorize `CompareAndSwapAlias` with `WRITE`; the decision is witnessed.
8. CAS the alias from the complete expected snapshot to the new revision.

The initial alias generation is 1. Every successful CAS uses checked
increment. The expected snapshot includes both revision and generation, so a
stale writer loses even if an alias moved away and later returned to the same
revision. Generation wrap fails instead of reusing an old value.

The immutable Put and the alias CAS are separate operations. If another writer
wins the alias race, the newly registered pinned object remains a valid
immutable object, but it is not the alias head. A storage adapter may later
garbage-collect unreachable objects under an explicit retention policy.

---

## 7. Resolve, Read, Search, and Execute

For every operation, the safe order is:

```text
parse canonical URI
    -> look up capability and context grant
    -> authorize exact scope, operation, and view
    -> append allow or denial witness
    -> on allow only: call ContextResolver
```

An alias resolution returns its pinned revision and generation snapshot. A
pinned resolution verifies that the registered full RVF identity equals the
URI revision. Search is capped at `MAX_SEARCH_RESULTS = 64` before resolver
allocation or enumeration, and the conformance resolver caps a query at 4,096
bytes. Context RVF input is capped at `MAX_RVF_BYTES = 16 MiB` by the reference
contract. `MemoryResolver` defaults to 64 immutable-object slots and 64 alias
slots; both capacities are const-generic. Its matcher is linear in candidate
bytes, and it retains only the globally ranked top K hits, so result storage is
bounded by the requested limit rather than the number of scanned aliases.

Execute is a separate path:

- it requires an `EXECUTE` grant;
- it requires a pinned URI;
- it returns an `ExecutionPermit`; and
- it does not itself map, load, or invoke executable bytes.

The verified RVF loader and RVM launch boundary consume that permit under the
existing verify-before-load contract. A versionless skill alias must first be
resolved and deliberately pinned; execution must never race a moving alias.

---

## 8. Forgetting and Retention

`Forget` applies to a versionless alias. It creates a domain-separated
tombstone as a new immutable revision, then CAS-advances the alias to the
tombstone. Historic pinned bytes are not rewritten.

This is namespace deletion, not complete data erasure. A production adapter
must separately implement any required key destruction and removal from
replicas, backups, caches, vector indexes, and derived representations. Those
storage actions need their own policy and evidence.

---

## 9. Epoch Receipts and Ring Wrap

The hot witness log is a const-generic ring. Its retention horizon is:

```text
seconds before wrap = ring record capacity / records emitted per second
```

`rvm_witness::DEFAULT_RING_CAPACITY` is 262,144 records, or 16 MiB at 64 bytes
per record. At 1,000 records per second it retains about 262 seconds. The
current integrated `rvm-kernel` log uses a smaller `WitnessLog<256>`, which at
the same rate retains only about 0.256 seconds. Deployments must size and drain
the actual `N`; the library constant is not a service guarantee.

`ContextRuntime::seal_epoch` snapshots a complete range after its owned
checkpoint. It fails if any requested record has already wrapped rather than
signing a partial range. The runtime owns `ReceiptChainState`, which contains
the exact next checkpoint, next epoch ID, and previous signed-receipt ID. The
request cannot choose any of those coordinates. Genesis is fixed to epoch 0,
sequence 0, zero initial chain hash, and a zero prior link. The state advances
only after the new receipt is signed and verified; persist the state atomically
with the durable signed receipt. `ReceiptChainState::trusted_resume` is an
explicit administrative recovery boundary and its inputs must first be
authenticated against durable storage.

The lower-level `ContextEpochReceipt::seal_from_log` returns a checkpoint
captured under the same witness-log lock. Runtime state uses that exact boundary
for the following epoch so a concurrent append cannot fall between receipts.
One receipt is limited to 262,144 records. Merkle construction reduces the
leaf vector in place, so the largest permitted epoch reserves at most 8 MiB
for 32-byte leaf hashes rather than allocating a second tree-sized buffer.
The unsigned receipt binds:

| Field group | Binding |
|---|---|
| Epoch coordinates | Epoch ID, first and last sequence, record count |
| Time | Minimum and maximum observed timestamps |
| RVM chain | Chain hash immediately before the first record and a Merkle root of canonical 64-byte records |
| Receipt continuity | SHA-256 ID of the previous signed receipt |
| State and policy | Namespace root, policy hash, optional encrypted-detail commitment |
| Content | Full RVF identity governing the epoch |

Signing adds a 32-byte signer ID and 64-byte signature over a domain-separated
digest. The fixed signed receipt is 352 bytes. `verify_records` recomputes the
sequence, timestamp bounds, RVM chain, and Merkle root; `verify` authenticates
the signer and signature. Sequence and chain coordinates define order;
timestamps are non-authoritative observations, so backwards or extreme values
do not prevent sealing. Verified typestate can require genesis or an exact
successor, including the receipt link, checked epoch increment, exact sequence
adjacency, and the full chain value derived across every prior sequence.

The full signed receipt must be retained as durable sidecar evidence. Its
canonical 73-byte RVF witness entry stores a chain link, a SHAKE-256 commitment
to the full receipt, the maximum observed timestamp, and the existing RVF
computation witness type. Signature verification produces a typed verified
receipt before either commitment operation is available. `emit_seal` records
the actual P1 runtime authorization and places the receipt ID and range
commitment in the next RVM epoch, so a receipt never claims to cover its own
seal record.

Drain and seal with margin. Once the first record of an unsealed range is
overwritten, the reference implementation refuses to manufacture a complete
receipt. Production services need alerting and backpressure before that point.

---

## 10. Security Checklist

Before exposing a resolver through a CLI, MCP server, or HTTP gateway:

- keep capability handles out of the URI and out of ordinary logs;
- parse with `RuvUri`, not a forgiving URL library;
- call the resolver only through the authorization-and-witness runtime path;
- give each tenant a structured scope, not a text-prefix filter;
- use uniform external errors for forbidden and hidden objects unless the
  caller has explicit audit authority;
- require pinned URIs for Put and Execute;
- enforce the 4,096-byte query, 64-result, and 16 MiB ceilings before
  allocation;
- treat retrieved context as hostile input;
- verify derived-view provenance before serving it;
- implement linearizable CAS in any distributed alias store; and
- drain receipts well before the configured witness ring can wrap.

The reference implementation establishes namespace, integrity, capability,
and evidence boundaries. It does not by itself provide network federation,
tenant-isolated persistent indexes, semantic truth, prompt-injection defense,
cryptographic erasure, or a production receipt drainer.

---

## 11. Planned Validation

Acceptance evidence for the initial implementation is defined in ADR-157 and
includes URI conformance and property tests, full-RVF tamper tests, denied
search spy-resolver tests, exhaustive operation-to-rights checks, alias race
and wrap tests, READ-versus-EXECUTE tests, profile provenance tampering, receipt
range/signature/tamper tests, and resource-boundary tests.

Performance baselines should cover canonical and rejected URI parsing,
authorization plus witness emission, pinned lookup, CAS, profile verification,
search at the 64-result ceiling, and receipt sealing across representative
epoch sizes. Compare same-host Criterion samples; do not infer a regression
from results collected on different machines.

---

## Further Reading

- [ADR-157: Capability-Governed `ruv://` Context Namespace](../docs/adr/ADR-157-ruv-context-namespace.md)
- [Capabilities and Proofs](05-capabilities-proofs.md)
- [Witness and Audit](06-witness-audit.md)
- [Security](10-security.md)
- [RVForge Execution Contract](../docs/adr/ADR-155-rvf-execution-contract.md)
- [External Receipt Anchoring](../docs/adr/ADR-156-external-receipt-anchoring.md)
- [Cross-Reference Index](cross-reference.md)
