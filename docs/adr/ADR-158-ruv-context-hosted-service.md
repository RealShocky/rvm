# ADR-158: Durable Hosted `ruv://` Context Service

**Status**: Proposed
**Date**: 2026-08-22
**Authors**: RVM Contributors
**Supersedes**: None
**Related**: ADR-155 (RVF Execution Contract), ADR-157 (`ruv://` Context
Namespace), RuVector ADR-332 (Tenant-Sharded Context Storage)

---

## Context

ADR-157 defines the capability, naming, immutable revision, progressive view,
execution-permit, and receipt contracts. Its bounded in-memory resolver is a
conformance reference, not a hosted multi-tenant service. A durable deployment
also needs linearizable aliases, encrypted object storage, retrieval isolation,
crash-replayable derived state, receipt persistence before witness-ring
advance, and network surfaces that cannot reinterpret canonical `ruv://`
identifiers.

RuVector already supplies vector storage and search primitives, but a shared
index followed by tenant filtering would violate ADR-157: an unauthorized
query could still enumerate another tenant's candidates. The integration must
make the authorized RVM scope the physical retrieval boundary.

## Decision

Add `rvm-context-service`, a safe-Rust hosted adapter over `rvm-context`, REDB,
and the upstream `ruvector-context` crate. The service has four trust layers:

| Layer | Authority and responsibility |
|---|---|
| RVM `ContextRuntime` | Capability authorization, scope/view checks, operation-to-rights mapping, and witness-before-backend ordering |
| REDB source of truth | Encrypted immutable RVFs, generation-bearing aliases, index/purge outboxes, signed receipts, and authenticated resume cursor |
| RuVector active index | Exact-scope physical shards containing only active alias heads; rebuildable from source-of-truth state |
| HTTPS/MCP adapters | Authentication, bounded parsing, uniform external errors, and byte-for-byte canonical URI dispatch |

The `rvm-context` contract retains the workspace Rust 1.77 MSRV and `no_std`
support. `rvm-context-service` declares Rust 1.85 because the upstream REDB
adapter requires it.

## Durable Mutation Model

The resolver stores complete RVF revisions as immutable encrypted objects. A
single REDB write transaction performs each source-of-truth mutation and
enqueues any derived work needed after commit:

1. `Put` verifies the full RVF identity/profile, encrypts with a fresh data
   key, and inserts only if that pinned URI does not already contain different
   bytes.
2. Alias compare-and-swap compares the complete revision and generation,
   checks generation increment, advances the alias, and enqueues an active
   index replacement.
3. `Forget` creates a tombstone revision, atomically advances the alias,
   removes encrypted historic payload envelopes for that logical alias,
   thereby discards their only wrapped data keys, and enqueues active-index
   erasure plus replica/cache purge.
4. Index and purge jobs remain durable until their sinks confirm success.
   Startup replays index jobs before the resolver becomes available; failed
   external purge work remains visible and retryable.

The REDB database is authoritative. RuVector is deliberately treated as
rebuildable derived state, so a crash cannot leave an alias transaction only
partially visible.

## Encryption and Erasure

Every immutable object receives an independent random AES-256-GCM data key.
The tenant and canonical pinned URI are authenticated as additional data, so a
ciphertext cannot be transplanted to a different tenant or name. Plaintext
data keys and temporary key material are zeroized.

`DataKeyProvider` is the deployment boundary for wrapping and unwrapping data
keys with an HSM or KMS. Cryptographic erasure discards the only wrapped DEK;
provider-level KEK retirement remains an operator action. `LocalKeyProvider`
exists for tests and local development only. The bundled gateway will not start with that provider
unless `RVM_CONTEXT_ALLOW_LOCAL_KEK=1` is explicitly set. A production binary
must inject a provider backed by its operator's KMS and a `PurgeSink` backed by
its actual replicas, backups, and caches; ADR-158 does not claim that a no-op
sink purges systems it cannot observe.

## RuVector Isolation

The upstream `ruvector-context` crate converts the authorized structured RVM
scope into an exact tenant/authority/subject/collection/path shard. Searches
open only that shard or a bounded set of descendant shards. They never search
a global index and post-filter results.

Alias changes remove the former active point and insert the new active view
through the durable index outbox. Stored vector manifests are bound to the
scope hash, vector dimensions and metric. Non-finite values, mismatched
dimensions, overlong scope components, and unbounded fan-out are rejected.

## Context Compiler

`RvfContextCompiler` deterministically builds a canonical RVF from content and
optional derived abstract/overview views. It uses only ratified RVF v1 segment
types, writes the versioned context descriptor into `PROFILE`, records
progressive-view provenance, computes the complete-file revision, and
self-verifies the result through `VerifiedContextProfile` before returning it.
No RVM-private segment discriminant or RVF root profile identifier is added.

## Receipt Durability and Recovery

Receipt durability is part of the runtime state transition, not an eventual
side effect. `ContextRuntime::seal_epoch_transactional` signs and verifies the
candidate receipt, then invokes the durable commit before it emits the seal
witness or advances `ReceiptChainState`. Failure leaves both the cursor and
seal witness unchanged.

`DurableReceiptStore` atomically appends the signed receipt and following
cursor. It rejects invalid signatures, replayed epochs, missing predecessors,
forked receipt links, non-adjacent ranges, and chain-hash mismatches.
`ReceiptDrainer` computes the number of unsealed records, refuses an unsafe
threshold, and activates admission backpressure while at least two ring slots
remain available.

| Failure point | Recovery behavior |
|---|---|
| Crash before REDB commit | No alias or outbox change is visible |
| Crash after source-of-truth commit | Startup replays the durable index outbox |
| RuVector shard unavailable | Source of truth remains committed; job stays pending and requests fail closed where fresh derived state is required |
| Purge sink unavailable | Key destruction/source mutation remain committed; purge job remains pending for operator-visible retry |
| Receipt database failure | Runtime cursor and seal witness do not advance |
| Crash after receipt commit | Authenticated cursor resumes at the exact next sequence/epoch and replay is rejected |
| Drainer lag | Admission stops before an unsealed record can be overwritten |

## Execution Boundary

`Instance::create_from_context` consumes a non-cloneable `ExecutionPermit`,
checks the permit's full RVF identity against the verified package, checks the
placement actor, and retains authorization metadata in the instance. A
mismatch is witnessed and refused. Construction does not execute guest code;
the existing verified launch lifecycle remains responsible for mapping and
starting the instance.

## Hosted Protocols

`ContextGateway` is the only JSON dispatcher for both HTTPS routes and MCP
tools. It exposes:

```text
/v1/resolve  /v1/list     /v1/tree    /v1/read    /v1/search
/v1/history  /v1/verify   /v1/put     /v1/cas     /v1/forget
/mcp
```

The MCP adapter implements the 2025-03-26 initialization, tool listing, and
tool call shapes for the same ten operations. It forwards requests to the same
dispatcher, so the two surfaces cannot drift in authorization or URI parsing.
Forbidden, hidden, absent, and tombstoned resources collapse to the same
external `404` response. Detailed internal errors remain available to trusted
service telemetry.

The bundled server is TLS-only, validates PEM key material at startup, limits
request bodies to 24 MiB, caps concurrent connections at 128, applies a
30-second handshake/request timeout, reads a bearer token from a file, compares
it in constant time, and defaults to `READ | PROVE`. Writes require
`RVM_CONTEXT_ALLOW_WRITES=1`. The CLI validates the server certificate, bounds
responses to 32 MiB, and accepts only `/mcp` or plain `/v1/*` routes.

Required server configuration is:

| Environment variable | Purpose |
|---|---|
| `RVM_CONTEXT_BIND` | Socket address to bind |
| `RVM_CONTEXT_SCOPE` | Canonical root `ruv://` scope |
| `RVM_CONTEXT_ACTOR` | Trusted RVM partition identifier |
| `RVM_CONTEXT_ROOT` | Durable REDB and RuVector directory |
| `RVM_CONTEXT_TOKEN_FILE` | File containing at least 32 bytes of bearer-token entropy |
| `RVM_CONTEXT_TLS_CERT`, `RVM_CONTEXT_TLS_KEY` | PEM TLS certificate chain and private key |
| `RVM_CONTEXT_DEV_KEK_HEX` | 32-byte development KEK encoded as 64 hex characters |

## Security and Performance Evidence

Automated tests cover encrypted round trips, immutable-put conflict, stale CAS,
restart recovery, index replay, purge retry, cryptographic forget, uniform
cross-tenant errors, denied-search zero-touch behavior, MCP/HTTPS parity,
receipt fork/replay/refusal, persistence-before-cursor advance, and
permit-to-launch identity checks.

On the development host, deterministic 384-dimensional embedding of a 4 KiB
input improved from approximately 116 microseconds to 8.5 microseconds after
hash-state reuse. The canonical RVF compiler measured approximately 40--95
microseconds and an authorized durable resolution approximately 4.3--5.4
microseconds. These are engineering baselines, not cross-machine SLOs.

`cargo audit` has no known vulnerable dependency in the integrated lockfile.
It reports three inherited ecosystem warnings: unmaintained `bincode` 1.x and
2.x through RuVector dependencies, and the existing yanked `spin` 0.9.8 in the
RVM workspace. They are disclosed release risks and must be removed through
their owning dependency updates rather than hidden with local patches.

## Upstream Coordination

The physical-scope storage primitive is contributed upstream as
[RuVector PR #902](https://github.com/ruvnet/RuVector/pull/902). This service is
stacked on [RVM PR #38](https://github.com/ruvnet/rvm/pull/38), which introduces
the ADR-157 contract. The RVM gitlink is pinned to the exact reviewed RuVector
commit; it must advance to the upstream merge commit when #902 lands.

## Consequences

### Positive

1. Authorization occurs before any physical vector enumeration.
2. Alias/source mutations are linearizable and crash replay is explicit.
3. Erasure has cryptographic and operational evidence boundaries.
4. Receipt persistence cannot lag behind a claimed successful seal.
5. HTTPS, MCP, and CLI surfaces share one canonical request contract.
6. A context execution permit is consumed at the existing verified launch
   boundary instead of becoming a second loader.

### Negative

1. Hosted builds require Rust 1.85 while the core contract remains on 1.77.
2. Exact physical sharding uses more files and handles than one global index.
3. Operators must supply real KMS and purge adapters for their infrastructure.
4. Local bearer-token authentication is intentionally small in scope; an
   identity-aware edge proxy remains appropriate for Internet exposure.
5. The experimental `ruv://` identifier still uses HTTPS as its transport and
   is not an IANA-registered public scheme.

## Rollback

Revoke the gateway's Context capabilities and stop admission. Drain any
remaining sealable witness range, retain signed receipts and pinned RVFs, and
snapshot REDB before disabling the service. Reverting the active RuVector
index is safe because it is derived state. Do not reuse an alias generation,
rewrite a pinned revision, discard pending purge work, or reconstruct a receipt
cursor without authenticating the stored receipt chain.
