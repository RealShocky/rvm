//! Governed runtime ordering authorization, resolver access, and witnessing.
//!
//! Every entry point first mints a private [`AuthorizedRequest`] through the
//! live capability authority. Resolver results are then checked against the
//! authorized URI before any bytes or enumeration results reach the caller.
//! A P1 allow/deny decision is witnessed before backend access; operation
//! actions are emitted only after successful completion and validation.

use crate::capability::{
    AuthorizedRequest, CapabilityHandle, ContextAuthority, ContextOperation, ContextRequest,
    ContextScope, MAX_SEARCH_RESULTS,
};
use crate::error::{ContextError, ContextResult};
use crate::profile::{ProfileTrust, VerifiedContextProfile};
use crate::receipt::{ContextEpochReceipt, SignedContextEpochReceipt};
use crate::resolver::{
    is_within, same_logical_name, AliasGeneration, AliasSnapshot, ContextHit, ContextResolver,
    ResolvedContext, MAX_ENUM_RESULTS, MAX_RVF_BYTES, MAX_SEARCH_QUERY_BYTES,
};
use crate::uri::{PinnedRuvUri, ProgressiveView, Revision};
use alloc::vec::Vec;
use rvm_proof::WitnessSigner;
use rvm_types::{CapRights, PartitionId, WitnessRecord};
use rvm_witness::{WitnessCheckpoint, WitnessLog};

/// Trusted source of witness timestamps for one actor-bound runtime.
///
/// Implementations are supplied by the kernel or host dispatch layer, never by
/// request payloads. Values should be monotonic. Receipt integrity relies on
/// sequence and chain coordinates even if an imported clock observation moves
/// backwards.
pub trait ContextClock {
    /// Return the next trusted witness timestamp in nanoseconds.
    fn timestamp_ns(&mut self) -> u64;
}

impl<F> ContextClock for F
where
    F: FnMut() -> u64,
{
    fn timestamp_ns(&mut self) -> u64 {
        self()
    }
}

/// Deterministic monotonic logical clock used by the default runtime.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct LogicalContextClock {
    next_timestamp_ns: u64,
}

impl LogicalContextClock {
    /// Create a logical clock beginning at zero.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            next_timestamp_ns: 0,
        }
    }

    /// Create a logical clock at an authenticated resume value.
    #[must_use]
    pub const fn trusted_resume(next_timestamp_ns: u64) -> Self {
        Self { next_timestamp_ns }
    }
}

impl ContextClock for LogicalContextClock {
    fn timestamp_ns(&mut self) -> u64 {
        let timestamp_ns = self.next_timestamp_ns;
        self.next_timestamp_ns = self.next_timestamp_ns.saturating_add(1);
        timestamp_ns
    }
}

/// A one-operation authorization to execute one pinned skill revision.
///
/// The permit intentionally contains no RVF bytes and is not `Clone`: read
/// authority and execute authority remain distinct, and callers must hand the
/// permit to their execution boundary rather than treating it as content.
#[derive(Debug, PartialEq, Eq)]
pub struct ExecutionPermit {
    actor: PartitionId,
    pinned_uri: PinnedRuvUri,
    revision: Revision,
    capability_hash: u32,
    witness_sequence: u64,
}

/// Persistent cursor for the runtime-owned context receipt chain.
///
/// The runtime derives every new receipt's checkpoint, epoch identifier, and
/// previous-receipt link from this state. Callers cannot select those values at
/// seal time. Persist this state atomically with each durable signed receipt.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ReceiptChainState {
    next_checkpoint: WitnessCheckpoint,
    next_epoch_id: u64,
    previous_receipt_id: [u8; 32],
}

impl ReceiptChainState {
    fn genesis(next_checkpoint: WitnessCheckpoint) -> Self {
        debug_assert_eq!(next_checkpoint.next_sequence(), 0);
        debug_assert_eq!(next_checkpoint.chain_hash(), 0);
        Self {
            next_checkpoint,
            next_epoch_id: 0,
            previous_receipt_id: [0; 32],
        }
    }

    /// Reconstruct persisted receipt-chain state at a trusted resume boundary.
    ///
    /// This is an administrative recovery API. The caller must authenticate
    /// the checkpoint and receipt ID against durable receipt storage before
    /// constructing the state; ordinary context requests never supply it.
    #[must_use]
    pub const fn trusted_resume(
        next_checkpoint: WitnessCheckpoint,
        next_epoch_id: u64,
        previous_receipt_id: [u8; 32],
    ) -> Self {
        Self {
            next_checkpoint,
            next_epoch_id,
            previous_receipt_id,
        }
    }

    /// Return the exact witness boundary at which the next epoch begins.
    #[must_use]
    pub const fn next_checkpoint(self) -> WitnessCheckpoint {
        self.next_checkpoint
    }

    /// Return the epoch identifier the runtime will assign to the next receipt.
    #[must_use]
    pub const fn next_epoch_id(self) -> u64 {
        self.next_epoch_id
    }

    /// Return the signed receipt ID that the next receipt must link to.
    #[must_use]
    pub const fn previous_receipt_id(self) -> [u8; 32] {
        self.previous_receipt_id
    }
}

impl ExecutionPermit {
    /// Return the partition authorized to execute the revision.
    #[must_use]
    pub const fn actor(&self) -> PartitionId {
        self.actor
    }

    /// Return the exact immutable skill URI.
    #[must_use]
    pub const fn pinned_uri(&self) -> &PinnedRuvUri {
        &self.pinned_uri
    }

    /// Return the verified complete-RVF identity.
    #[must_use]
    pub const fn revision(&self) -> Revision {
        self.revision
    }

    /// Return the non-secret truncated capability identifier.
    #[must_use]
    pub const fn capability_hash(&self) -> u32 {
        self.capability_hash
    }

    /// Return the sequence of the successful execute-authorization witness.
    #[must_use]
    pub const fn witness_sequence(&self) -> u64 {
        self.witness_sequence
    }
}

/// Capability-gated facade over one context resolver and witness ring.
pub struct ContextRuntime<
    R,
    const CAPABILITIES: usize,
    const GRANTS: usize,
    const WITNESSES: usize,
    CLOCK = LogicalContextClock,
> {
    actor: PartitionId,
    authority: ContextAuthority<CAPABILITIES, GRANTS>,
    resolver: R,
    witness: WitnessLog<WITNESSES>,
    receipt_chain: ReceiptChainState,
    clock: CLOCK,
}

impl<R, const C: usize, const G: usize, const W: usize>
    ContextRuntime<R, C, G, W, LogicalContextClock>
{
    /// Create an actor-bound runtime with a new empty witness ring.
    ///
    /// `actor` comes from the trusted kernel dispatch context. It is immutable
    /// for the lifetime of this runtime and is never selected by request data.
    #[must_use]
    pub fn new(actor: PartitionId, authority: ContextAuthority<C, G>, resolver: R) -> Self {
        Self::with_clock(actor, authority, resolver, LogicalContextClock::new())
    }
}

impl<R, const C: usize, const G: usize, const W: usize, CLOCK: ContextClock>
    ContextRuntime<R, C, G, W, CLOCK>
{
    /// Create an actor-bound runtime with an injected trusted host clock.
    #[must_use]
    pub fn with_clock(
        actor: PartitionId,
        authority: ContextAuthority<C, G>,
        resolver: R,
        clock: CLOCK,
    ) -> Self {
        let witness = WitnessLog::new();
        let receipt_chain = ReceiptChainState::genesis(witness.checkpoint());
        Self {
            actor,
            authority,
            resolver,
            witness,
            receipt_chain,
            clock,
        }
    }

    /// Resume a runtime around an existing witness ring and trusted chain state.
    ///
    /// The state must have been authenticated against durable receipt storage.
    /// A fresh runtime should use [`Self::new`] so genesis is fixed to epoch and
    /// sequence zero with an all-zero previous-receipt link.
    #[must_use]
    pub const fn with_witness(
        actor: PartitionId,
        authority: ContextAuthority<C, G>,
        resolver: R,
        witness: WitnessLog<W>,
        receipt_chain: ReceiptChainState,
        clock: CLOCK,
    ) -> Self {
        Self {
            actor,
            authority,
            resolver,
            witness,
            receipt_chain,
            clock,
        }
    }

    /// Return the authenticated partition bound by trusted kernel dispatch.
    #[must_use]
    pub const fn actor(&self) -> PartitionId {
        self.actor
    }

    /// Return trusted capability administration access.
    #[must_use]
    pub const fn authority(&self) -> &ContextAuthority<C, G> {
        &self.authority
    }

    /// Return mutable trusted capability administration access.
    #[must_use]
    pub fn authority_mut(&mut self) -> &mut ContextAuthority<C, G> {
        &mut self.authority
    }

    /// Return read-only resolver access for metrics and inspection.
    #[must_use]
    pub const fn resolver(&self) -> &R {
        &self.resolver
    }

    /// Return the append-only witness ring.
    #[must_use]
    pub const fn witness_log(&self) -> &WitnessLog<W> {
        &self.witness
    }

    /// Return the receipt cursor that must be persisted with durable receipts.
    #[must_use]
    pub const fn receipt_chain_state(&self) -> ReceiptChainState {
        self.receipt_chain
    }

    /// Consume the runtime and return its owned components.
    #[must_use]
    pub fn into_parts(
        self,
    ) -> (
        PartitionId,
        ContextAuthority<C, G>,
        R,
        WitnessLog<W>,
        ReceiptChainState,
        CLOCK,
    ) {
        (
            self.actor,
            self.authority,
            self.resolver,
            self.witness,
            self.receipt_chain,
            self.clock,
        )
    }

    fn authorize(
        &mut self,
        request: &ContextRequest,
        operation: ContextOperation,
    ) -> ContextResult<AuthorizedRequest> {
        let timestamp_ns = self.clock.timestamp_ns();
        self.authority
            .authorize(self.actor, timestamp_ns, request, operation, &self.witness)
    }

    fn reject_resolver<T>(&self, request: &AuthorizedRequest) -> ContextResult<T> {
        let _ = ContextAuthority::<C, G>::record_resolver_rejection(request, &self.witness);
        Err(ContextError::ResolverScopeViolation)
    }

    fn complete(&self, request: &AuthorizedRequest) -> u64 {
        ContextAuthority::<C, G>::record_success(request, &self.witness)
    }
}

impl<R: ContextResolver, const C: usize, const G: usize, const W: usize, CLOCK: ContextClock>
    ContextRuntime<R, C, G, W, CLOCK>
{
    /// Resolve an alias or pinned target to immutable metadata.
    ///
    /// # Errors
    ///
    /// Returns authorization, resolver, or scope-validation failures.
    pub fn resolve(&mut self, request: &ContextRequest) -> ContextResult<ResolvedContext> {
        let authorized = self.authorize(request, ContextOperation::Resolve)?;
        let resolved = self.resolver.resolve(&authorized)?;
        if !valid_exact_result(authorized.target(), &resolved) {
            return self.reject_resolver(&authorized);
        }
        let _ = self.complete(&authorized);
        Ok(resolved)
    }

    /// List live direct-child aliases with a bounded result count.
    ///
    /// # Errors
    ///
    /// Refuses invalid bounds, unauthorized calls, and out-of-scope results.
    pub fn list(
        &mut self,
        request: &ContextRequest,
        limit: usize,
    ) -> ContextResult<Vec<ResolvedContext>> {
        let authorized = self.authorize(request, ContextOperation::List)?;
        validate_enum_limit(limit)?;
        let entries = self.resolver.list(&authorized, limit)?;
        if !valid_enumeration(authorized.target(), &entries, limit, false) {
            return self.reject_resolver(&authorized);
        }
        let _ = self.complete(&authorized);
        Ok(entries)
    }

    /// Traverse all live descendant aliases with a bounded result count.
    ///
    /// # Errors
    ///
    /// Refuses invalid bounds, unauthorized calls, and out-of-scope results.
    pub fn tree(
        &mut self,
        request: &ContextRequest,
        limit: usize,
    ) -> ContextResult<Vec<ResolvedContext>> {
        let authorized = self.authorize(request, ContextOperation::Tree)?;
        validate_enum_limit(limit)?;
        let entries = self.resolver.tree(&authorized, limit)?;
        if !valid_enumeration(authorized.target(), &entries, limit, true) {
            return self.reject_resolver(&authorized);
        }
        let _ = self.complete(&authorized);
        Ok(entries)
    }

    /// Read one verified progressive representation.
    ///
    /// With no explicit `view`, this returns the profile-bound content segment.
    /// An explicit view returns only that profile-bound segment payload. The
    /// complete container is never released through the read API.
    ///
    /// # Errors
    ///
    /// Refuses unauthorized access, invalid RVF/profile bytes, and resolver
    /// identity or scope violations.
    pub fn read(&mut self, request: &ContextRequest) -> ContextResult<(ResolvedContext, Vec<u8>)> {
        let authorized = self.authorize(request, ContextOperation::Read)?;
        let (resolved, rvf) = self.resolver.read(&authorized)?;
        if !valid_exact_result(authorized.target(), &resolved) || resolved.rvf_len() != rvf.len() {
            return self.reject_resolver(&authorized);
        }
        let profile = verify_profile(&rvf, resolved.revision())?;
        let view = authorized
            .target()
            .view()
            .unwrap_or(ProgressiveView::Content);
        let output = profile
            .payload(&rvf, view)
            .map_err(|_| ContextError::RvfVerificationFailed)?
            .to_vec();
        let _ = self.complete(&authorized);
        Ok((resolved, output))
    }

    /// Search live context aliases with bounded input and output.
    ///
    /// # Errors
    ///
    /// Refuses invalid bounds, unauthorized calls, and out-of-scope results.
    pub fn search(
        &mut self,
        request: &ContextRequest,
        query: &[u8],
        limit: usize,
    ) -> ContextResult<Vec<ContextHit>> {
        let authorized = self.authorize(request, ContextOperation::Search)?;
        if query.is_empty() || query.len() > MAX_SEARCH_QUERY_BYTES {
            return Err(ContextError::InvalidQuery);
        }
        if limit == 0 || limit > MAX_SEARCH_RESULTS {
            return Err(ContextError::InvalidResultLimit);
        }
        let hits = self.resolver.search(&authorized, query, limit)?;
        if !valid_hits(authorized.target(), &hits, limit) {
            return self.reject_resolver(&authorized);
        }
        let _ = self.complete(&authorized);
        Ok(hits)
    }

    /// Enumerate immutable revisions registered under one live alias.
    ///
    /// # Errors
    ///
    /// Refuses invalid bounds, tombstones, unauthorized calls, and invalid
    /// resolver results.
    pub fn history(
        &mut self,
        request: &ContextRequest,
        limit: usize,
    ) -> ContextResult<Vec<ResolvedContext>> {
        let authorized = self.authorize(request, ContextOperation::History)?;
        validate_enum_limit(limit)?;
        let entries = self.resolver.history(&authorized, limit)?;
        if entries.len() > limit
            || entries.iter().any(|entry| {
                !valid_result_integrity(entry)
                    || !same_logical_name(authorized.target(), entry.pinned_uri().as_uri())
            })
            || has_duplicate_results(&entries)
        {
            return self.reject_resolver(&authorized);
        }
        let _ = self.complete(&authorized);
        Ok(entries)
    }

    /// Verify a pinned complete RVF and its context profile without returning
    /// any bytes.
    ///
    /// # Errors
    ///
    /// Refuses unauthorized access, corrupt RVF/profile bytes, or a resolver
    /// identity mismatch.
    pub fn verify(&mut self, request: &ContextRequest) -> ContextResult<ResolvedContext> {
        let authorized = self.authorize(request, ContextOperation::Verify)?;
        let (resolved, rvf) = self.resolver.verify(&authorized)?;
        if !valid_exact_result(authorized.target(), &resolved) || resolved.rvf_len() != rvf.len() {
            return self.reject_resolver(&authorized);
        }
        let _ = verify_profile(&rvf, resolved.revision())?;
        let _ = self.complete(&authorized);
        Ok(resolved)
    }

    /// Verify and register a new immutable complete RVF revision.
    ///
    /// # Errors
    ///
    /// Refuses unverified RVF/profile bytes before backend mutation, as well
    /// as authorization, capacity, identity, and scope failures.
    pub fn put(&mut self, request: &ContextRequest, rvf: &[u8]) -> ContextResult<ResolvedContext> {
        let authorized = self.authorize(request, ContextOperation::Put)?;
        let revision = authorized
            .target()
            .revision()
            .ok_or(ContextError::PinnedUriRequired)?;
        let _ = verify_profile(rvf, revision)?;
        let resolved = self.resolver.put(&authorized, rvf)?;
        if !valid_exact_result(authorized.target(), &resolved) || resolved.rvf_len() != rvf.len() {
            return self.reject_resolver(&authorized);
        }
        let _ = self.complete(&authorized);
        Ok(resolved)
    }

    /// Atomically create or advance a versionless alias.
    ///
    /// # Errors
    ///
    /// Refuses stale/full snapshots, unauthorized mutation, absent revisions,
    /// and invalid resolver results.
    pub fn compare_and_swap_alias(
        &mut self,
        request: &ContextRequest,
        expected: Option<&AliasSnapshot>,
        next_revision: Revision,
    ) -> ContextResult<AliasSnapshot> {
        let authorized = self.authorize(request, ContextOperation::CompareAndSwapAlias)?;
        if expected.is_some_and(|snapshot| {
            snapshot.is_tombstone() || !same_logical_name(snapshot.alias(), authorized.target())
        }) {
            return Err(ContextError::InvalidTarget);
        }
        let snapshot =
            self.resolver
                .compare_and_swap_alias(&authorized, expected, next_revision)?;
        let expected_generation = expected.map_or(Some(AliasGeneration::INITIAL), |prior| {
            prior
                .generation()
                .get()
                .checked_add(1)
                .and_then(AliasGeneration::new)
        });
        if snapshot.is_tombstone()
            || !same_logical_name(snapshot.alias(), authorized.target())
            || snapshot.revision() != next_revision
            || Some(snapshot.generation()) != expected_generation
        {
            return self.reject_resolver(&authorized);
        }
        let _ = self.complete(&authorized);
        Ok(snapshot)
    }

    /// Permanently advance an alias to an immutable tombstone revision.
    ///
    /// # Errors
    ///
    /// Refuses stale snapshots, repeat forget, unauthorized mutation, and
    /// invalid resolver results.
    pub fn forget(
        &mut self,
        request: &ContextRequest,
        expected: &AliasSnapshot,
    ) -> ContextResult<AliasSnapshot> {
        let authorized = self.authorize(request, ContextOperation::Forget)?;
        if expected.is_tombstone() || !same_logical_name(expected.alias(), authorized.target()) {
            return Err(ContextError::InvalidTarget);
        }
        let snapshot = self.resolver.forget(&authorized, expected)?;
        let expected_generation = expected
            .generation()
            .get()
            .checked_add(1)
            .and_then(AliasGeneration::new);
        if !snapshot.is_tombstone()
            || !same_logical_name(snapshot.alias(), authorized.target())
            || snapshot.revision() == expected.revision()
            || Some(snapshot.generation()) != expected_generation
        {
            return self.reject_resolver(&authorized);
        }
        let _ = self.complete(&authorized);
        Ok(snapshot)
    }

    /// Verify a pinned executable skill and return a byte-free permit.
    ///
    /// # Errors
    ///
    /// Requires separate `EXECUTE` authority, a pinned Skills URI, a verified
    /// RVF/profile, and an executable content segment.
    pub fn authorize_execute(
        &mut self,
        request: &ContextRequest,
    ) -> ContextResult<ExecutionPermit> {
        let authorized = self.authorize(request, ContextOperation::Execute)?;
        let (resolved, rvf) = self.resolver.prepare_execute(&authorized)?;
        if !valid_exact_result(authorized.target(), &resolved) || resolved.rvf_len() != rvf.len() {
            return self.reject_resolver(&authorized);
        }
        let profile = verify_profile(&rvf, resolved.revision())?;
        if !profile.is_executable(ProgressiveView::Content) {
            return Err(ContextError::InvalidTarget);
        }
        let witness_sequence = self.complete(&authorized);
        Ok(ExecutionPermit {
            actor: authorized.actor(),
            pinned_uri: resolved.pinned_uri().clone(),
            revision: resolved.revision(),
            capability_hash: authorized.capability_hash(),
            witness_sequence,
        })
    }

    /// Delegate an equal-or-narrower context capability after authorization.
    ///
    /// # Errors
    ///
    /// Refuses missing `GRANT`, owner mismatch, stale handles, scope or rights
    /// widening, and bounded table exhaustion.
    pub fn grant(
        &mut self,
        request: &ContextRequest,
        child_scope: ContextScope,
        requested_rights: CapRights,
        target_owner: PartitionId,
    ) -> ContextResult<CapabilityHandle> {
        let source = request.capability();
        let authorized = self.authorize(request, ContextOperation::Grant)?;
        let handle = self.authority.delegate(
            source,
            child_scope,
            requested_rights,
            target_owner,
            self.actor,
        )?;
        let _ = self.complete(&authorized);
        Ok(handle)
    }

    /// Revoke a context capability lineage after authorization.
    ///
    /// # Errors
    ///
    /// Refuses missing `REVOKE`, owner mismatch, or a stale capability.
    pub fn revoke(&mut self, request: &ContextRequest) -> ContextResult<usize> {
        let handle = request.capability();
        let authorized = self.authorize(request, ContextOperation::Revoke)?;
        let count = self.authority.revoke(handle)?;
        let _ = self.complete(&authorized);
        Ok(count)
    }

    /// Snapshot, seal, sign, and anchor one complete witness epoch.
    ///
    /// The pinned request target must equal `rvf_identity`. The successful
    /// `ContextEpochSeal` record is appended only after signing, placing it in
    /// the next epoch and preventing a failed seal from claiming success.
    ///
    /// # Errors
    ///
    /// Refuses missing `PROVE`, an identity mismatch, wrapped or incomplete
    /// witness snapshots, invalid record chains, and empty epochs.
    #[allow(clippy::too_many_arguments)]
    pub fn seal_epoch<S: WitnessSigner>(
        &mut self,
        request: &ContextRequest,
        scratch: &mut [WitnessRecord],
        namespace_root: [u8; 32],
        rvf_identity: [u8; 32],
        policy_hash: [u8; 32],
        detail_root: [u8; 32],
        signer: &S,
    ) -> ContextResult<(SignedContextEpochReceipt, WitnessCheckpoint)> {
        self.seal_epoch_transactional(
            request,
            scratch,
            namespace_root,
            rvf_identity,
            policy_hash,
            detail_root,
            signer,
            |_, _| Ok(()),
        )
    }

    /// Seal an epoch and durably persist its following cursor before runtime
    /// state advances.
    ///
    /// `persist` receives the authenticated signed receipt and the exact state
    /// that a recovered runtime must resume from. A persistence refusal leaves
    /// the runtime cursor unchanged and emits no successful seal record.
    ///
    /// # Errors
    ///
    /// Refuses every condition documented by [`Self::seal_epoch`] and any
    /// fail-closed error returned by `persist`.
    #[allow(clippy::too_many_arguments)]
    pub fn seal_epoch_transactional<S: WitnessSigner, F>(
        &mut self,
        request: &ContextRequest,
        scratch: &mut [WitnessRecord],
        namespace_root: [u8; 32],
        rvf_identity: [u8; 32],
        policy_hash: [u8; 32],
        detail_root: [u8; 32],
        signer: &S,
        persist: F,
    ) -> ContextResult<(SignedContextEpochReceipt, WitnessCheckpoint)>
    where
        F: FnOnce(&SignedContextEpochReceipt, ReceiptChainState) -> ContextResult<()>,
    {
        let authorized = self.authorize(request, ContextOperation::SealReceipt)?;
        let following_epoch_id = self
            .receipt_chain
            .next_epoch_id
            .checked_add(1)
            .ok_or(ContextError::ReceiptSealFailed)?;
        if authorized
            .target()
            .revision()
            .map(|revision| *revision.as_bytes())
            != Some(rvf_identity)
        {
            return Err(ContextError::InvalidTarget);
        }
        let (receipt, next_checkpoint) = ContextEpochReceipt::seal_from_log(
            self.receipt_chain.next_epoch_id,
            &self.witness,
            self.receipt_chain.next_checkpoint,
            scratch,
            self.receipt_chain.previous_receipt_id,
            namespace_root,
            rvf_identity,
            policy_hash,
            detail_root,
        )
        .map_err(|_| ContextError::ReceiptSealFailed)?;
        let signed_receipt = receipt.sign(signer);
        let receipt_id = signed_receipt.receipt_id();
        let following_state = ReceiptChainState {
            next_checkpoint,
            next_epoch_id: following_epoch_id,
            previous_receipt_id: receipt_id,
        };
        {
            let verified = signed_receipt
                .verify(signer)
                .map_err(|_| ContextError::ReceiptSealFailed)?;
            persist(&signed_receipt, following_state)?;
            let seal_timestamp_ns = self.clock.timestamp_ns();
            let _ = verified.emit_seal(
                &self.witness,
                authorized.actor().as_u32(),
                authorized.capability_hash(),
                seal_timestamp_ns,
            );
        }
        self.receipt_chain = following_state;
        Ok((signed_receipt, next_checkpoint))
    }
}

fn verify_profile(rvf: &[u8], revision: Revision) -> ContextResult<VerifiedContextProfile> {
    if rvf.len() > MAX_RVF_BYTES {
        return Err(ContextError::ObjectTooLarge);
    }
    VerifiedContextProfile::from_rvf(rvf, revision, ProfileTrust::PinnedIdentity, &[])
        .map_err(|_| ContextError::RvfVerificationFailed)
}

fn validate_enum_limit(limit: usize) -> ContextResult<()> {
    if limit == 0 || limit > MAX_ENUM_RESULTS {
        Err(ContextError::InvalidResultLimit)
    } else {
        Ok(())
    }
}

fn valid_result_integrity(result: &ResolvedContext) -> bool {
    let alias_is_valid = match result.alias() {
        Some(alias) => {
            !alias.is_tombstone()
                && alias.revision() == result.revision()
                && same_logical_name(alias.alias(), result.pinned_uri().as_uri())
        }
        None => true,
    };
    result.rvf_len() <= MAX_RVF_BYTES
        && result.pinned_uri().revision() == result.revision()
        && alias_is_valid
}

fn valid_exact_result(target: &crate::uri::RuvUri, result: &ResolvedContext) -> bool {
    valid_result_integrity(result)
        && same_logical_name(target, result.pinned_uri().as_uri())
        && target.revision().map_or_else(
            || result.alias().is_some(),
            |revision| revision == result.revision(),
        )
}

fn valid_enumeration(
    root: &crate::uri::RuvUri,
    entries: &[ResolvedContext],
    limit: usize,
    recursive: bool,
) -> bool {
    entries.len() <= limit
        && !has_duplicate_results(entries)
        && entries.iter().all(|entry| {
            let candidate = entry.pinned_uri().as_uri();
            valid_result_integrity(entry)
                && entry.alias().is_some()
                && is_within(root, candidate)
                && candidate.path().len() > root.path().len()
                && (recursive || candidate.path().len() == root.path().len() + 1)
        })
}

fn has_duplicate_results(entries: &[ResolvedContext]) -> bool {
    entries.iter().enumerate().any(|(index, entry)| {
        entries[..index]
            .iter()
            .any(|prior| prior.pinned_uri() == entry.pinned_uri())
    })
}

fn valid_hits(root: &crate::uri::RuvUri, hits: &[ContextHit], limit: usize) -> bool {
    hits.len() <= limit
        && hits.iter().enumerate().all(|(index, hit)| {
            let candidate = hit.pinned_uri().as_uri();
            hit.revision() == hit.pinned_uri().revision()
                && if let Some(revision) = root.revision() {
                    same_logical_name(root, candidate) && hit.revision() == revision
                } else {
                    is_within(root, candidate)
                }
                && !hits[..index]
                    .iter()
                    .any(|prior| prior.pinned_uri() == hit.pinned_uri())
        })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::capability::{CapabilityHandle, ContextScope, ContextViewMask};
    use crate::profile::{ContextProfile, ProfileView};
    use crate::resolver::MemoryResolver;
    use crate::uri::RuvUri;
    use alloc::format;
    use alloc::vec;
    use rvm_proof::HmacSha256WitnessSigner;
    use rvm_rvf::{
        content_hash, sha256, SegmentHeader, SEGMENT_HEADER_SIZE, SEGMENT_MAGIC, SEGMENT_VERSION,
        SEG_TYPE_PROFILE,
    };
    use rvm_types::ActionKind;
    use sha2::{Digest, Sha256};

    #[derive(Default)]
    struct SpyResolver {
        calls: usize,
    }

    impl SpyResolver {
        fn called<T>(&mut self) -> ContextResult<T> {
            self.calls += 1;
            Err(ContextError::RevisionNotFound)
        }
    }

    impl ContextResolver for SpyResolver {
        fn resolve(&mut self, _: &AuthorizedRequest) -> ContextResult<ResolvedContext> {
            self.called()
        }

        fn list(&mut self, _: &AuthorizedRequest, _: usize) -> ContextResult<Vec<ResolvedContext>> {
            self.called()
        }

        fn tree(&mut self, _: &AuthorizedRequest, _: usize) -> ContextResult<Vec<ResolvedContext>> {
            self.called()
        }

        fn read(&mut self, _: &AuthorizedRequest) -> ContextResult<(ResolvedContext, Vec<u8>)> {
            self.called()
        }

        fn search(
            &mut self,
            _: &AuthorizedRequest,
            _: &[u8],
            _: usize,
        ) -> ContextResult<Vec<ContextHit>> {
            self.called()
        }

        fn history(
            &mut self,
            _: &AuthorizedRequest,
            _: usize,
        ) -> ContextResult<Vec<ResolvedContext>> {
            self.called()
        }

        fn verify(&mut self, _: &AuthorizedRequest) -> ContextResult<(ResolvedContext, Vec<u8>)> {
            self.called()
        }

        fn put(&mut self, _: &AuthorizedRequest, _: &[u8]) -> ContextResult<ResolvedContext> {
            self.called()
        }

        fn compare_and_swap_alias(
            &mut self,
            _: &AuthorizedRequest,
            _: Option<&AliasSnapshot>,
            _: Revision,
        ) -> ContextResult<AliasSnapshot> {
            self.called()
        }

        fn forget(
            &mut self,
            _: &AuthorizedRequest,
            _: &AliasSnapshot,
        ) -> ContextResult<AliasSnapshot> {
            self.called()
        }

        fn prepare_execute(
            &mut self,
            _: &AuthorizedRequest,
        ) -> ContextResult<(ResolvedContext, Vec<u8>)> {
            self.called()
        }
    }

    type TestRuntime = ContextRuntime<SpyResolver, 16, 16, 32>;

    fn root() -> RuvUri {
        RuvUri::parse("ruv://example.com/acme/user/alice/resources/docs").unwrap()
    }

    fn target() -> RuvUri {
        RuvUri::parse("ruv://example.com/acme/user/alice/resources/docs/item").unwrap()
    }

    fn runtime_as(
        rights: CapRights,
        runtime_actor: PartitionId,
    ) -> (TestRuntime, CapabilityHandle, PartitionId) {
        let owner = PartitionId::new(41);
        let mut authority = ContextAuthority::<16, 16>::with_defaults();
        let handle = authority
            .issue_root(
                ContextScope::from_uri(&root(), ContextViewMask::ALL),
                rights,
                owner,
                PartitionId::HYPERVISOR,
            )
            .unwrap();
        (
            ContextRuntime::new(runtime_actor, authority, SpyResolver::default()),
            handle,
            owner,
        )
    }

    fn runtime(rights: CapRights) -> (TestRuntime, CapabilityHandle, PartitionId) {
        let owner = PartitionId::new(41);
        runtime_as(rights, owner)
    }

    fn request(
        handle: CapabilityHandle,
        operation: ContextOperation,
        target: RuvUri,
    ) -> ContextRequest {
        ContextRequest::new(handle, operation, target)
    }

    fn segment(segment_type: u8, segment_id: u64, payload: &[u8]) -> Vec<u8> {
        let total = SEGMENT_HEADER_SIZE + payload.len();
        let padded = total.div_ceil(64) * 64;
        let header = SegmentHeader {
            magic: SEGMENT_MAGIC,
            version: SEGMENT_VERSION,
            seg_type: segment_type,
            flags: 0,
            segment_id,
            payload_length: u64::try_from(payload.len()).unwrap(),
            timestamp_ns: segment_id,
            checksum_algo: 2,
            compression: 0,
            reserved_0: 0,
            reserved_1: 0,
            content_hash: content_hash(2, payload),
            uncompressed_len: 0,
            alignment_pad: u32::try_from(padded - total).unwrap(),
        };
        let mut bytes = header.to_bytes().to_vec();
        bytes.extend_from_slice(payload);
        bytes.resize(padded, 0);
        bytes
    }

    fn content_only_rvf(content: &[u8]) -> Vec<u8> {
        let profile = ContextProfile::new(vec![ProfileView::content(
            1,
            Revision::from_bytes(sha256(content)),
        )
        .unwrap()])
        .unwrap();
        let mut bytes = segment(0x07, 1, content);
        bytes.extend(segment(SEG_TYPE_PROFILE, 2, &profile.to_bytes()));
        bytes.extend(segment(0x05, 3, b"root"));
        bytes
    }

    #[test]
    fn runtime_bound_actor_cannot_use_another_partitions_handle() {
        let outsider = PartitionId::new(42);
        let (mut runtime, handle, owner) = runtime_as(CapRights::READ, outsider);
        assert_ne!(runtime.actor(), owner);
        let list_request = request(handle, ContextOperation::List, root());
        assert_eq!(
            runtime.list(&list_request, 8),
            Err(ContextError::AccessDenied)
        );
        let search_request = request(handle, ContextOperation::Search, root());
        assert_eq!(
            runtime.search(&search_request, b"needle", 8),
            Err(ContextError::AccessDenied)
        );
        assert_eq!(runtime.resolver().calls, 0);
        assert_eq!(runtime.witness_log().total_emitted(), 2);
    }

    #[test]
    fn receipt_state_is_runtime_owned_and_timestamp_extremes_do_not_block_sealing() {
        let (mut runtime, handle, _) = runtime(CapRights::PROVE);
        let mut rejected = WitnessRecord::zeroed();
        rejected.action_kind = ActionKind::ProofRejected as u8;
        rejected.timestamp_ns = u64::MAX;
        let _ = runtime.witness_log().append(rejected);

        let mut normal = WitnessRecord::zeroed();
        normal.action_kind = ActionKind::ContextRead as u8;
        normal.timestamp_ns = 0;
        let _ = runtime.witness_log().append(normal);

        let rvf_identity = [9; 32];
        let pinned = target()
            .with_revision(Revision::from_bytes(rvf_identity))
            .unwrap()
            .into_uri();
        let seal_request = request(handle, ContextOperation::SealReceipt, pinned);
        let signer = HmacSha256WitnessSigner::new([0x66; 32]);
        let mut scratch = [WitnessRecord::zeroed(); 16];
        let (first, first_checkpoint) = runtime
            .seal_epoch(
                &seal_request,
                &mut scratch,
                [1; 32],
                rvf_identity,
                [2; 32],
                [3; 32],
                &signer,
            )
            .unwrap();
        let first_verified = first.verify(&signer).unwrap();
        first_verified.verify_genesis().unwrap();
        assert_eq!(first.receipt().started_ns(), 0);
        assert_eq!(first.receipt().ended_ns(), u64::MAX);
        assert_eq!(
            runtime.receipt_chain_state().next_checkpoint(),
            first_checkpoint
        );
        assert_eq!(runtime.receipt_chain_state().next_epoch_id(), 1);
        assert_eq!(
            runtime.receipt_chain_state().previous_receipt_id(),
            first.receipt_id()
        );

        let (second, second_checkpoint) = runtime
            .seal_epoch(
                &seal_request,
                &mut scratch,
                [4; 32],
                rvf_identity,
                [5; 32],
                [6; 32],
                &signer,
            )
            .unwrap();
        let second_verified = second.verify(&signer).unwrap();
        second_verified.verify_successor(&first_verified).unwrap();
        assert_eq!(second.receipt().epoch_id(), 1);
        assert_eq!(
            runtime.receipt_chain_state().next_checkpoint(),
            second_checkpoint
        );
        assert_eq!(runtime.receipt_chain_state().next_epoch_id(), 2);
        assert_eq!(
            runtime.receipt_chain_state().previous_receipt_id(),
            second.receipt_id()
        );
    }

    #[test]
    fn receipt_persistence_failure_does_not_advance_or_claim_a_seal() {
        let (mut runtime, handle, _) = runtime(CapRights::PROVE);
        let rvf_identity = [9; 32];
        let pinned = target()
            .with_revision(Revision::from_bytes(rvf_identity))
            .unwrap()
            .into_uri();
        let seal_request = request(handle, ContextOperation::SealReceipt, pinned);
        let signer = HmacSha256WitnessSigner::new([0x66; 32]);
        let mut scratch = [WitnessRecord::zeroed(); 16];
        let initial = runtime.receipt_chain_state();
        let result = runtime.seal_epoch_transactional(
            &seal_request,
            &mut scratch,
            [1; 32],
            rvf_identity,
            [2; 32],
            [3; 32],
            &signer,
            |_, _| Err(ContextError::BackendUnavailable),
        );
        assert_eq!(result, Err(ContextError::BackendUnavailable));
        assert_eq!(runtime.receipt_chain_state(), initial);
        let mut records = [WitnessRecord::zeroed(); 8];
        let count = runtime.witness_log().snapshot(&mut records);
        assert!(records[..count]
            .iter()
            .all(|record| { record.action_kind != ActionKind::ContextEpochSeal as u8 }));
    }

    #[test]
    fn operation_mismatch_is_denied_before_backend() {
        let (mut runtime, handle, _) = runtime(CapRights::READ);
        let request = request(handle, ContextOperation::Read, root());
        let result = runtime.search(&request, b"needle", 1);
        assert_eq!(result, Err(ContextError::OperationMismatch));
        assert_eq!(runtime.resolver().calls, 0);
    }

    #[test]
    fn failed_backend_call_has_allow_but_no_operation_success_record() {
        let (mut runtime, handle, _) = runtime(CapRights::READ);
        let request = request(handle, ContextOperation::Resolve, target());
        assert_eq!(
            runtime.resolve(&request),
            Err(ContextError::RevisionNotFound)
        );
        assert_eq!(runtime.resolver().calls, 1);
        let mut records = [WitnessRecord::zeroed(); 4];
        assert_eq!(runtime.witness_log().snapshot(&mut records), 1);
        assert_eq!(records[0].action_kind, ActionKind::ProofVerifiedP1 as u8);
    }

    #[test]
    fn failed_alias_cas_never_claims_alias_update() {
        let (mut runtime, handle, _) = runtime(CapRights::WRITE);
        let request = request(handle, ContextOperation::CompareAndSwapAlias, target());
        assert_eq!(
            runtime.compare_and_swap_alias(&request, None, Revision::from_bytes([9; 32])),
            Err(ContextError::RevisionNotFound)
        );
        let mut records = [WitnessRecord::zeroed(); 4];
        assert_eq!(runtime.witness_log().snapshot(&mut records), 1);
        assert_eq!(records[0].action_kind, ActionKind::ProofVerifiedP1 as u8);
        assert_ne!(records[0].action_kind, ActionKind::ContextAliasUpdate as u8);
    }

    #[test]
    fn default_read_releases_content_segment_not_whole_rvf() {
        let owner = PartitionId::new(41);
        let name = target();
        let content = b"released content only";
        let rvf = content_only_rvf(content);
        let revision = Revision::from_bytes(sha256(&rvf));
        let pinned = name.clone().with_revision(revision).unwrap();
        let mut authority = ContextAuthority::<16, 16>::with_defaults();
        let handle = authority
            .issue_root(
                ContextScope::from_uri(&root(), ContextViewMask::ALL),
                CapRights::READ | CapRights::WRITE,
                owner,
                PartitionId::HYPERVISOR,
            )
            .unwrap();
        let mut runtime = ContextRuntime::<MemoryResolver<8, 8>, 16, 16, 16>::new(
            owner,
            authority,
            MemoryResolver::new(),
        );

        let put = request(handle, ContextOperation::Put, pinned.clone().into_uri());
        runtime.put(&put, &rvf).unwrap();
        let cas = request(handle, ContextOperation::CompareAndSwapAlias, name.clone());
        runtime
            .compare_and_swap_alias(&cas, None, revision)
            .unwrap();
        let read = request(handle, ContextOperation::Read, name);
        let (_, released) = runtime.read(&read).unwrap();
        assert_eq!(released, content);
        assert_ne!(released, rvf);
    }

    #[test]
    fn invalid_rvf_is_rejected_before_put_backend() {
        let (mut runtime, handle, _) = runtime(CapRights::WRITE);
        let bytes = b"not an RVF";
        let digest = Sha256::digest(bytes);
        let mut revision_bytes = [0u8; 32];
        revision_bytes.copy_from_slice(&digest);
        let revision = Revision::sha256(revision_bytes);
        let pinned = target().with_revision(revision).unwrap().into_uri();
        let request = request(handle, ContextOperation::Put, pinned);
        assert_eq!(
            runtime.put(&request, bytes),
            Err(ContextError::RvfVerificationFailed)
        );
        assert_eq!(runtime.resolver().calls, 0);
    }

    #[test]
    fn read_right_does_not_reach_execute_backend() {
        let (mut runtime, handle, _) = runtime(CapRights::READ);
        let skill = RuvUri::parse(&format!(
            "ruv://example.com/acme/user/alice/skills/tool?rev=sha256:{}",
            "22".repeat(32)
        ))
        .unwrap();
        let request = request(handle, ContextOperation::Execute, skill);
        assert_eq!(
            runtime.authorize_execute(&request),
            Err(ContextError::AccessDenied)
        );
        assert_eq!(runtime.resolver().calls, 0);
    }
}
