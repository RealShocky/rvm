//! Resolver contract and a bounded in-memory conformance implementation.
//!
//! The trait accepts only [`AuthorizedRequest`] values. Their construction is
//! private to this crate and occurs after a live capability check and witness
//! append, making resolver invocation structurally later than authorization.
//! [`MemoryResolver`] is intentionally a deterministic reference backend, not
//! an ANN implementation; production RuVector adapters implement the same
//! contract without treating metadata filters as an authorization boundary.

use crate::capability::{AuthorizedRequest, ContextOperation, MAX_SEARCH_RESULTS};
use crate::error::{ContextError, ContextResult};
use crate::profile::{ProfileTrust, VerifiedContextProfile};
use crate::uri::{PinnedRuvUri, Revision, RuvUri};
use alloc::string::ToString;
use alloc::vec::Vec;
use sha2::{Digest, Sha256};

/// Maximum whole-RVF size accepted by the in-memory conformance resolver.
pub const MAX_RVF_BYTES: usize = 16 * 1024 * 1024;

/// Maximum query size accepted by the in-memory conformance search.
pub const MAX_SEARCH_QUERY_BYTES: usize = 4 * 1024;

/// Maximum entries returned by list, tree, or history enumeration.
pub const MAX_ENUM_RESULTS: usize = 64;

const TOMBSTONE_DOMAIN: &[u8] = b"RUV-CONTEXT-TOMBSTONE-V1";

/// Monotonic generation of one versionless alias.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct AliasGeneration(u64);

impl AliasGeneration {
    /// First generation assigned when an alias is created.
    pub const INITIAL: Self = Self(1);

    /// Construct a nonzero generation.
    #[must_use]
    pub const fn new(value: u64) -> Option<Self> {
        if value == 0 {
            None
        } else {
            Some(Self(value))
        }
    }

    /// Return the numeric generation.
    #[must_use]
    pub const fn get(self) -> u64 {
        self.0
    }

    fn next(self) -> ContextResult<Self> {
        self.0
            .checked_add(1)
            .map(Self)
            .ok_or(ContextError::AliasGenerationExhausted)
    }
}

/// Complete compare-and-swap state of a versionless alias.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AliasSnapshot {
    alias: RuvUri,
    revision: Revision,
    generation: AliasGeneration,
    tombstone: bool,
}

impl AliasSnapshot {
    /// Return the canonical versionless alias.
    #[must_use]
    pub const fn alias(&self) -> &RuvUri {
        &self.alias
    }

    /// Return the immutable revision currently named by the alias.
    #[must_use]
    pub const fn revision(&self) -> Revision {
        self.revision
    }

    /// Return the anti-ABA generation.
    #[must_use]
    pub const fn generation(&self) -> AliasGeneration {
        self.generation
    }

    /// Whether the alias is permanently tombstoned.
    #[must_use]
    pub const fn is_tombstone(&self) -> bool {
        self.tombstone
    }
}

/// Metadata returned after resolving a target to one immutable RVF revision.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolvedContext {
    pinned_uri: PinnedRuvUri,
    revision: Revision,
    alias: Option<AliasSnapshot>,
    rvf_len: usize,
}

impl ResolvedContext {
    /// Return the immutable URI suitable for citations and receipts.
    #[must_use]
    pub const fn pinned_uri(&self) -> &PinnedRuvUri {
        &self.pinned_uri
    }

    /// Return the whole-RVF identity.
    #[must_use]
    pub const fn revision(&self) -> Revision {
        self.revision
    }

    /// Return alias state when a versionless name was resolved.
    #[must_use]
    pub const fn alias(&self) -> Option<&AliasSnapshot> {
        self.alias.as_ref()
    }

    /// Return the immutable RVF byte length without disclosing its bytes.
    #[must_use]
    pub const fn rvf_len(&self) -> usize {
        self.rvf_len
    }
}

/// One bounded result from a governed search.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ContextHit {
    pinned_uri: PinnedRuvUri,
    revision: Revision,
    score: u32,
    alias_generation: Option<AliasGeneration>,
}

impl ContextHit {
    /// Return the immutable result URI.
    #[must_use]
    pub const fn pinned_uri(&self) -> &PinnedRuvUri {
        &self.pinned_uri
    }

    /// Return the whole-RVF identity.
    #[must_use]
    pub const fn revision(&self) -> Revision {
        self.revision
    }

    /// Return the deterministic conformance score.
    #[must_use]
    pub const fn score(&self) -> u32 {
        self.score
    }

    /// Return the alias generation used for an unpinned search result.
    #[must_use]
    pub const fn alias_generation(&self) -> Option<AliasGeneration> {
        self.alias_generation
    }
}

/// Governed resolver operations available to [`crate::ContextRuntime`].
///
/// Every method receives an authorization permit that already binds one actor,
/// operation, and canonical target and records the pre-call witness sequence.
pub trait ContextResolver {
    /// Resolve metadata without returning RVF bytes.
    ///
    /// # Errors
    ///
    /// Returns a resolver error for absent, tombstoned, or inconsistent state.
    fn resolve(&mut self, request: &AuthorizedRequest) -> ContextResult<ResolvedContext>;

    /// List live direct-child aliases below a versionless target.
    ///
    /// # Errors
    ///
    /// Refuses a zero or oversized bound and inconsistent stored state.
    fn list(
        &mut self,
        request: &AuthorizedRequest,
        limit: usize,
    ) -> ContextResult<Vec<ResolvedContext>>;

    /// Enumerate live descendant aliases below a versionless target.
    ///
    /// # Errors
    ///
    /// Refuses a zero or oversized bound and inconsistent stored state.
    fn tree(
        &mut self,
        request: &AuthorizedRequest,
        limit: usize,
    ) -> ContextResult<Vec<ResolvedContext>>;

    /// Read a whole immutable RVF object.
    ///
    /// # Errors
    ///
    /// Returns an error for absent revisions or tombstones. The governed
    /// runtime verifies the profile and releases only the requested view.
    fn read(&mut self, request: &AuthorizedRequest) -> ContextResult<(ResolvedContext, Vec<u8>)>;

    /// Search live alias heads below the authorized target.
    ///
    /// # Errors
    ///
    /// Refuses empty or oversized queries and invalid result bounds.
    fn search(
        &mut self,
        request: &AuthorizedRequest,
        query: &[u8],
        limit: usize,
    ) -> ContextResult<Vec<ContextHit>>;

    /// Enumerate immutable revisions registered under one live alias.
    ///
    /// # Errors
    ///
    /// Refuses absent or tombstoned aliases and invalid result bounds.
    fn history(
        &mut self,
        request: &AuthorizedRequest,
        limit: usize,
    ) -> ContextResult<Vec<ResolvedContext>>;

    /// Re-hash and verify one pinned immutable revision without returning it.
    ///
    /// # Errors
    ///
    /// Refuses absent, tombstoned, forgotten, or corrupt revisions.
    fn verify(&mut self, request: &AuthorizedRequest) -> ContextResult<(ResolvedContext, Vec<u8>)>;

    /// Register runtime-verified immutable bytes under their pinned identity.
    ///
    /// # Errors
    ///
    /// Refuses hash mismatch, conflicting bytes, or capacity exhaustion.
    fn put(&mut self, request: &AuthorizedRequest, rvf: &[u8]) -> ContextResult<ResolvedContext>;

    /// Atomically create or advance one versionless alias.
    ///
    /// `expected = None` means the alias must be absent. Otherwise every field
    /// of the prior snapshot, including generation and revision, must match.
    ///
    /// # Errors
    ///
    /// Refuses stale snapshots, tombstones, missing revisions, and overflow.
    fn compare_and_swap_alias(
        &mut self,
        request: &AuthorizedRequest,
        expected: Option<&AliasSnapshot>,
        next_revision: Revision,
    ) -> ContextResult<AliasSnapshot>;

    /// Permanently advance an alias to a new immutable tombstone revision.
    ///
    /// # Errors
    ///
    /// Refuses a stale snapshot, missing alias, repeat forget, or capacity
    /// exhaustion.
    fn forget(
        &mut self,
        request: &AuthorizedRequest,
        expected: &AliasSnapshot,
    ) -> ContextResult<AliasSnapshot>;

    /// Load a pinned executable revision for internal runtime verification.
    /// The governed runtime returns only an [`crate::ExecutionPermit`] to its
    /// caller and never releases these bytes through the execute path.
    ///
    /// # Errors
    ///
    /// Refuses absent, forgotten, tombstoned, or unpinned targets.
    fn prepare_execute(
        &mut self,
        request: &AuthorizedRequest,
    ) -> ContextResult<(ResolvedContext, Vec<u8>)>;
}

#[derive(Debug, Clone)]
struct StoredObject {
    canonical_uri: RuvUri,
    revision: Revision,
    rvf: Vec<u8>,
    tombstone: bool,
    forgotten: bool,
}

#[derive(Debug, Clone)]
struct StoredAlias {
    snapshot: AliasSnapshot,
}

/// Const-bounded in-memory resolver for conformance tests and local use.
///
/// Objects are keyed by `(logical name, complete-RVF SHA-256 identity)` so
/// identical containers can be registered independently in different tenant
/// scopes without creating a cross-scope existence oracle. Existing bytes are
/// never replaced. Alias state advances only through generation-checked CAS.
#[derive(Debug)]
pub struct MemoryResolver<const OBJECTS: usize = 64, const ALIASES: usize = 64> {
    objects: Vec<StoredObject>,
    aliases: Vec<StoredAlias>,
}

impl<const OBJECTS: usize, const ALIASES: usize> MemoryResolver<OBJECTS, ALIASES> {
    /// Create an empty resolver.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            objects: Vec::new(),
            aliases: Vec::new(),
        }
    }

    /// Return the number of immutable revision records, including tombstones.
    #[must_use]
    pub fn object_count(&self) -> usize {
        self.objects.len()
    }

    /// Return the number of versionless aliases.
    #[must_use]
    pub fn alias_count(&self) -> usize {
        self.aliases.len()
    }

    fn ensure_operation(
        request: &AuthorizedRequest,
        expected: ContextOperation,
    ) -> ContextResult<()> {
        if request.operation() == expected {
            Ok(())
        } else {
            Err(ContextError::OperationMismatch)
        }
    }

    fn object_for(&self, target: &RuvUri, revision: Revision) -> Option<&StoredObject> {
        self.objects.iter().find(|object| {
            object.revision == revision && same_logical_name(&object.canonical_uri, target)
        })
    }

    fn alias_index(&self, target: &RuvUri) -> Option<usize> {
        self.aliases
            .iter()
            .position(|entry| same_logical_name(entry.snapshot.alias(), target))
    }

    fn validate_enumeration_limit(limit: usize) -> ContextResult<()> {
        if limit == 0 || limit > MAX_ENUM_RESULTS {
            Err(ContextError::InvalidResultLimit)
        } else {
            Ok(())
        }
    }

    fn enumerate_aliases(
        &self,
        target: &RuvUri,
        limit: usize,
        recursive: bool,
    ) -> ContextResult<Vec<ResolvedContext>> {
        Self::validate_enumeration_limit(limit)?;
        let mut entries = Vec::new();
        for entry in &self.aliases {
            let snapshot = &entry.snapshot;
            let child_depth = snapshot.alias().path().len();
            let root_depth = target.path().len();
            let is_descendant = child_depth > root_depth && is_within(target, snapshot.alias());
            if snapshot.tombstone || !is_descendant || (!recursive && child_depth != root_depth + 1)
            {
                continue;
            }
            let Some(object) = self.object_for(snapshot.alias(), snapshot.revision) else {
                continue;
            };
            if object.tombstone || object.forgotten {
                continue;
            }
            let pinned = snapshot
                .alias
                .clone()
                .with_revision(snapshot.revision)
                .map_err(|_| ContextError::InvalidTarget)?;
            entries.push(ResolvedContext {
                pinned_uri: pinned,
                revision: snapshot.revision,
                alias: Some(snapshot.clone()),
                rvf_len: object.rvf.len(),
            });
        }
        entries.sort_by(|left, right| left.pinned_uri.cmp(&right.pinned_uri));
        entries.truncate(limit);
        Ok(entries)
    }

    fn score_view(
        object: &StoredObject,
        requested: Option<crate::uri::ProgressiveView>,
        matcher: &QueryMatcher<'_>,
    ) -> ContextResult<u32> {
        let profile = VerifiedContextProfile::from_rvf(
            &object.rvf,
            object.revision,
            ProfileTrust::PinnedIdentity,
            &[],
        )
        .map_err(|_| ContextError::RvfVerificationFailed)?;
        let view = requested.unwrap_or(crate::uri::ProgressiveView::Overview);
        if profile.profile().view(view).is_none() {
            return Ok(0);
        }
        let payload = profile
            .payload(&object.rvf, view)
            .map_err(|_| ContextError::RvfVerificationFailed)?;
        Ok(matcher.occurrence_count(payload))
    }

    fn resolved_for(&self, target: &RuvUri) -> ContextResult<(ResolvedContext, usize)> {
        if let Some(revision) = target.revision() {
            let (index, object) = self
                .objects
                .iter()
                .enumerate()
                .find(|(_, object)| {
                    object.revision == revision && same_logical_name(&object.canonical_uri, target)
                })
                .ok_or(ContextError::RevisionNotFound)?;
            if object.tombstone || object.forgotten {
                return Err(ContextError::Tombstoned);
            }
            let pinned = PinnedRuvUri::try_from(target.clone())
                .map_err(|_| ContextError::PinnedUriRequired)?;
            return Ok((
                ResolvedContext {
                    pinned_uri: pinned,
                    revision,
                    alias: None,
                    rvf_len: object.rvf.len(),
                },
                index,
            ));
        }

        let alias_index = self
            .alias_index(target)
            .ok_or(ContextError::AliasNotFound)?;
        let snapshot = self.aliases[alias_index].snapshot.clone();
        if snapshot.tombstone {
            return Err(ContextError::Tombstoned);
        }
        let (object_index, object) = self
            .objects
            .iter()
            .enumerate()
            .find(|(_, object)| {
                object.revision == snapshot.revision
                    && same_logical_name(&object.canonical_uri, target)
            })
            .ok_or(ContextError::RevisionNotFound)?;
        if object.tombstone || object.forgotten || !same_logical_name(&object.canonical_uri, target)
        {
            return Err(if object.tombstone || object.forgotten {
                ContextError::Tombstoned
            } else {
                ContextError::RevisionConflict
            });
        }
        let pinned = target
            .clone()
            .with_revision(snapshot.revision)
            .map_err(|_| ContextError::InvalidTarget)?;
        Ok((
            ResolvedContext {
                pinned_uri: pinned,
                revision: snapshot.revision,
                alias: Some(snapshot),
                rvf_len: object.rvf.len(),
            },
            object_index,
        ))
    }

    fn insert_tombstone(
        &mut self,
        alias: &RuvUri,
        expected: &AliasSnapshot,
        generation: AliasGeneration,
    ) -> ContextResult<Revision> {
        let mut payload = Vec::new();
        payload.extend_from_slice(TOMBSTONE_DOMAIN);
        payload.push(0);
        payload.extend_from_slice(alias.to_string().as_bytes());
        payload.push(0);
        payload.extend_from_slice(expected.revision.as_bytes());
        payload.extend_from_slice(&generation.get().to_le_bytes());
        let digest = Sha256::digest(&payload);
        let mut bytes = [0u8; 32];
        bytes.copy_from_slice(&digest);
        let revision = Revision::from_bytes(bytes);

        if let Some(existing) = self.object_for(alias, revision) {
            if existing.tombstone && existing.rvf == payload {
                return Ok(revision);
            }
            return Err(ContextError::RevisionConflict);
        }
        if self.objects.len() >= OBJECTS {
            return Err(ContextError::ObjectTableFull);
        }
        self.objects.push(StoredObject {
            canonical_uri: alias.clone(),
            revision,
            rvf: payload,
            tombstone: true,
            forgotten: false,
        });
        Ok(revision)
    }
}

impl<const OBJECTS: usize, const ALIASES: usize> Default for MemoryResolver<OBJECTS, ALIASES> {
    fn default() -> Self {
        Self::new()
    }
}

impl<const OBJECTS: usize, const ALIASES: usize> ContextResolver
    for MemoryResolver<OBJECTS, ALIASES>
{
    fn resolve(&mut self, request: &AuthorizedRequest) -> ContextResult<ResolvedContext> {
        Self::ensure_operation(request, ContextOperation::Resolve)?;
        self.resolved_for(request.target())
            .map(|(resolved, _)| resolved)
    }

    fn list(
        &mut self,
        request: &AuthorizedRequest,
        limit: usize,
    ) -> ContextResult<Vec<ResolvedContext>> {
        Self::ensure_operation(request, ContextOperation::List)?;
        self.enumerate_aliases(request.target(), limit, false)
    }

    fn tree(
        &mut self,
        request: &AuthorizedRequest,
        limit: usize,
    ) -> ContextResult<Vec<ResolvedContext>> {
        Self::ensure_operation(request, ContextOperation::Tree)?;
        self.enumerate_aliases(request.target(), limit, true)
    }

    fn read(&mut self, request: &AuthorizedRequest) -> ContextResult<(ResolvedContext, Vec<u8>)> {
        Self::ensure_operation(request, ContextOperation::Read)?;
        let (resolved, object_index) = self.resolved_for(request.target())?;
        Ok((resolved, self.objects[object_index].rvf.clone()))
    }

    fn search(
        &mut self,
        request: &AuthorizedRequest,
        query: &[u8],
        limit: usize,
    ) -> ContextResult<Vec<ContextHit>> {
        Self::ensure_operation(request, ContextOperation::Search)?;
        if query.is_empty() || query.len() > MAX_SEARCH_QUERY_BYTES {
            return Err(ContextError::InvalidQuery);
        }
        if limit == 0 || limit > MAX_SEARCH_RESULTS {
            return Err(ContextError::InvalidResultLimit);
        }

        let matcher = QueryMatcher::new(query);
        let mut hits = Vec::with_capacity(limit);
        if let Some(revision) = request.target().revision() {
            if let Some(object) = self.object_for(request.target(), revision) {
                if !object.tombstone
                    && !object.forgotten
                    && same_logical_name(&object.canonical_uri, request.target())
                {
                    let score = Self::score_view(object, request.target().view(), &matcher)?;
                    if score > 0 {
                        let pinned = PinnedRuvUri::try_from(request.target().clone())
                            .map_err(|_| ContextError::PinnedUriRequired)?;
                        push_top_hit(
                            &mut hits,
                            limit,
                            ContextHit {
                                pinned_uri: pinned,
                                revision,
                                score,
                                alias_generation: None,
                            },
                        );
                    }
                }
            }
        } else {
            for entry in &self.aliases {
                let snapshot = &entry.snapshot;
                if snapshot.tombstone || !is_within(request.target(), snapshot.alias()) {
                    continue;
                }
                let Some(object) = self.object_for(snapshot.alias(), snapshot.revision) else {
                    continue;
                };
                if object.tombstone || object.forgotten {
                    continue;
                }
                let score = Self::score_view(object, request.target().view(), &matcher)?;
                if score == 0 {
                    continue;
                }
                let pinned = snapshot
                    .alias
                    .clone()
                    .with_revision(snapshot.revision)
                    .map_err(|_| ContextError::InvalidTarget)?;
                push_top_hit(
                    &mut hits,
                    limit,
                    ContextHit {
                        pinned_uri: pinned,
                        revision: snapshot.revision,
                        score,
                        alias_generation: Some(snapshot.generation),
                    },
                );
            }
        }
        hits.sort_by(compare_hits);
        Ok(hits)
    }

    fn history(
        &mut self,
        request: &AuthorizedRequest,
        limit: usize,
    ) -> ContextResult<Vec<ResolvedContext>> {
        Self::ensure_operation(request, ContextOperation::History)?;
        Self::validate_enumeration_limit(limit)?;
        let alias_index = self
            .alias_index(request.target())
            .ok_or(ContextError::AliasNotFound)?;
        if self.aliases[alias_index].snapshot.tombstone {
            return Err(ContextError::Tombstoned);
        }

        let mut entries = Vec::new();
        for object in &self.objects {
            if object.tombstone
                || object.forgotten
                || !same_logical_name(&object.canonical_uri, request.target())
            {
                continue;
            }
            let pinned = request
                .target()
                .clone()
                .with_revision(object.revision)
                .map_err(|_| ContextError::InvalidTarget)?;
            entries.push(ResolvedContext {
                pinned_uri: pinned,
                revision: object.revision,
                alias: None,
                rvf_len: object.rvf.len(),
            });
        }
        entries.sort_by_key(ResolvedContext::revision);
        entries.truncate(limit);
        Ok(entries)
    }

    fn verify(&mut self, request: &AuthorizedRequest) -> ContextResult<(ResolvedContext, Vec<u8>)> {
        Self::ensure_operation(request, ContextOperation::Verify)?;
        let (resolved, object_index) = self.resolved_for(request.target())?;
        let digest = Sha256::digest(&self.objects[object_index].rvf);
        if &digest[..] != resolved.revision.as_bytes() {
            return Err(ContextError::RevisionHashMismatch);
        }
        Ok((resolved, self.objects[object_index].rvf.clone()))
    }

    fn put(&mut self, request: &AuthorizedRequest, rvf: &[u8]) -> ContextResult<ResolvedContext> {
        Self::ensure_operation(request, ContextOperation::Put)?;
        if rvf.len() > MAX_RVF_BYTES {
            return Err(ContextError::ObjectTooLarge);
        }
        let pinned = PinnedRuvUri::try_from(request.target().clone())
            .map_err(|_| ContextError::PinnedUriRequired)?;
        let revision = pinned.revision();
        let digest = Sha256::digest(rvf);
        if digest.as_slice() != revision.as_bytes() {
            return Err(ContextError::RevisionHashMismatch);
        }

        if let Some(existing) = self.object_for(request.target(), revision) {
            if existing.rvf == rvf
                && !existing.tombstone
                && !existing.forgotten
                && same_logical_name(&existing.canonical_uri, request.target())
            {
                return Ok(ResolvedContext {
                    pinned_uri: pinned,
                    revision,
                    alias: None,
                    rvf_len: existing.rvf.len(),
                });
            }
            return Err(ContextError::RevisionConflict);
        }
        if self.objects.len() >= OBJECTS {
            return Err(ContextError::ObjectTableFull);
        }
        self.objects.push(StoredObject {
            canonical_uri: request.target().clone(),
            revision,
            rvf: rvf.to_vec(),
            tombstone: false,
            forgotten: false,
        });
        Ok(ResolvedContext {
            pinned_uri: pinned,
            revision,
            alias: None,
            rvf_len: rvf.len(),
        })
    }

    fn compare_and_swap_alias(
        &mut self,
        request: &AuthorizedRequest,
        expected: Option<&AliasSnapshot>,
        next_revision: Revision,
    ) -> ContextResult<AliasSnapshot> {
        Self::ensure_operation(request, ContextOperation::CompareAndSwapAlias)?;
        if request.target().is_pinned() {
            return Err(ContextError::ImmutableRevision);
        }
        let next = self
            .object_for(request.target(), next_revision)
            .ok_or(ContextError::RevisionNotFound)?;
        if next.tombstone || next.forgotten {
            return Err(ContextError::Tombstoned);
        }
        if !same_logical_name(&next.canonical_uri, request.target()) {
            return Err(ContextError::RevisionConflict);
        }

        if let Some(index) = self.alias_index(request.target()) {
            let current = &self.aliases[index].snapshot;
            if current.tombstone {
                return Err(ContextError::Tombstoned);
            }
            if expected != Some(current) {
                return Err(ContextError::AliasConflict);
            }
            let generation = current.generation.next()?;
            let snapshot = AliasSnapshot {
                alias: request.target().clone(),
                revision: next_revision,
                generation,
                tombstone: false,
            };
            self.aliases[index].snapshot = snapshot.clone();
            return Ok(snapshot);
        }

        if expected.is_some() {
            return Err(ContextError::AliasConflict);
        }
        if self.aliases.len() >= ALIASES {
            return Err(ContextError::AliasTableFull);
        }
        let snapshot = AliasSnapshot {
            alias: request.target().clone(),
            revision: next_revision,
            generation: AliasGeneration::INITIAL,
            tombstone: false,
        };
        self.aliases.push(StoredAlias {
            snapshot: snapshot.clone(),
        });
        Ok(snapshot)
    }

    fn forget(
        &mut self,
        request: &AuthorizedRequest,
        expected: &AliasSnapshot,
    ) -> ContextResult<AliasSnapshot> {
        Self::ensure_operation(request, ContextOperation::Forget)?;
        if request.target().is_pinned() {
            return Err(ContextError::ImmutableRevision);
        }
        let index = self
            .alias_index(request.target())
            .ok_or(ContextError::AliasNotFound)?;
        let current = self.aliases[index].snapshot.clone();
        if current.tombstone {
            return Err(ContextError::Tombstoned);
        }
        if &current != expected {
            return Err(ContextError::AliasConflict);
        }
        let generation = current.generation.next()?;
        let tombstone_revision = self.insert_tombstone(request.target(), expected, generation)?;

        // Make every prior revision of this logical object unreachable while
        // preserving its immutable bytes for a storage layer to key-erase.
        for object in &mut self.objects {
            if !object.tombstone && same_logical_name(&object.canonical_uri, request.target()) {
                object.forgotten = true;
            }
        }
        let snapshot = AliasSnapshot {
            alias: request.target().clone(),
            revision: tombstone_revision,
            generation,
            tombstone: true,
        };
        self.aliases[index].snapshot = snapshot.clone();
        Ok(snapshot)
    }

    fn prepare_execute(
        &mut self,
        request: &AuthorizedRequest,
    ) -> ContextResult<(ResolvedContext, Vec<u8>)> {
        Self::ensure_operation(request, ContextOperation::Execute)?;
        if !request.target().is_pinned() {
            return Err(ContextError::PinnedUriRequired);
        }
        let (resolved, object_index) = self.resolved_for(request.target())?;
        Ok((resolved, self.objects[object_index].rvf.clone()))
    }
}

pub(crate) fn same_logical_name(left: &RuvUri, right: &RuvUri) -> bool {
    left.authority() == right.authority()
        && left.tenant() == right.tenant()
        && left.subject() == right.subject()
        && left.collection() == right.collection()
        && left.path() == right.path()
}

pub(crate) fn is_within(root: &RuvUri, candidate: &RuvUri) -> bool {
    root.authority() == candidate.authority()
        && root.tenant() == candidate.tenant()
        && root.subject() == candidate.subject()
        && root.collection() == candidate.collection()
        && candidate.path().len() >= root.path().len()
        && &candidate.path()[..root.path().len()] == root.path()
}

fn compare_hits(left: &ContextHit, right: &ContextHit) -> core::cmp::Ordering {
    right
        .score
        .cmp(&left.score)
        .then_with(|| left.pinned_uri.cmp(&right.pinned_uri))
}

fn push_top_hit(hits: &mut Vec<ContextHit>, limit: usize, hit: ContextHit) {
    if hits.len() < limit {
        hits.push(hit);
        return;
    }

    let worst_index = hits
        .iter()
        .enumerate()
        .max_by(|(_, left), (_, right)| compare_hits(left, right))
        .map_or(0, |(index, _)| index);
    if compare_hits(&hit, &hits[worst_index]).is_lt() {
        hits[worst_index] = hit;
    }
}

struct QueryMatcher<'a> {
    needle: &'a [u8],
    failure: Vec<usize>,
}

impl<'a> QueryMatcher<'a> {
    fn new(needle: &'a [u8]) -> Self {
        let mut failure = alloc::vec![0; needle.len()];
        let mut matched = 0;
        for index in 1..needle.len() {
            while matched > 0 && needle[index] != needle[matched] {
                matched = failure[matched - 1];
            }
            if needle[index] == needle[matched] {
                matched += 1;
                failure[index] = matched;
            }
        }
        Self { needle, failure }
    }

    fn occurrence_count(&self, haystack: &[u8]) -> u32 {
        if self.needle.is_empty() || haystack.len() < self.needle.len() {
            return 0;
        }

        let mut matched = 0;
        let mut count = 0u32;
        for byte in haystack {
            while matched > 0 && *byte != self.needle[matched] {
                matched = self.failure[matched - 1];
            }
            if *byte == self.needle[matched] {
                matched += 1;
                if matched == self.needle.len() {
                    count = count.saturating_add(1);
                    matched = self.failure[matched - 1];
                }
            }
        }
        count
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::capability::{
        CapabilityHandle, ContextAuthority, ContextRequest, ContextScope, ContextViewMask,
    };
    use crate::profile::{ContextProfile, DerivedView, ProfileView};
    use alloc::format;
    use alloc::vec;
    use rvm_rvf::{
        content_hash, sha256, SegmentHeader, SEGMENT_HEADER_SIZE, SEGMENT_MAGIC, SEGMENT_VERSION,
        SEG_TYPE_PROFILE,
    };
    use rvm_types::{CapRights, PartitionId};
    use rvm_witness::WitnessLog;

    type TestAuthority = ContextAuthority<32, 32>;

    fn alias(path: &str) -> RuvUri {
        RuvUri::parse(&format!(
            "ruv://example.com/acme/agent/reader/resources/{path}"
        ))
        .unwrap()
    }

    fn pinned(alias: &RuvUri, bytes: &[u8]) -> PinnedRuvUri {
        let digest = Sha256::digest(bytes);
        let mut revision = [0u8; 32];
        revision.copy_from_slice(&digest);
        alias
            .clone()
            .with_revision(Revision::from_bytes(revision))
            .unwrap()
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

    fn context_rvf(overview: &[u8], content: &[u8]) -> Vec<u8> {
        let content_revision = Revision::from_bytes(sha256(content));
        let profile = ContextProfile::new(vec![
            ProfileView::content(1, content_revision).unwrap(),
            ProfileView::derived(
                crate::uri::ProgressiveView::Overview,
                2,
                Revision::from_bytes(sha256(overview)),
                DerivedView::new(
                    content_revision,
                    Revision::from_bytes([2; 32]),
                    Revision::from_bytes([3; 32]),
                    Revision::from_bytes([4; 32]),
                    Revision::from_bytes([5; 32]),
                )
                .unwrap(),
            )
            .unwrap(),
        ])
        .unwrap();
        let mut bytes = segment(0x07, 1, content);
        bytes.extend(segment(0x07, 2, overview));
        bytes.extend(segment(SEG_TYPE_PROFILE, 3, &profile.to_bytes()));
        bytes.extend(segment(0x05, 4, b"root"));
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

    fn authority() -> (TestAuthority, CapabilityHandle, PartitionId) {
        let owner = PartitionId::new(9);
        let root = alias("docs");
        let mut authority = TestAuthority::with_defaults();
        let handle = authority
            .issue_root(
                ContextScope::from_uri(&root, ContextViewMask::ALL),
                CapRights::READ | CapRights::WRITE | CapRights::EXECUTE | CapRights::PROVE,
                owner,
                PartitionId::HYPERVISOR,
            )
            .unwrap();
        (authority, handle, owner)
    }

    fn authorized(
        authority: &TestAuthority,
        handle: CapabilityHandle,
        owner: PartitionId,
        operation: ContextOperation,
        target: RuvUri,
        log: &WitnessLog<128>,
    ) -> AuthorizedRequest {
        let request = ContextRequest::new(handle, operation, target);
        authority
            .authorize(owner, 1, &request, operation, log)
            .unwrap()
    }

    #[test]
    fn immutable_put_is_hash_bound_and_idempotent() {
        let (authority, handle, owner) = authority();
        let log = WitnessLog::<128>::new();
        let bytes = b"whole RVF bytes";
        let target = pinned(&alias("docs/a"), bytes);
        let permit = authorized(
            &authority,
            handle,
            owner,
            ContextOperation::Put,
            target.clone().into_uri(),
            &log,
        );
        let mut resolver = MemoryResolver::<4, 4>::new();
        let first = resolver.put(&permit, bytes).unwrap();
        let second = resolver.put(&permit, bytes).unwrap();
        assert_eq!(first, second);
        assert_eq!(resolver.object_count(), 1);
        assert_eq!(
            resolver.put(&permit, b"different"),
            Err(ContextError::RevisionHashMismatch)
        );
    }

    #[test]
    fn identical_revision_is_scoped_by_logical_name_and_tenant() {
        fn tenant_alias(tenant: &str) -> RuvUri {
            RuvUri::parse(&format!(
                "ruv://example.com/{tenant}/agent/reader/resources/docs/a"
            ))
            .unwrap()
        }

        let owner = PartitionId::new(9);
        let mut authority = TestAuthority::with_defaults();
        let mut handles = Vec::new();
        for tenant in ["acme", "beta", "gamma"] {
            let name = tenant_alias(tenant);
            handles.push(
                authority
                    .issue_root(
                        ContextScope::from_uri(&name, ContextViewMask::ALL),
                        CapRights::READ | CapRights::WRITE,
                        owner,
                        PartitionId::HYPERVISOR,
                    )
                    .unwrap(),
            );
        }
        let bytes = b"identical whole RVF bytes";
        let acme = pinned(&tenant_alias("acme"), bytes);
        let beta = pinned(&tenant_alias("beta"), bytes);
        let gamma = pinned(&tenant_alias("gamma"), bytes);
        let log = WitnessLog::<128>::new();
        let mut resolver = MemoryResolver::<8, 4>::new();

        for (handle, target) in [(handles[0], &acme), (handles[1], &beta)] {
            let put = authorized(
                &authority,
                handle,
                owner,
                ContextOperation::Put,
                target.clone().into_uri(),
                &log,
            );
            resolver.put(&put, bytes).unwrap();
        }
        assert_eq!(resolver.object_count(), 2);

        for (handle, target) in [(handles[0], acme), (handles[1], beta)] {
            let resolve = authorized(
                &authority,
                handle,
                owner,
                ContextOperation::Resolve,
                target.into_uri(),
                &log,
            );
            assert!(resolver.resolve(&resolve).is_ok());
        }
        let unregistered_scope = authorized(
            &authority,
            handles[2],
            owner,
            ContextOperation::Resolve,
            gamma.into_uri(),
            &log,
        );
        assert_eq!(
            resolver.resolve(&unregistered_scope),
            Err(ContextError::RevisionNotFound)
        );
    }

    #[test]
    fn alias_cas_generation_prevents_aba() {
        let (authority, handle, owner) = authority();
        let log = WitnessLog::<128>::new();
        let name = alias("docs/a");
        let a_bytes = b"rvf A";
        let b_bytes = b"rvf B";
        let a = pinned(&name, a_bytes);
        let b = pinned(&name, b_bytes);
        let mut resolver = MemoryResolver::<8, 4>::new();
        for (uri, bytes) in [(&a, a_bytes.as_slice()), (&b, b_bytes.as_slice())] {
            let put = authorized(
                &authority,
                handle,
                owner,
                ContextOperation::Put,
                uri.clone().into_uri(),
                &log,
            );
            resolver.put(&put, bytes).unwrap();
        }

        let create = authorized(
            &authority,
            handle,
            owner,
            ContextOperation::CompareAndSwapAlias,
            name.clone(),
            &log,
        );
        let generation_one = resolver
            .compare_and_swap_alias(&create, None, a.revision())
            .unwrap();
        let generation_two = resolver
            .compare_and_swap_alias(&create, Some(&generation_one), b.revision())
            .unwrap();
        let generation_three = resolver
            .compare_and_swap_alias(&create, Some(&generation_two), a.revision())
            .unwrap();
        assert_eq!(generation_three.generation().get(), 3);
        assert_eq!(
            resolver.compare_and_swap_alias(&create, Some(&generation_one), b.revision()),
            Err(ContextError::AliasConflict)
        );
    }

    #[test]
    fn exactly_one_competing_cas_snapshot_wins() {
        let (authority, handle, owner) = authority();
        let log = WitnessLog::<128>::new();
        let name = alias("docs/a");
        let one = pinned(&name, b"one");
        let two = pinned(&name, b"two");
        let three = pinned(&name, b"three");
        let mut resolver = MemoryResolver::<8, 4>::new();
        for (uri, bytes) in [
            (&one, b"one".as_slice()),
            (&two, b"two".as_slice()),
            (&three, b"three".as_slice()),
        ] {
            let put = authorized(
                &authority,
                handle,
                owner,
                ContextOperation::Put,
                uri.clone().into_uri(),
                &log,
            );
            resolver.put(&put, bytes).unwrap();
        }
        let cas = authorized(
            &authority,
            handle,
            owner,
            ContextOperation::CompareAndSwapAlias,
            name,
            &log,
        );
        let initial = resolver
            .compare_and_swap_alias(&cas, None, one.revision())
            .unwrap();
        assert!(resolver
            .compare_and_swap_alias(&cas, Some(&initial), two.revision())
            .is_ok());
        assert_eq!(
            resolver.compare_and_swap_alias(&cas, Some(&initial), three.revision()),
            Err(ContextError::AliasConflict)
        );
    }

    #[test]
    fn list_tree_history_and_verify_are_bounded_and_revision_bound() {
        let (authority, handle, owner) = authority();
        let log = WitnessLog::<128>::new();
        let direct_name = alias("docs/a");
        let deep_name = alias("docs/a/deep");
        let first = pinned(&direct_name, b"first");
        let second = pinned(&direct_name, b"second");
        let deep = pinned(&deep_name, b"deep");
        let mut resolver = MemoryResolver::<8, 4>::new();
        for (target, bytes) in [
            (&first, b"first".as_slice()),
            (&second, b"second".as_slice()),
            (&deep, b"deep".as_slice()),
        ] {
            let put = authorized(
                &authority,
                handle,
                owner,
                ContextOperation::Put,
                target.clone().into_uri(),
                &log,
            );
            resolver.put(&put, bytes).unwrap();
        }

        let direct_cas = authorized(
            &authority,
            handle,
            owner,
            ContextOperation::CompareAndSwapAlias,
            direct_name.clone(),
            &log,
        );
        let first_head = resolver
            .compare_and_swap_alias(&direct_cas, None, first.revision())
            .unwrap();
        resolver
            .compare_and_swap_alias(&direct_cas, Some(&first_head), second.revision())
            .unwrap();
        let deep_cas = authorized(
            &authority,
            handle,
            owner,
            ContextOperation::CompareAndSwapAlias,
            deep_name,
            &log,
        );
        resolver
            .compare_and_swap_alias(&deep_cas, None, deep.revision())
            .unwrap();

        let list = authorized(
            &authority,
            handle,
            owner,
            ContextOperation::List,
            alias("docs"),
            &log,
        );
        assert_eq!(resolver.list(&list, 8).unwrap().len(), 1);
        let tree = authorized(
            &authority,
            handle,
            owner,
            ContextOperation::Tree,
            alias("docs"),
            &log,
        );
        assert_eq!(resolver.tree(&tree, 8).unwrap().len(), 2);
        assert_eq!(
            resolver.tree(&tree, MAX_ENUM_RESULTS + 1),
            Err(ContextError::InvalidResultLimit)
        );

        let history = authorized(
            &authority,
            handle,
            owner,
            ContextOperation::History,
            direct_name,
            &log,
        );
        assert_eq!(resolver.history(&history, 8).unwrap().len(), 2);

        let verify = authorized(
            &authority,
            handle,
            owner,
            ContextOperation::Verify,
            second.clone().into_uri(),
            &log,
        );
        let (verified, bytes) = resolver.verify(&verify).unwrap();
        assert_eq!(verified.revision(), second.revision());
        assert_eq!(bytes, b"second");
    }

    #[test]
    fn forget_creates_new_tombstone_and_hides_pinned_history() {
        let (authority, handle, owner) = authority();
        let log = WitnessLog::<128>::new();
        let name = alias("docs/a");
        let object = pinned(&name, b"private");
        let mut resolver = MemoryResolver::<8, 4>::new();
        let put = authorized(
            &authority,
            handle,
            owner,
            ContextOperation::Put,
            object.clone().into_uri(),
            &log,
        );
        resolver.put(&put, b"private").unwrap();
        let cas = authorized(
            &authority,
            handle,
            owner,
            ContextOperation::CompareAndSwapAlias,
            name.clone(),
            &log,
        );
        let head = resolver
            .compare_and_swap_alias(&cas, None, object.revision())
            .unwrap();
        let forget = authorized(
            &authority,
            handle,
            owner,
            ContextOperation::Forget,
            name.clone(),
            &log,
        );
        let tombstone = resolver.forget(&forget, &head).unwrap();
        assert!(tombstone.is_tombstone());
        assert_ne!(tombstone.revision(), head.revision());

        let resolve_alias = authorized(
            &authority,
            handle,
            owner,
            ContextOperation::Resolve,
            name,
            &log,
        );
        assert_eq!(
            resolver.resolve(&resolve_alias),
            Err(ContextError::Tombstoned)
        );
        let read_old = authorized(
            &authority,
            handle,
            owner,
            ContextOperation::Read,
            object.into_uri(),
            &log,
        );
        assert_eq!(resolver.read(&read_old), Err(ContextError::Tombstoned));
    }

    #[test]
    fn search_enumerates_only_live_descendant_aliases_and_is_bounded() {
        let (authority, handle, owner) = authority();
        let log = WitnessLog::<128>::new();
        let name = alias("docs/a");
        let bytes = context_rvf(b"alpha alpha beta", b"content-only secret");
        let object = pinned(&name, &bytes);
        let mut resolver = MemoryResolver::<8, 4>::new();
        let put = authorized(
            &authority,
            handle,
            owner,
            ContextOperation::Put,
            object.clone().into_uri(),
            &log,
        );
        resolver.put(&put, &bytes).unwrap();
        let cas = authorized(
            &authority,
            handle,
            owner,
            ContextOperation::CompareAndSwapAlias,
            name,
            &log,
        );
        resolver
            .compare_and_swap_alias(&cas, None, object.revision())
            .unwrap();

        let content_only_name = alias("docs/b");
        let content_only_bytes = content_only_rvf(b"content-only alpha");
        let content_only_object = pinned(&content_only_name, &content_only_bytes);
        let content_only_put = authorized(
            &authority,
            handle,
            owner,
            ContextOperation::Put,
            content_only_object.clone().into_uri(),
            &log,
        );
        resolver
            .put(&content_only_put, &content_only_bytes)
            .unwrap();
        let content_only_cas = authorized(
            &authority,
            handle,
            owner,
            ContextOperation::CompareAndSwapAlias,
            content_only_name,
            &log,
        );
        resolver
            .compare_and_swap_alias(&content_only_cas, None, content_only_object.revision())
            .unwrap();

        let search = authorized(
            &authority,
            handle,
            owner,
            ContextOperation::Search,
            alias("docs"),
            &log,
        );
        let hits = resolver.search(&search, b"alpha", 4).unwrap();
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].score(), 2);
        assert!(resolver
            .search(&search, b"content-only", 4)
            .unwrap()
            .is_empty());

        let content_search = authorized(
            &authority,
            handle,
            owner,
            ContextOperation::Search,
            RuvUri::parse("ruv://example.com/acme/agent/reader/resources/docs?view=content")
                .unwrap(),
            &log,
        );
        assert_eq!(
            resolver
                .search(&content_search, b"secret", 4)
                .unwrap()
                .len(),
            1
        );
        assert_eq!(
            resolver.search(&search, b"alpha", MAX_SEARCH_RESULTS + 1),
            Err(ContextError::InvalidResultLimit)
        );
    }

    #[test]
    fn search_applies_limit_after_global_score_ordering() {
        let (authority, handle, owner) = authority();
        let log = WitnessLog::<128>::new();
        let mut resolver = MemoryResolver::<8, 4>::new();

        let low_name = alias("docs/first");
        let low_bytes = context_rvf(b"needle", b"low content");
        let low_object = pinned(&low_name, &low_bytes);
        let low_put = authorized(
            &authority,
            handle,
            owner,
            ContextOperation::Put,
            low_object.clone().into_uri(),
            &log,
        );
        resolver.put(&low_put, &low_bytes).unwrap();
        let low_cas = authorized(
            &authority,
            handle,
            owner,
            ContextOperation::CompareAndSwapAlias,
            low_name,
            &log,
        );
        resolver
            .compare_and_swap_alias(&low_cas, None, low_object.revision())
            .unwrap();

        let high_name = alias("docs/second");
        let high_bytes = context_rvf(b"needle needle needle", b"high content");
        let high_object = pinned(&high_name, &high_bytes);
        let high_put = authorized(
            &authority,
            handle,
            owner,
            ContextOperation::Put,
            high_object.clone().into_uri(),
            &log,
        );
        resolver.put(&high_put, &high_bytes).unwrap();
        let high_cas = authorized(
            &authority,
            handle,
            owner,
            ContextOperation::CompareAndSwapAlias,
            high_name,
            &log,
        );
        resolver
            .compare_and_swap_alias(&high_cas, None, high_object.revision())
            .unwrap();

        let search = authorized(
            &authority,
            handle,
            owner,
            ContextOperation::Search,
            alias("docs"),
            &log,
        );
        let hits = resolver.search(&search, b"needle", 1).unwrap();
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].pinned_uri(), &high_object);
        assert_eq!(hits[0].score(), 3);
    }

    #[test]
    fn query_matcher_is_linear_and_preserves_overlapping_scores() {
        let matcher = QueryMatcher::new(b"aaa");
        assert_eq!(matcher.occurrence_count(b"aaaaa"), 3);
        assert_eq!(matcher.occurrence_count(b"aa"), 0);
        assert_eq!(QueryMatcher::new(b"aba").occurrence_count(b"abababa"), 3);
    }
}
