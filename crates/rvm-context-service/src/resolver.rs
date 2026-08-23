//! Durable [`rvm_context::ContextResolver`] implementation.

use crate::active_index::ActiveIndex;
use crate::crypto::EncryptedObject;
use crate::embed::checked_embedding;
use crate::store::{
    decode_alias, encode_alias, logical_key, parse_pinned, point_id, IndexJob, Store, ALIASES,
    INDEX_JOBS, OBJECTS, PURGE_JOBS,
};
use crate::{ContextEmbedder, DataKeyProvider, ServiceError, ServiceResult};
use redb::{ReadableTable, ReadableTableMetadata};
use rvm_context::{
    AliasGeneration, AliasSnapshot, AuthorizedRequest, ContextError, ContextHit, ContextOperation,
    ContextResolver, ContextResult, PinnedRuvUri, ProfileTrust, ProgressiveView, ResolvedContext,
    Revision, RuvUri, VerifiedContextProfile, MAX_ENUM_RESULTS, MAX_RVF_BYTES,
    MAX_SEARCH_QUERY_BYTES, MAX_SEARCH_RESULTS,
};
use sha2::{Digest, Sha256};
use std::path::Path;
use std::sync::Arc;

const TOMBSTONE_DOMAIN: &[u8] = b"RUV-CONTEXT-TOMBSTONE-V1";

/// Resource ceilings for one hosted resolver instance.
#[derive(Debug, Clone, Copy)]
pub struct ResolverOptions {
    /// Maximum immutable encrypted objects retained across all tenants.
    pub max_objects: u64,
    /// Maximum versionless aliases retained across all tenants.
    pub max_aliases: u64,
    /// Maximum exact vector scopes opened or created.
    pub max_scopes: usize,
    /// Maximum descendant vector shards touched by one search.
    pub max_search_shards: usize,
}

impl Default for ResolverOptions {
    fn default() -> Self {
        Self {
            max_objects: 100_000,
            max_aliases: 25_000,
            max_scopes: 25_000,
            max_search_shards: 256,
        }
    }
}

/// Replica and cache invalidation boundary invoked from a durable outbox.
pub trait PurgeSink: Send + Sync {
    /// Purge all cached, replicated, and derived state for one logical alias.
    ///
    /// # Errors
    ///
    /// Returns an error when any required replica or cache cannot confirm the
    /// purge. The durable outbox retains the job for retry in that case.
    fn purge(&self, logical_uri: &RuvUri) -> ServiceResult<()>;
}

/// Purge sink for deployments without external replicas or caches.
#[derive(Debug, Clone, Copy, Default)]
pub struct NoopPurgeSink;

impl PurgeSink for NoopPurgeSink {
    fn purge(&self, _logical_uri: &RuvUri) -> ServiceResult<()> {
        Ok(())
    }
}

/// Encrypted REDB resolver with an isolated RuVector active-alias index.
pub struct PersistentContextResolver {
    store: Store,
    active_index: ActiveIndex,
    keys: Arc<dyn DataKeyProvider>,
    embedder: Arc<dyn ContextEmbedder>,
    purge_sink: Arc<dyn PurgeSink>,
    options: ResolverOptions,
}

impl PersistentContextResolver {
    /// Open or create all durable service state below `root`.
    ///
    /// Pending vector jobs are replayed before the resolver is returned.
    ///
    /// # Errors
    ///
    /// Refuses invalid limits, storage failures, corrupt outbox state, and an
    /// embedding/vector dimension mismatch.
    pub fn open(
        root: impl AsRef<Path>,
        options: ResolverOptions,
        keys: Arc<dyn DataKeyProvider>,
        embedder: Arc<dyn ContextEmbedder>,
        purge_sink: Arc<dyn PurgeSink>,
    ) -> ServiceResult<Self> {
        if options.max_objects == 0
            || options.max_aliases == 0
            || options.max_scopes == 0
            || options.max_search_shards == 0
            || embedder.dimensions() == 0
        {
            return Err(ServiceError::CorruptState("invalid resolver limits"));
        }
        let root = root.as_ref();
        std::fs::create_dir_all(root)?;
        let store = Store::open(root.join("context.redb"))?;
        let active_index = ActiveIndex::open(
            root.join("active-index"),
            embedder.dimensions(),
            options.max_scopes,
            options.max_search_shards,
            MAX_SEARCH_RESULTS,
        )?;
        let mut resolver = Self {
            store,
            active_index,
            keys,
            embedder,
            purge_sink,
            options,
        };
        resolver.drain_index_jobs()?;
        let _ = resolver.drain_purge_jobs();
        Ok(resolver)
    }

    /// Replay vector-index and replica/cache purge outboxes.
    ///
    /// Source-of-truth mutations stay committed when an external sink is
    /// unavailable; this method can be retried until every job is removed.
    ///
    /// # Errors
    ///
    /// Returns the first backend or corrupt-state failure without deleting its
    /// durable job.
    pub fn maintenance(&mut self) -> ServiceResult<()> {
        self.drain_index_jobs()?;
        self.drain_purge_jobs()
    }

    /// Number of vector jobs waiting for replay.
    ///
    /// # Errors
    ///
    /// Returns a database error when the outbox cannot be read.
    pub fn pending_index_jobs(&self) -> ServiceResult<u64> {
        let transaction = self.store.db.begin_read().map_err(ServiceError::database)?;
        let table = transaction
            .open_table(INDEX_JOBS)
            .map_err(ServiceError::database)?;
        table.len().map_err(ServiceError::database)
    }

    /// Number of cache/replica purge jobs waiting for replay.
    ///
    /// # Errors
    ///
    /// Returns a database error when the outbox cannot be read.
    pub fn pending_purge_jobs(&self) -> ServiceResult<u64> {
        let transaction = self.store.db.begin_read().map_err(ServiceError::database)?;
        let table = transaction
            .open_table(PURGE_JOBS)
            .map_err(ServiceError::database)?;
        table.len().map_err(ServiceError::database)
    }

    /// Number of encrypted immutable objects in the source-of-truth store.
    ///
    /// # Errors
    ///
    /// Returns a database error when the object table cannot be read.
    pub fn object_count(&self) -> ServiceResult<u64> {
        let transaction = self.store.db.begin_read().map_err(ServiceError::database)?;
        let table = transaction
            .open_table(OBJECTS)
            .map_err(ServiceError::database)?;
        table.len().map_err(ServiceError::database)
    }

    /// Number of live or tombstoned logical aliases retained for CAS safety.
    ///
    /// # Errors
    ///
    /// Returns a database error when the alias table cannot be read.
    pub fn alias_count(&self) -> ServiceResult<u64> {
        let transaction = self.store.db.begin_read().map_err(ServiceError::database)?;
        let table = transaction
            .open_table(ALIASES)
            .map_err(ServiceError::database)?;
        table.len().map_err(ServiceError::database)
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

    fn alias_snapshot(&self, target: &RuvUri) -> ServiceResult<Option<AliasSnapshot>> {
        let key = logical_key(target);
        let transaction = self.store.db.begin_read().map_err(ServiceError::database)?;
        let table = transaction
            .open_table(ALIASES)
            .map_err(ServiceError::database)?;
        table
            .get(key.as_str())
            .map_err(ServiceError::database)?
            .map(|value| {
                let alias = RuvUri::parse(&key)
                    .map_err(|_| ServiceError::CorruptState("stored alias URI is invalid"))?;
                decode_alias(alias, value.value())
            })
            .transpose()
    }

    fn read_object(&self, pinned: &PinnedRuvUri) -> ServiceResult<Option<Vec<u8>>> {
        let key = pinned.to_string();
        let transaction = self.store.db.begin_read().map_err(ServiceError::database)?;
        let table = transaction
            .open_table(OBJECTS)
            .map_err(ServiceError::database)?;
        let envelope = table
            .get(key.as_str())
            .map_err(ServiceError::database)?
            .map(|value| value.value().to_vec());
        envelope
            .map(|bytes| {
                EncryptedObject::decode(&bytes)?.open(
                    self.keys.as_ref(),
                    pinned.as_uri().tenant().as_str(),
                    key.as_bytes(),
                )
            })
            .transpose()
    }

    fn resolved_for(&self, target: &RuvUri) -> ContextResult<(ResolvedContext, Vec<u8>)> {
        let (pinned, alias) = if target.revision().is_some() {
            (
                PinnedRuvUri::try_from(target.clone())
                    .map_err(|_| ContextError::PinnedUriRequired)?,
                None,
            )
        } else {
            let snapshot =
                backend(self.alias_snapshot(target))?.ok_or(ContextError::AliasNotFound)?;
            if snapshot.is_tombstone() {
                return Err(ContextError::Tombstoned);
            }
            let pinned = target
                .clone()
                .with_revision(snapshot.revision())
                .map_err(|_| ContextError::InvalidTarget)?;
            (pinned, Some(snapshot))
        };
        let bytes = backend(self.read_object(&pinned))?.ok_or(ContextError::RevisionNotFound)?;
        let revision = pinned.revision();
        let resolved = ResolvedContext::new(pinned, revision, alias, bytes.len())?;
        Ok((resolved, bytes))
    }

    fn enumerate(
        &self,
        root: &RuvUri,
        limit: usize,
        recursive: bool,
    ) -> ContextResult<Vec<ResolvedContext>> {
        if limit == 0 || limit > MAX_ENUM_RESULTS {
            return Err(ContextError::InvalidResultLimit);
        }
        let snapshots = backend(self.all_aliases())?;
        let mut resolved = Vec::with_capacity(limit);
        for snapshot in snapshots {
            let child_depth = snapshot.alias().path().len();
            let root_depth = root.path().len();
            if snapshot.is_tombstone()
                || child_depth <= root_depth
                || !is_within(root, snapshot.alias())
                || (!recursive && child_depth != root_depth + 1)
            {
                continue;
            }
            let pinned = snapshot
                .alias()
                .clone()
                .with_revision(snapshot.revision())
                .map_err(|_| ContextError::InvalidTarget)?;
            let bytes =
                backend(self.read_object(&pinned))?.ok_or(ContextError::RevisionNotFound)?;
            resolved.push(ResolvedContext::new(
                pinned,
                snapshot.revision(),
                Some(snapshot),
                bytes.len(),
            )?);
            if resolved.len() == limit {
                break;
            }
        }
        resolved.sort_by(|left, right| left.pinned_uri().cmp(right.pinned_uri()));
        Ok(resolved)
    }

    fn all_aliases(&self) -> ServiceResult<Vec<AliasSnapshot>> {
        let transaction = self.store.db.begin_read().map_err(ServiceError::database)?;
        let table = transaction
            .open_table(ALIASES)
            .map_err(ServiceError::database)?;
        let mut aliases = Vec::new();
        for entry in table.iter().map_err(ServiceError::database)? {
            let (key, value) = entry.map_err(ServiceError::database)?;
            let alias = RuvUri::parse(key.value())
                .map_err(|_| ServiceError::CorruptState("stored alias URI is invalid"))?;
            aliases.push(decode_alias(alias, value.value())?);
        }
        aliases.sort_by(|left, right| left.alias().cmp(right.alias()));
        Ok(aliases)
    }

    fn compile_active_vector(&self, revision: Revision, rvf: &[u8]) -> ServiceResult<Vec<f32>> {
        let profile =
            VerifiedContextProfile::from_rvf(rvf, revision, ProfileTrust::PinnedIdentity, &[])
                .map_err(|_| ServiceError::CorruptState("stored RVF profile is invalid"))?;
        let view = if profile.profile().view(ProgressiveView::Overview).is_some() {
            ProgressiveView::Overview
        } else {
            ProgressiveView::Content
        };
        let payload = profile
            .payload(rvf, view)
            .map_err(|_| ServiceError::CorruptState("RVF overview is invalid"))?;
        checked_embedding(self.embedder.as_ref(), payload)
    }

    fn drain_index_jobs(&mut self) -> ServiceResult<()> {
        let jobs = {
            let transaction = self.store.db.begin_read().map_err(ServiceError::database)?;
            let table = transaction
                .open_table(INDEX_JOBS)
                .map_err(ServiceError::database)?;
            let mut jobs = Vec::new();
            for entry in table.iter().map_err(ServiceError::database)? {
                let (key, value) = entry.map_err(ServiceError::database)?;
                jobs.push((key.value().to_owned(), value.value().to_vec()));
            }
            jobs
        };
        for (key, bytes) in jobs {
            let alias = RuvUri::parse(&key)
                .map_err(|_| ServiceError::CorruptState("index job alias is invalid"))?;
            let job = IndexJob::decode(&bytes)?;
            self.active_index.apply(&alias, &job)?;
            self.remove_job_if_unchanged(INDEX_JOBS, &key, &bytes)?;
        }
        Ok(())
    }

    fn drain_purge_jobs(&mut self) -> ServiceResult<()> {
        let jobs = {
            let transaction = self.store.db.begin_read().map_err(ServiceError::database)?;
            let table = transaction
                .open_table(PURGE_JOBS)
                .map_err(ServiceError::database)?;
            let mut jobs = Vec::new();
            for entry in table.iter().map_err(ServiceError::database)? {
                let (key, value) = entry.map_err(ServiceError::database)?;
                jobs.push((key.value().to_owned(), value.value().to_vec()));
            }
            jobs
        };
        for (key, bytes) in jobs {
            let alias = RuvUri::parse(&key)
                .map_err(|_| ServiceError::CorruptState("purge job alias is invalid"))?;
            self.purge_sink.purge(&alias)?;
            self.remove_job_if_unchanged(PURGE_JOBS, &key, &bytes)?;
        }
        Ok(())
    }

    fn remove_job_if_unchanged(
        &self,
        definition: redb::TableDefinition<&str, &[u8]>,
        key: &str,
        expected: &[u8],
    ) -> ServiceResult<()> {
        let transaction = self
            .store
            .db
            .begin_write()
            .map_err(ServiceError::database)?;
        {
            let mut table = transaction
                .open_table(definition)
                .map_err(ServiceError::database)?;
            let unchanged = table
                .get(key)
                .map_err(ServiceError::database)?
                .is_some_and(|value| value.value() == expected);
            if unchanged {
                let _ = table.remove(key).map_err(ServiceError::database)?;
            }
        }
        transaction.commit().map_err(ServiceError::database)
    }
}

impl ContextResolver for PersistentContextResolver {
    fn resolve(&mut self, request: &AuthorizedRequest) -> ContextResult<ResolvedContext> {
        Self::ensure_operation(request, ContextOperation::Resolve)?;
        self.resolved_for(request.target()).map(|value| value.0)
    }

    fn list(
        &mut self,
        request: &AuthorizedRequest,
        limit: usize,
    ) -> ContextResult<Vec<ResolvedContext>> {
        Self::ensure_operation(request, ContextOperation::List)?;
        self.enumerate(request.target(), limit, false)
    }

    fn tree(
        &mut self,
        request: &AuthorizedRequest,
        limit: usize,
    ) -> ContextResult<Vec<ResolvedContext>> {
        Self::ensure_operation(request, ContextOperation::Tree)?;
        self.enumerate(request.target(), limit, true)
    }

    fn read(&mut self, request: &AuthorizedRequest) -> ContextResult<(ResolvedContext, Vec<u8>)> {
        Self::ensure_operation(request, ContextOperation::Read)?;
        self.resolved_for(request.target())
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
        backend(self.drain_index_jobs())?;
        let query_vector = backend(checked_embedding(self.embedder.as_ref(), query))?;
        if request.target().is_pinned() {
            let (resolved, rvf) = self.resolved_for(request.target())?;
            let document_vector = backend(self.compile_active_vector(resolved.revision(), &rvf))?;
            let score = score_vectors(&query_vector, &document_vector)?;
            return Ok(vec![ContextHit::new(
                resolved.pinned_uri().clone(),
                resolved.revision(),
                score,
                None,
            )?]);
        }
        let matches = backend(
            self.active_index
                .search(request.target(), &query_vector, limit),
        )?;
        let mut hits = Vec::with_capacity(matches.len());
        for item in matches {
            if !is_within(request.target(), &item.alias) {
                return Err(ContextError::ResolverScopeViolation);
            }
            let Some(snapshot) = backend(self.alias_snapshot(&item.alias))? else {
                continue;
            };
            if snapshot.is_tombstone() {
                continue;
            }
            let pinned = snapshot
                .alias()
                .clone()
                .with_revision(snapshot.revision())
                .map_err(|_| ContextError::InvalidTarget)?;
            if item.point_id != point_id(&pinned) {
                return Err(ContextError::BackendUnavailable);
            }
            hits.push(ContextHit::new(
                pinned,
                snapshot.revision(),
                score_distance(item.distance),
                Some(snapshot.generation()),
            )?);
        }
        Ok(hits)
    }

    fn history(
        &mut self,
        request: &AuthorizedRequest,
        limit: usize,
    ) -> ContextResult<Vec<ResolvedContext>> {
        Self::ensure_operation(request, ContextOperation::History)?;
        if limit == 0 || limit > MAX_ENUM_RESULTS {
            return Err(ContextError::InvalidResultLimit);
        }
        let snapshot =
            backend(self.alias_snapshot(request.target()))?.ok_or(ContextError::AliasNotFound)?;
        if snapshot.is_tombstone() {
            return Err(ContextError::Tombstoned);
        }
        let logical = logical_key(request.target());
        let keys = backend(self.object_keys_for(&logical))?;
        let mut resolved = Vec::with_capacity(limit);
        for key in keys.into_iter().take(limit) {
            let pinned = backend(parse_pinned(&key))?;
            let bytes =
                backend(self.read_object(&pinned))?.ok_or(ContextError::RevisionNotFound)?;
            resolved.push(ResolvedContext::new(
                pinned.clone(),
                pinned.revision(),
                None,
                bytes.len(),
            )?);
        }
        resolved.sort_by_key(ResolvedContext::revision);
        Ok(resolved)
    }

    fn verify(&mut self, request: &AuthorizedRequest) -> ContextResult<(ResolvedContext, Vec<u8>)> {
        Self::ensure_operation(request, ContextOperation::Verify)?;
        let (resolved, rvf) = self.resolved_for(request.target())?;
        if Sha256::digest(&rvf).as_slice() != resolved.revision().as_bytes() {
            return Err(ContextError::RevisionHashMismatch);
        }
        Ok((resolved, rvf))
    }

    fn put(&mut self, request: &AuthorizedRequest, rvf: &[u8]) -> ContextResult<ResolvedContext> {
        Self::ensure_operation(request, ContextOperation::Put)?;
        if rvf.len() > MAX_RVF_BYTES {
            return Err(ContextError::ObjectTooLarge);
        }
        let pinned = PinnedRuvUri::try_from(request.target().clone())
            .map_err(|_| ContextError::PinnedUriRequired)?;
        if Sha256::digest(rvf).as_slice() != pinned.revision().as_bytes() {
            return Err(ContextError::RevisionHashMismatch);
        }
        let key = pinned.to_string();
        if let Some(existing) = backend(self.read_object(&pinned))? {
            if existing == rvf {
                return ResolvedContext::new(pinned.clone(), pinned.revision(), None, rvf.len());
            }
            return Err(ContextError::RevisionConflict);
        }
        let envelope = backend(EncryptedObject::seal(
            self.keys.as_ref(),
            request.target().tenant().as_str(),
            key.as_bytes(),
            rvf,
        ))?;
        let encoded = backend(envelope.encode())?;
        let transaction = backend(self.store.db.begin_write().map_err(ServiceError::database))?;
        {
            let mut objects = backend(
                transaction
                    .open_table(OBJECTS)
                    .map_err(ServiceError::database),
            )?;
            if objects
                .len()
                .map_err(|_| ContextError::BackendUnavailable)?
                >= self.options.max_objects
            {
                return Err(ContextError::ObjectTableFull);
            }
            if objects
                .get(key.as_str())
                .map_err(|_| ContextError::BackendUnavailable)?
                .is_some()
            {
                return Err(ContextError::RevisionConflict);
            }
            objects
                .insert(key.as_str(), encoded.as_slice())
                .map_err(|_| ContextError::BackendUnavailable)?;
        }
        transaction
            .commit()
            .map_err(|_| ContextError::BackendUnavailable)?;
        ResolvedContext::new(pinned.clone(), pinned.revision(), None, rvf.len())
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
        let pinned = request
            .target()
            .clone()
            .with_revision(next_revision)
            .map_err(|_| ContextError::InvalidTarget)?;
        let rvf = backend(self.read_object(&pinned))?.ok_or(ContextError::RevisionNotFound)?;
        let vector = backend(self.compile_active_vector(next_revision, &rvf))?;
        let logical = logical_key(request.target());
        let job = backend(
            IndexJob::Upsert {
                pinned: pinned.clone(),
                vector,
            }
            .encode(),
        )?;
        let transaction = self
            .store
            .db
            .begin_write()
            .map_err(|_| ContextError::BackendUnavailable)?;
        let snapshot;
        {
            let objects = transaction
                .open_table(OBJECTS)
                .map_err(|_| ContextError::BackendUnavailable)?;
            if objects
                .get(pinned.to_string().as_str())
                .map_err(|_| ContextError::BackendUnavailable)?
                .is_none()
            {
                return Err(ContextError::RevisionNotFound);
            }
            let mut aliases = transaction
                .open_table(ALIASES)
                .map_err(|_| ContextError::BackendUnavailable)?;
            let current_bytes = aliases
                .get(logical.as_str())
                .map_err(|_| ContextError::BackendUnavailable)?
                .map(|value| value.value().to_vec());
            snapshot = if let Some(bytes) = current_bytes {
                let current = backend(decode_alias(request.target().clone(), &bytes))?;
                if current.is_tombstone() {
                    return Err(ContextError::Tombstoned);
                }
                if expected != Some(&current) {
                    return Err(ContextError::AliasConflict);
                }
                AliasSnapshot::new(
                    request.target().clone(),
                    next_revision,
                    current.generation().checked_next()?,
                    false,
                )?
            } else {
                if expected.is_some() {
                    return Err(ContextError::AliasConflict);
                }
                if aliases
                    .len()
                    .map_err(|_| ContextError::BackendUnavailable)?
                    >= self.options.max_aliases
                {
                    return Err(ContextError::AliasTableFull);
                }
                AliasSnapshot::new(
                    request.target().clone(),
                    next_revision,
                    AliasGeneration::INITIAL,
                    false,
                )?
            };
            aliases
                .insert(logical.as_str(), encode_alias(&snapshot).as_slice())
                .map_err(|_| ContextError::BackendUnavailable)?;
            let mut jobs = transaction
                .open_table(INDEX_JOBS)
                .map_err(|_| ContextError::BackendUnavailable)?;
            jobs.insert(logical.as_str(), job.as_slice())
                .map_err(|_| ContextError::BackendUnavailable)?;
        }
        transaction
            .commit()
            .map_err(|_| ContextError::BackendUnavailable)?;
        let _ = self.drain_index_jobs();
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
        let logical = logical_key(request.target());
        let generation = expected.generation().checked_next()?;
        let tombstone_revision = tombstone_revision(request.target(), expected, generation);
        let snapshot = AliasSnapshot::new(
            request.target().clone(),
            tombstone_revision,
            generation,
            true,
        )?;
        let erase_job = backend(IndexJob::Erase.encode())?;
        let transaction = self
            .store
            .db
            .begin_write()
            .map_err(|_| ContextError::BackendUnavailable)?;
        {
            let mut aliases = transaction
                .open_table(ALIASES)
                .map_err(|_| ContextError::BackendUnavailable)?;
            let current = aliases
                .get(logical.as_str())
                .map_err(|_| ContextError::BackendUnavailable)?
                .map(|value| value.value().to_vec())
                .ok_or(ContextError::AliasNotFound)?;
            let current = backend(decode_alias(request.target().clone(), &current))?;
            if current.is_tombstone() {
                return Err(ContextError::Tombstoned);
            }
            if &current != expected {
                return Err(ContextError::AliasConflict);
            }
            aliases
                .insert(logical.as_str(), encode_alias(&snapshot).as_slice())
                .map_err(|_| ContextError::BackendUnavailable)?;
            let mut objects = transaction
                .open_table(OBJECTS)
                .map_err(|_| ContextError::BackendUnavailable)?;
            let mut remove = Vec::new();
            for entry in objects
                .iter()
                .map_err(|_| ContextError::BackendUnavailable)?
            {
                let (key, _) = entry.map_err(|_| ContextError::BackendUnavailable)?;
                let pinned = backend(parse_pinned(key.value()))?;
                if logical_key(pinned.as_uri()) == logical {
                    remove.push(key.value().to_owned());
                }
            }
            for key in remove {
                let _ = objects
                    .remove(key.as_str())
                    .map_err(|_| ContextError::BackendUnavailable)?;
            }
            let mut index_jobs = transaction
                .open_table(INDEX_JOBS)
                .map_err(|_| ContextError::BackendUnavailable)?;
            index_jobs
                .insert(logical.as_str(), erase_job.as_slice())
                .map_err(|_| ContextError::BackendUnavailable)?;
            let mut purge_jobs = transaction
                .open_table(PURGE_JOBS)
                .map_err(|_| ContextError::BackendUnavailable)?;
            purge_jobs
                .insert(logical.as_str(), [1_u8].as_slice())
                .map_err(|_| ContextError::BackendUnavailable)?;
        }
        transaction
            .commit()
            .map_err(|_| ContextError::BackendUnavailable)?;
        let _ = self.maintenance();
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
        self.resolved_for(request.target())
    }
}

impl PersistentContextResolver {
    fn object_keys_for(&self, logical: &str) -> ServiceResult<Vec<String>> {
        let transaction = self.store.db.begin_read().map_err(ServiceError::database)?;
        let table = transaction
            .open_table(OBJECTS)
            .map_err(ServiceError::database)?;
        let mut keys = Vec::new();
        for entry in table.iter().map_err(ServiceError::database)? {
            let (key, _) = entry.map_err(ServiceError::database)?;
            let pinned = parse_pinned(key.value())?;
            if logical_key(pinned.as_uri()) == logical {
                keys.push(key.value().to_owned());
            }
        }
        Ok(keys)
    }
}

fn backend<T>(result: ServiceResult<T>) -> ContextResult<T> {
    result.map_err(|_| ContextError::BackendUnavailable)
}

fn is_within(root: &RuvUri, candidate: &RuvUri) -> bool {
    root.authority() == candidate.authority()
        && root.tenant() == candidate.tenant()
        && root.subject() == candidate.subject()
        && root.collection() == candidate.collection()
        && candidate.path().len() >= root.path().len()
        && candidate.path()[..root.path().len()] == root.path()[..]
}

fn tombstone_revision(
    alias: &RuvUri,
    expected: &AliasSnapshot,
    generation: AliasGeneration,
) -> Revision {
    let mut payload = Vec::new();
    payload.extend_from_slice(TOMBSTONE_DOMAIN);
    payload.push(0);
    payload.extend_from_slice(logical_key(alias).as_bytes());
    payload.push(0);
    payload.extend_from_slice(expected.revision().as_bytes());
    payload.extend_from_slice(&generation.get().to_le_bytes());
    Revision::from_bytes(Sha256::digest(&payload).into())
}

#[allow(clippy::cast_possible_truncation)]
fn score_vectors(query: &[f32], document: &[f32]) -> ContextResult<u32> {
    if query.len() != document.len() || query.is_empty() {
        return Err(ContextError::BackendUnavailable);
    }
    let mut dot = 0.0_f64;
    let mut query_norm = 0.0_f64;
    let mut document_norm = 0.0_f64;
    for (left, right) in query.iter().zip(document) {
        dot += f64::from(*left) * f64::from(*right);
        query_norm += f64::from(*left) * f64::from(*left);
        document_norm += f64::from(*right) * f64::from(*right);
    }
    if query_norm == 0.0 || document_norm == 0.0 {
        return Err(ContextError::BackendUnavailable);
    }
    let distance = 1.0 - dot / (query_norm.sqrt() * document_norm.sqrt());
    Ok(score_distance(distance as f32))
}

#[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
fn score_distance(distance: f32) -> u32 {
    if !distance.is_finite() {
        return 1;
    }
    let similarity = 1.0_f64 / (1.0 + f64::from(distance.max(0.0)));
    (similarity * 1_000_000.0).round().clamp(1.0, 1_000_000.0) as u32
}
