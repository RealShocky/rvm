//! Tenant- and path-sharded active-alias retrieval adapter.

use crate::store::{point_id, IndexJob};
use crate::{ServiceError, ServiceResult};
use ruvector_context::{
    ContextIndexOptions, ContextNamespace, ContextPoint, ContextScope, ScopedContextIndex,
};
use ruvector_core::types::DbOptions;
use ruvector_core::DistanceMetric;
use rvm_context::RuvUri;
use std::path::Path;

pub(crate) struct ActiveMatch {
    pub(crate) alias: RuvUri,
    pub(crate) point_id: String,
    pub(crate) distance: f32,
}

pub(crate) struct ActiveIndex {
    index: ScopedContextIndex,
}

impl ActiveIndex {
    pub(crate) fn open(
        path: impl AsRef<Path>,
        dimensions: usize,
        max_scopes: usize,
        max_search_shards: usize,
        max_results: usize,
    ) -> ServiceResult<Self> {
        let options = ContextIndexOptions {
            vector: DbOptions {
                dimensions,
                distance_metric: DistanceMetric::Cosine,
                storage_path: String::new(),
                hnsw_config: None,
                quantization: None,
            },
            max_scopes,
            max_search_shards,
            max_results,
        };
        let index = ScopedContextIndex::open(path, options).map_err(ServiceError::vector)?;
        Ok(Self { index })
    }

    pub(crate) fn apply(&self, alias: &RuvUri, job: &IndexJob) -> ServiceResult<()> {
        let scope = to_vector_scope(alias)?;
        let _ = self
            .index
            .erase_scope(&scope)
            .map_err(ServiceError::vector)?;
        if let IndexJob::Upsert { pinned, vector } = job {
            self.index
                .insert(
                    &scope,
                    ContextPoint {
                        id: point_id(pinned),
                        vector: vector.clone(),
                    },
                )
                .map_err(ServiceError::vector)?;
        }
        Ok(())
    }

    pub(crate) fn search(
        &self,
        root: &RuvUri,
        vector: &[f32],
        limit: usize,
    ) -> ServiceResult<Vec<ActiveMatch>> {
        let root_scope = to_vector_scope(root)?;
        self.index
            .search(&root_scope, vector, limit)
            .map_err(ServiceError::vector)?
            .into_iter()
            .map(|item| {
                Ok(ActiveMatch {
                    alias: from_vector_scope(&item.scope)?,
                    point_id: item.id,
                    distance: item.score,
                })
            })
            .collect()
    }
}

fn to_vector_scope(uri: &RuvUri) -> ServiceResult<ContextScope> {
    let namespace = ContextNamespace::new(
        uri.authority().as_str(),
        uri.tenant().as_str(),
        uri.subject().kind().as_str(),
        uri.subject().id().as_str(),
        uri.collection().as_str(),
    )
    .map_err(ServiceError::vector)?;
    ContextScope::new(
        namespace,
        uri.path()
            .iter()
            .map(|segment| segment.as_str().to_owned())
            .collect(),
    )
    .map_err(ServiceError::vector)
}

fn from_vector_scope(scope: &ContextScope) -> ServiceResult<RuvUri> {
    let namespace = scope.namespace();
    let mut uri = format!(
        "ruv://{}/{}/{}/{}/{}",
        namespace.authority(),
        namespace.tenant(),
        namespace.subject_kind(),
        namespace.subject_id(),
        namespace.collection()
    );
    for segment in scope.path() {
        uri.push('/');
        uri.push_str(segment);
    }
    RuvUri::parse(&uri)
        .map_err(|_| ServiceError::CorruptState("vector scope is not a canonical ruv URI"))
}
