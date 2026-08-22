//! Pluggable query/document embedding boundary.

use crate::{ServiceError, ServiceResult};
use sha2::{Digest, Sha256};

/// Embedding provider shared by document compilation and query retrieval.
pub trait ContextEmbedder: Send + Sync {
    /// Fixed vector-space dimensionality.
    fn dimensions(&self) -> usize;

    /// Embed canonical view or query bytes into the configured vector space.
    ///
    /// # Errors
    ///
    /// Returns an error when the provider is unavailable or cannot produce an
    /// embedding in its declared vector space.
    fn embed(&self, input: &[u8]) -> ServiceResult<Vec<f32>>;
}

/// Deterministic bounded embedder for conformance tests and offline fallback.
///
/// It is not a semantic model. Production services should provide an ONNX or
/// remote model implementation with the same fixed-space contract.
#[derive(Debug, Clone, Copy)]
pub struct HashEmbedder {
    dimensions: usize,
}

impl HashEmbedder {
    /// Construct a deterministic vector space.
    ///
    /// # Errors
    ///
    /// Refuses zero dimensions or values above 4096.
    pub fn new(dimensions: usize) -> ServiceResult<Self> {
        if dimensions == 0 || dimensions > 4096 {
            return Err(ServiceError::Embedding("invalid hash vector dimensions"));
        }
        Ok(Self { dimensions })
    }
}

impl ContextEmbedder for HashEmbedder {
    fn dimensions(&self) -> usize {
        self.dimensions
    }

    #[allow(clippy::cast_possible_truncation)]
    fn embed(&self, input: &[u8]) -> ServiceResult<Vec<f32>> {
        let mut vector = Vec::with_capacity(self.dimensions);
        let mut seed_hash = Sha256::new();
        seed_hash.update(b"RUV-CONTEXT-HASH-EMBEDDER-SEED-V1\0");
        seed_hash.update(input);
        let seed = seed_hash.finalize();
        let mut counter = 0_u64;
        while vector.len() < self.dimensions {
            let mut hash = Sha256::new();
            hash.update(b"RUV-CONTEXT-HASH-EMBEDDER-V1\0");
            hash.update(counter.to_le_bytes());
            hash.update(seed);
            let digest = hash.finalize();
            for chunk in digest.chunks_exact(4) {
                let raw = u32::from_le_bytes(chunk.try_into().unwrap_or([0; 4]));
                let scaled = (f64::from(raw) / f64::from(u32::MAX)).mul_add(2.0, -1.0) as f32;
                vector.push(scaled);
                if vector.len() == self.dimensions {
                    break;
                }
            }
            counter = counter
                .checked_add(1)
                .ok_or(ServiceError::Embedding("hash vector counter overflow"))?;
        }
        let norm = vector
            .iter()
            .map(|value| f64::from(*value) * f64::from(*value))
            .sum::<f64>()
            .sqrt();
        if norm == 0.0 || !norm.is_finite() {
            return Err(ServiceError::Embedding("invalid hash vector norm"));
        }
        for value in &mut vector {
            *value = (f64::from(*value) / norm) as f32;
        }
        Ok(vector)
    }
}

pub(crate) fn checked_embedding(
    embedder: &dyn ContextEmbedder,
    input: &[u8],
) -> ServiceResult<Vec<f32>> {
    let vector = embedder.embed(input)?;
    if vector.len() != embedder.dimensions() || vector.iter().any(|value| !value.is_finite()) {
        return Err(ServiceError::Embedding(
            "provider returned an invalid vector",
        ));
    }
    Ok(vector)
}
