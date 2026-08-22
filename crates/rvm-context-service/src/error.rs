//! Hosted service error contract.

use core::fmt;

/// Result returned by the durable context service.
pub type ServiceResult<T> = Result<T, ServiceError>;

/// Fail-closed durable service failures.
#[derive(Debug)]
pub enum ServiceError {
    /// Persistent state could not be opened, read, committed, or decoded.
    Database(String),
    /// Envelope encryption, key wrapping, or authenticated decryption failed.
    Cryptography(&'static str),
    /// A persisted wire value is malformed or exceeds a configured bound.
    CorruptState(&'static str),
    /// The embedding provider returned an invalid vector space or value.
    Embedding(&'static str),
    /// The isolated RuVector backend refused an operation.
    Vector(String),
    /// The governed RVM context runtime refused a service operation.
    Runtime(String),
    /// An operating-system operation failed.
    Io(std::io::Error),
}

impl ServiceError {
    pub(crate) fn database(error: impl fmt::Display) -> Self {
        Self::Database(error.to_string())
    }

    pub(crate) fn vector(error: impl fmt::Display) -> Self {
        Self::Vector(error.to_string())
    }
}

impl fmt::Display for ServiceError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Database(error) => write!(f, "context database failed: {error}"),
            Self::Cryptography(error) => write!(f, "context cryptography failed: {error}"),
            Self::CorruptState(error) => write!(f, "context state is corrupt: {error}"),
            Self::Embedding(error) => write!(f, "context embedding failed: {error}"),
            Self::Vector(error) => write!(f, "context vector index failed: {error}"),
            Self::Runtime(error) => write!(f, "context runtime failed: {error}"),
            Self::Io(error) => write!(f, "context I/O failed: {error}"),
        }
    }
}

impl std::error::Error for ServiceError {}

impl From<std::io::Error> for ServiceError {
    fn from(error: std::io::Error) -> Self {
        Self::Io(error)
    }
}
