use crate::rpc::errors::{BrokerRpcError, FromMutexError};
use thiserror::Error;

#[derive(Error, Debug)]
pub enum BrokerStorageError {
    #[error("Mutex poisoned: storage")]
    MutexPoisoned,

    #[error("Storage backend error: {0}")]
    Backend(#[from] storage_backend::error::StorageError),

    #[error("Malformed key: {0}")]
    MalformedKey(String),

    #[error("Invalid identifier in key: {0}")]
    InvalidIdentifier(String),
}

impl FromMutexError for BrokerStorageError {
    fn from_mutex_error(_context: &'static str) -> Self {
        BrokerStorageError::MutexPoisoned
    }
}

impl From<BrokerStorageError> for BrokerRpcError {
    fn from(err: BrokerStorageError) -> Self {
        match err {
            BrokerStorageError::MutexPoisoned => BrokerRpcError::MutexError("storage".to_string()),
            other => BrokerRpcError::ParseError(other.to_string()),
        }
    }
}
