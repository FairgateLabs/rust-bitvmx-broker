use crate::rpc::errors::{BrokerRpcError, FromMutexError, Severity};
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

impl BrokerStorageError {
    pub fn severity(&self) -> Severity {
        match self {
            BrokerStorageError::MutexPoisoned => Severity::Fatal,
            // One unreadable row, or one input that never should have been keyed.
            BrokerStorageError::MalformedKey(_) | BrokerStorageError::InvalidIdentifier(_) => {
                Severity::NonFatal
            }
            // The backend reports a missing key and an unopenable database through one type. All of it is considered non-fatal.
            BrokerStorageError::Backend(_) => Severity::NonFatal,
        }
    }
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_storage_errors() {
        let mutex: BrokerRpcError = BrokerStorageError::MutexPoisoned.into();
        assert!(matches!(mutex, BrokerRpcError::MutexError(_)));
        assert!(mutex.is_fatal());

        // Everything else collapses into ParseError, keeping the original message.
        let row: BrokerRpcError =
            BrokerStorageError::MalformedKey("broker/msgs/x".to_string()).into();
        assert!(matches!(row, BrokerRpcError::ParseError(ref m) if m.contains("broker/msgs/x")));
        assert!(!row.is_fatal());

        assert_eq!(
            BrokerStorageError::InvalidIdentifier("not-an-id".to_string()).severity(),
            Severity::NonFatal
        );
        assert!(matches!(
            BrokerStorageError::from_mutex_error("storage"),
            BrokerStorageError::MutexPoisoned
        ));
    }
}
