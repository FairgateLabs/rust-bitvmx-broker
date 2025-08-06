use std::sync::{Mutex, MutexGuard};
use thiserror::Error;

#[derive(Error, Debug)]
pub enum BrokerError {
    #[error("Rpc error")]
    RpcError(#[from] tarpc::client::RpcError),

    #[error("IO error")]
    IoError(#[from] std::io::Error),

    #[error("Broker client is disconnected")]
    Disconnected,

    #[error("Unauthorized fingerprint: {0}")]
    UnauthorizedFingerprint(String),

    #[error("Failed with certs/keys/allowlist")]
    AboutCertsAllow(#[from] anyhow::Error),

    #[error("Generic TLS error: {0}")]
    TlsError(String),

    #[error("Storage error: {0}")]
    StorageError(String),

    #[error("Failed to get address: {0}")]
    AddressError(#[from] std::net::AddrParseError),

    #[error("Invalid identifier: {0}")]
    InvalidIdentifier(String),

    #[error("Closed channel")]
    ClosedChannel,

    #[error("Mutex error: {0}")]
    MutexError(String),
}

pub trait MutexExt<T> {
    fn lock_or_err(&self, context: &'static str) -> Result<MutexGuard<T>, BrokerError>;
}

impl<T> MutexExt<T> for Mutex<T> {
    fn lock_or_err(&self, context: &'static str) -> Result<MutexGuard<T>, BrokerError> {
        self.lock()
            .map_err(|_| BrokerError::MutexError(format!("Mutex poisoned: {context}")))
    }
}
