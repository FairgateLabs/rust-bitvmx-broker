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

    #[error("X509 parse error: {0}")]
    X509ParseError(#[from] x509_parser::error::X509Error),

    #[error("PEM parse error: {0}")]
    PemParseError(#[from] pem::PemError),

    #[error("Rcgen error: {0}")]
    RcgenError(#[from] rcgen::Error),

    #[error("Rustls error: {0}")]
    RustlsError(#[from] rustls::Error),
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
