use crate::{identification, rpc::MAX_MSG_SIZE_KB};
use serde::{Deserialize, Serialize};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use thiserror::Error;

#[derive(Error, Debug)]
pub enum BrokerError {
    #[error("Rpc error")]
    RpcError(#[from] tarpc::client::RpcError),

    #[error("IO error")]
    IoError(#[from] std::io::Error),

    #[error("Serialization error {0}")]
    SerdeSerializationError(#[from] serde_json::Error),

    #[error("Identification error: {0}")]
    IdentificationError(#[from] identification::errors::IdentificationError),

    #[error("Broker client is disconnected")]
    Disconnected,

    #[error("Unauthorized fingerprint: {0}")]
    UnauthorizedFingerprint(String),

    #[error("Failed with certs/keys/allowlist")]
    AboutCertsAllow(#[from] anyhow::Error),

    #[error("Generic TLS error: {0}")]
    TlsError(String),

    #[cfg(feature = "storagebackend")]
    #[error("Storage error: {0}")]
    StorageError(#[from] storage_backend::error::StorageError),

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

    #[error("Broker Rpc Error: {0}")]
    BrokerRpcError(#[from] BrokerRpcError),

    #[error("RSA Error: {0}")]
    RsaError(#[from] rsa::Error),

    #[error("Invalid private key for PEM {0}")]
    InvalidPrivateKey(#[from] rsa::pkcs8::Error),

    #[error("Message too large. Max size is {MAX_MSG_SIZE_KB} KB, but got {0} KB")]
    MessageTooLarge(usize),

    #[error("Other error: {0}")]
    Other(String),
}

impl<T> From<PoisonError<T>> for BrokerError {
    fn from(err: PoisonError<T>) -> Self {
        BrokerError::MutexError(err.to_string())
    }
}

#[derive(Error, Debug, Serialize, Deserialize)]
pub enum BrokerRpcError {
    #[error("Mutex error: {0}")]
    MutexError(String),

    #[error("Parse error: {0}")]
    ParseError(String),

    #[error("Message too large. Max size is {MAX_MSG_SIZE_KB} KB, but got {0} KB")]
    MessageTooLarge(usize),

    #[error("Rate limit exceeded")]
    RateLimitExceeded,
}

pub trait FromMutexError {
    fn from_mutex_error(context: &'static str) -> Self;
}

impl FromMutexError for BrokerError {
    fn from_mutex_error(context: &'static str) -> Self {
        BrokerError::MutexError(format!("Mutex poisoned: {context}"))
    }
}

impl FromMutexError for BrokerRpcError {
    fn from_mutex_error(context: &'static str) -> Self {
        BrokerRpcError::MutexError(format!("Mutex poisoned: {context}"))
    }
}

pub trait MutexExt<T> {
    fn lock_or_err<E>(&self, context: &'static str) -> Result<MutexGuard<'_, T>, E>
    where
        E: FromMutexError;
}

impl<T> MutexExt<T> for Mutex<T> {
    fn lock_or_err<E>(&self, context: &'static str) -> Result<MutexGuard<'_, T>, E>
    where
        E: FromMutexError,
    {
        self.lock().map_err(|_| E::from_mutex_error(context))
    }
}

impl<T> MutexExt<T> for Arc<Mutex<T>> {
    fn lock_or_err<E>(&self, context: &'static str) -> Result<MutexGuard<'_, T>, E>
    where
        E: FromMutexError,
    {
        self.lock().map_err(|_| E::from_mutex_error(context))
    }
}
