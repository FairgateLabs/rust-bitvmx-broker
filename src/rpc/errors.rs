use crate::{identification, retry::RetryPolicyError, storage};
use bitvmx_settings::errors::ConfigError;
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

    #[error("Error parsing int")]
    ParseIntError(#[from] std::num::ParseIntError),

    #[error("Broker client is disconnected")]
    Disconnected,

    #[error("Unauthorized fingerprint: {0}")]
    UnauthorizedFingerprint(String),

    #[error("Failed with certs/keys/allowlist")]
    AboutCertsAllow(#[from] anyhow::Error),

    #[error("Generic TLS error: {0}")]
    TlsError(String),

    #[error("Broker storage error: {0}")]
    BrokerStorageError(#[from] storage::BrokerStorageError),

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

    #[error("Message too large. Max size is {0} KB, but got {1} KB")]
    MessageTooLarge(usize, usize),

    #[error("Expected ctx {}, but got {}", expected, got)]
    InvalidMessageContext { expected: String, got: String },

    #[error("Time error: {0}")]
    TimeError(#[from] std::time::SystemTimeError),

    #[error("Retry policy error: {0}")]
    RetryPolicyError(#[from] RetryPolicyError),

    #[error("Other error: {0}")]
    Other(String),

    #[error("Setting file error: {0}")]
    Settings(#[from] ConfigError),
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

    #[error("Message too large. Max size is {0} KB, but got {1} KB")]
    MessageTooLarge(usize, usize),

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
