use crate::{identification, retry::RetryPolicyError, storage};
use bitvmx_settings::errors::ConfigError;
use serde::{Deserialize, Serialize};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use thiserror::Error;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Severity {
    /// Storage is gone, a lock is poisoned, or the configuration is invalid. Nothing can proceed.
    Fatal,
    /// One message or one peer was refused or failed. Keep serving.
    NonFatal,
    /// The caller misused the API.
    Programming,
}

impl Severity {
    pub fn is_fatal(&self) -> bool {
        !matches!(self, Severity::NonFatal)
    }
}

#[derive(Error, Debug)]
pub enum BrokerError {
    #[error("Rpc error")]
    RpcError(#[from] tarpc::client::RpcError),

    #[error("Failed to reach a peer: {0}")]
    ConnectError(#[from] std::io::Error),

    #[error("Failed to bind the listener: {0}")]
    BindError(std::io::Error),

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

    #[error("Broker storage error: {0}")]
    BrokerStorageError(#[from] storage::BrokerStorageError),

    #[error("Failed to get the peer address: {0}")]
    AddressError(#[from] std::net::AddrParseError),

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

    #[error("Operation not available on a node built in {0} mode")]
    WrongNodeMode(String),

    #[error("Cannot create a local channel to the node's own local_id")]
    LocalChannelForOwnId,

    #[error("Time error: {0}")]
    TimeError(#[from] std::time::SystemTimeError),

    #[error("Retry policy error: {0}")]
    RetryPolicyError(#[from] RetryPolicyError),

    #[error("Setting file error: {0}")]
    Settings(#[from] ConfigError),
}

impl BrokerError {
    pub fn severity(&self) -> Severity {
        match self {
            // Only a constructor reaches these.
            BrokerError::BindError(_)
            | BrokerError::RcgenError(_)
            | BrokerError::RsaError(_)
            | BrokerError::InvalidPrivateKey(_)
            | BrokerError::X509ParseError(_)
            | BrokerError::MutexError(_)
            | BrokerError::Settings(_) => Severity::Fatal,

            BrokerError::WrongNodeMode(_) | BrokerError::LocalChannelForOwnId => {
                Severity::Programming
            }

            // Delegated.
            BrokerError::BrokerRpcError(e) => e.severity(),
            BrokerError::BrokerStorageError(e) => e.severity(),
            BrokerError::IdentificationError(e) => e.severity(),
            BrokerError::RetryPolicyError(e) => e.severity(),

            // One message, one row, one peer, or on every dial.
            BrokerError::AboutCertsAllow(_) // Considering certificate rotation.
            | BrokerError::TlsError(_)
            | BrokerError::RustlsError(_)
            | BrokerError::PemParseError(_)
            | BrokerError::RpcError(_)
            | BrokerError::ConnectError(_)
            | BrokerError::AddressError(_)
            | BrokerError::Disconnected
            | BrokerError::UnauthorizedFingerprint(_)
            | BrokerError::SerdeSerializationError(_)
            | BrokerError::MessageTooLarge(_, _)
            | BrokerError::InvalidMessageContext { .. }
            | BrokerError::TimeError(_) => Severity::NonFatal,
        }
    }

    pub fn is_fatal(&self) -> bool {
        self.severity().is_fatal()
    }
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

    #[error("Queue for {0} is full, it already holds {1} messages")]
    QueueFull(String, u64),
}

impl BrokerRpcError {
    pub fn severity(&self) -> Severity {
        match self {
            BrokerRpcError::MutexError(_) => Severity::Fatal,

            BrokerRpcError::ParseError(_)
            | BrokerRpcError::MessageTooLarge(_, _)
            | BrokerRpcError::RateLimitExceeded
            | BrokerRpcError::QueueFull(_, _) => Severity::NonFatal,
        }
    }

    pub fn is_fatal(&self) -> bool {
        self.severity().is_fatal()
    }
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
