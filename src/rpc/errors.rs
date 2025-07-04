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
}
