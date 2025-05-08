use thiserror::Error;

#[derive(Error, Debug)]
pub enum BrokerError {
    #[error("Rpc error")]
    RpcError(#[from] tarpc::client::RpcError),

    #[error("IO error")]
    IoError(#[from] std::io::Error),

    #[error("Broker client is disconnected")]
    Disconnected,
}
