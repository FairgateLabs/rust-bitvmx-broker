use std::{
    net::{IpAddr, Ipv4Addr, SocketAddr},
    sync::Arc,
};

use tokio::{net::TcpStream, sync::Mutex};

use super::{errors::BrokerError, BrokerConfig, Message};
use crate::rpc::BrokerClient;
use tarpc::{client, context, serde_transport, tokio_serde::formats::Json};

#[derive(Debug, Clone)]
pub struct AsyncClient {
    address: SocketAddr,
    client: Arc<Mutex<Option<BrokerClient>>>,
}

impl AsyncClient {
    pub fn new(config: &BrokerConfig) -> Self {
        let address = SocketAddr::new(
            config.ip.unwrap_or(IpAddr::V4(Ipv4Addr::LOCALHOST)),
            config.port,
        );

        Self {
            address,
            client: Arc::new(Mutex::new(None)),
        }
    }

    async fn connect(&self) -> Result<(), BrokerError> {
        let stream = TcpStream::connect(self.address).await?;
        stream.set_nodelay(true)?;
        let transport = serde_transport::Transport::from((stream, Json::default()));
        let client = BrokerClient::new(client::Config::default(), transport).spawn();
        let mut locked = self.client.lock().await;
        *locked = Some(client);
        Ok(())
    }

    async fn get_or_connect(&self) -> Result<BrokerClient, BrokerError> {
        {
            let mut locked = self.client.lock().await;

            if let Some(client) = locked.as_ref().cloned() {
                // Check if the client is still connected
                let test = client.get(context::current(), u32::MAX).await;
                if test.is_ok() {
                    return Ok(client);
                }

                // Client is broken
                *locked = None;
            }
        }

        // Try reconnecting
        if self.connect().await.is_ok() {
            let locked = self.client.lock().await;
            if let Some(client) = locked.as_ref().cloned() {
                return Ok(client);
            }
        }
        Err(BrokerError::Disconnected)
    }

    pub async fn send_msg(&self, from: u32, dest: u32, msg: String) -> Result<bool, BrokerError> {
        let client = self.get_or_connect().await?;
        Ok(client.send(context::current(), from, dest, msg).await?)
    }

    pub async fn get_msg(&self, dest: u32) -> Result<Option<Message>, BrokerError> {
        let client = self.get_or_connect().await?;
        Ok(client.get(context::current(), dest).await?)
    }

    pub async fn ack(&self, dest: u32, uid: u64) -> Result<bool, BrokerError> {
        let client = self.get_or_connect().await?;
        Ok(client.ack(context::current(), dest, uid).await?)
    }
}
