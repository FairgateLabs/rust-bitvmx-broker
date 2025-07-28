use std::{
    net::{IpAddr, SocketAddr},
    sync::Arc,
};

use tokio::{net::TcpStream, runtime::Runtime, sync::Mutex};

use super::{errors::BrokerError, BrokerConfig, Message};
use crate::rpc::BrokerClient;
use tarpc::{client, context, serde_transport, tokio_serde::formats::Json};

pub struct Client {
    rt: Runtime,
    address: SocketAddr,
    client: Arc<Mutex<Option<BrokerClient>>>,
}
impl Clone for Client {
    fn clone(&self) -> Self {
        let rt = Runtime::new().unwrap();
        Self {
            rt: rt,
            address: self.address,
            client: Arc::clone(&self.client),
        }
    }
}

impl Client {
    pub fn new(config: &BrokerConfig) -> Self {
        let rt = Runtime::new().unwrap();
        let address = SocketAddr::new(
            config.ip.unwrap_or(IpAddr::from([0, 0, 0, 0])),
            config.port,
        );

        Self {
            rt,
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

    async fn async_send_msg(&self, from: u32, dest: u32, msg: String) -> Result<bool, BrokerError> {
        let client = self.get_or_connect().await?;
        Ok(client.send(context::current(), from, dest, msg).await?)
    }

    async fn async_get_msg(&self, dest: u32) -> Result<Option<Message>, BrokerError> {
        let client = self.get_or_connect().await?;
        Ok(client.get(context::current(), dest).await?)
    }

    async fn async_ack(&self, dest: u32, uid: u64) -> Result<bool, BrokerError> {
        let client = self.get_or_connect().await?;
        Ok(client.ack(context::current(), dest, uid).await?)
    }

    pub fn send_msg(&self, from: u32, dest: u32, msg: String) -> Result<bool, BrokerError> {
        self.rt.block_on(self.async_send_msg(from, dest, msg))
    }

    pub fn get_msg(&self, dest: u32) -> Result<Option<Message>, BrokerError> {
        self.rt.block_on(self.async_get_msg(dest))
    }

    pub fn ack(&self, dest: u32, uid: u64) -> Result<bool, BrokerError> {
        self.rt.block_on(self.async_ack(dest, uid))
    }
}
