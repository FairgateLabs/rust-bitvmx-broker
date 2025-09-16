use super::errors::BrokerError;
use crate::{
    identification::{allow_list::AllowList, identifier::Identifier},
    rpc::{client::Client, tls_helper::Cert, BrokerConfig, Message},
};
use std::sync::{Arc, Mutex as ArcMutex};
use tokio::runtime::Runtime;

#[derive(Debug)]
pub struct SyncClient {
    client: Client,
    rt: Runtime,
}

impl Clone for SyncClient {
    fn clone(&self) -> Self {
        self.try_clone().expect("failed to clone SyncClient")
    }
}

impl SyncClient {
    pub fn new(
        config: &BrokerConfig,
        cert: Cert,
        allow_list: Arc<ArcMutex<AllowList>>,
    ) -> Result<Self, BrokerError> {
        let rt = Runtime::new()?;
        let client = Client::new(config, cert, allow_list)?;
        Ok(Self { rt, client })
    }

    pub fn send_msg(
        &self,
        from_id: u8,
        from_port: u16,
        dest: Identifier,
        msg: String,
    ) -> Result<bool, BrokerError> {
        self.rt
            .block_on(self.client.async_send_msg(from_id, from_port, dest, msg))
    }

    pub fn get_msg(&self, dest: Identifier) -> Result<Option<Message>, BrokerError> {
        self.rt.block_on(self.client.async_get_msg(dest))
    }

    pub fn ack(&self, dest: Identifier, uid: u64) -> Result<bool, BrokerError> {
        self.rt.block_on(self.client.async_ack(dest, uid))
    }

    fn try_clone(&self) -> Result<Self, BrokerError> {
        let rt = Runtime::new()?;
        Ok(Self {
            rt,
            client: self.client.clone(),
        })
    }
}
