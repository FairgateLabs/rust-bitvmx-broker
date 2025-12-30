use super::errors::BrokerError;
use crate::{
    identification::{allow_list::AllowList, identifier::Identifier},
    rpc::{client::Client, tls_helper::Cert, BrokerConfig, Message},
};
use std::sync::{Arc, Mutex};
use tokio::runtime::Runtime;

#[derive(Clone, Debug)]
pub struct SyncClient {
    client: Client,
    rt: Arc<Mutex<Runtime>>,
}

impl SyncClient {
    pub fn new(
        config: &BrokerConfig,
        cert: Cert,
        allow_list: Arc<Mutex<AllowList>>,
    ) -> Result<Self, BrokerError> {
        let rt = Arc::new(Mutex::new(Runtime::new()?));
        Self::new_with_runtime(config, cert, allow_list, rt)
    }

    pub fn new_with_runtime(
        config: &BrokerConfig,
        cert: Cert,
        allow_list: Arc<Mutex<AllowList>>,
        rt: Arc<Mutex<Runtime>>,
    ) -> Result<Self, BrokerError> {
        let client = Client::new(config, cert, allow_list);
        Ok(Self { rt, client })
    }

    pub fn send_msg(
        &self,
        from_id: u8,
        dest: Identifier,
        msg: String,
    ) -> Result<bool, BrokerError> {
        self.rt
            .lock()?
            .block_on(self.client.async_send_msg(from_id, dest, msg))
    }

    pub fn get_msg(&self, dest: u8) -> Result<Option<Message>, BrokerError> {
        self.rt.lock()?.block_on(self.client.async_get_msg(dest))
    }

    pub fn ack(&self, dest: u8, uid: u64) -> Result<bool, BrokerError> {
        self.rt.lock()?.block_on(self.client.async_ack(dest, uid))
    }
}
