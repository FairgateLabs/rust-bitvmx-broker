use crate::{
    allow_list::AllowList,
    rpc::{client::Client, tls_helper::Cert, BrokerConfig, Message, StorageApi},
};
use std::sync::{Arc, Mutex};

//#[derive(Clone)]
pub struct DualChannel {
    client: Client,
    my_id: String,   // Public key hash
    dest_id: String, // Public key hash of the destination
}

impl DualChannel {
    // The config is of the node you want to connect to
    pub fn new(
        config: &BrokerConfig,
        my_cert: Cert,
        allow_list: Arc<Mutex<AllowList>>,
    ) -> Result<Self, crate::rpc::errors::BrokerError> {
        let client = Client::new(config, my_cert.clone(), allow_list)?;
        let my_id = my_cert.get_pubk_hash()?;
        let dest_id = config.get_pubk_hash();
        Ok(Self {
            client,
            my_id,
            dest_id,
        })
    }

    // If dest is None, it will use the dest_id from the config
    pub fn send(
        &self,
        dest: Option<String>,
        msg: String,
    ) -> Result<bool, crate::rpc::errors::BrokerError> {
        let dest_id = dest.unwrap_or_else(|| self.dest_id.to_string());
        self.client.send_msg(self.my_id.clone(), dest_id, msg)
    }

    pub fn recv(&self) -> Result<Option<(String, String)>, crate::rpc::errors::BrokerError> {
        if let Some(msg) = self.client.get_msg(self.my_id.clone())? {
            self.client.ack(self.my_id.clone(), msg.uid)?;
            Ok(Some((msg.msg, msg.from)))
        } else {
            Ok(None)
        }
    }
}

pub struct LocalChannel<S: StorageApi> {
    my_id: String, // Public key hash
    storage: Arc<Mutex<S>>,
}

impl<S> LocalChannel<S>
where
    S: StorageApi,
{
    pub fn new(my_id: String, storage: Arc<Mutex<S>>) -> Self {
        Self { my_id, storage }
    }
    /*  fn get(&mut self, dest: String) -> Option<Message>;
    fn insert(&mut self, from: String, dest: String, msg: String);
    fn remove(&mut self, dest: String, uid: u64) -> bool;*/
    pub fn send(&self, dest: String, msg: String) -> Result<bool, crate::rpc::errors::BrokerError> {
        self.storage
            .lock()
            .unwrap()
            .insert(self.my_id.clone(), dest, msg);
        Ok(true)
    }

    pub fn get(&self, dest: String) -> Result<Option<Message>, crate::rpc::errors::BrokerError> {
        Ok(self.storage.lock().unwrap().get(dest))
    }

    pub fn ack(&self, dest: String, uid: u64) -> Result<bool, crate::rpc::errors::BrokerError> {
        Ok(self.storage.lock().unwrap().remove(dest, uid))
    }

    pub fn recv(&self) -> Result<Option<(String, String)>, crate::rpc::errors::BrokerError> {
        if let Some(msg) = self.get(self.my_id.clone())? {
            self.ack(self.my_id.clone(), msg.uid)?;
            Ok(Some((msg.msg, msg.from)))
        } else {
            Ok(None)
        }
    }
}
