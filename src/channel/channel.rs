use std::sync::{Arc, Mutex};

use crate::rpc::{client::Client, BrokerConfig, Message, StorageApi};

//#[derive(Clone)]
pub struct DualChannel {
    client: Client,
    my_id: String, // Public key hash
}

impl DualChannel {
    pub fn new(config: &BrokerConfig) -> Result<Self, crate::rpc::errors::BrokerError> {
        let client = Client::new(config)?;
        let my_id = config.get_cert().get_pubk_hash()?;
        Ok(Self { client, my_id })
    }

    pub fn send(&self, dest: String, msg: String) -> Result<bool, crate::rpc::errors::BrokerError> {
        self.client.send_msg(self.my_id.clone(), dest, msg)
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
