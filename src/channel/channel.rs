use std::sync::{Arc, Mutex};

use crate::rpc::{client::Client, BrokerConfig, Message, StorageApi};

pub struct DualChannel {
    client: Client,
    my_id: u32,
}

impl DualChannel {
    pub fn new(config: &BrokerConfig, my_id: u32) -> Self {
        let client = Client::new(config);
        Self { client, my_id }
    }

    pub fn send(&self, dest: u32, msg: String) -> Result<bool, crate::rpc::errors::BrokerError> {
        self.client.send_msg(self.my_id, dest, msg)
    }

    pub fn recv(&self) -> Result<Option<(String, u32)>, crate::rpc::errors::BrokerError> {
        if let Some(msg) = self.client.get_msg(self.my_id)? {
            self.client.ack(self.my_id, msg.uid)?;
            Ok(Some((msg.msg, msg.from)))
        } else {
            Ok(None)
        }
    }
}

pub struct LocalChannel<S: StorageApi> {
    my_id: u32,
    storage: Arc<Mutex<S>>,
}

impl<S> LocalChannel<S>
where
    S: StorageApi,
{
    pub fn new(my_id: u32, storage: Arc<Mutex<S>>) -> Self {
        Self { my_id, storage }
    }
    /*  fn get(&mut self, dest: u32) -> Option<Message>;
    fn insert(&mut self, from: u32, dest: u32, msg: String);
    fn remove(&mut self, dest: u32, uid: u64) -> bool;*/
    pub fn send(&self, dest: u32, msg: String) -> Result<bool, crate::rpc::errors::BrokerError> {
        self.storage.lock().unwrap().insert(self.my_id, dest, msg);
        Ok(true)
    }

    pub fn get(&self, dest: u32) -> Result<Option<Message>, crate::rpc::errors::BrokerError> {
        Ok(self.storage.lock().unwrap().get(dest))
    }

    pub fn ack(&self, dest: u32, uid: u64) -> Result<bool, crate::rpc::errors::BrokerError> {
        Ok(self.storage.lock().unwrap().remove(dest, uid))
    }

    pub fn recv(&self) -> Result<Option<(String, u32)>, crate::rpc::errors::BrokerError> {
        if let Some(msg) = self.get(self.my_id)? {
            self.ack(self.my_id, msg.uid)?;
            Ok(Some((msg.msg, msg.from)))
        } else {
            Ok(None)
        }
    }
}
