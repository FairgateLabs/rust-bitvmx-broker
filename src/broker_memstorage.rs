use crate::{
    identification::identifier::Identifier,
    rpc::{errors::BrokerRpcError, Message, StorageApi},
};
use std::collections::{HashMap, VecDeque};

#[derive(Clone, Debug)]
pub struct MemStorage {
    uid: u64,
    data: HashMap<Identifier, VecDeque<Message>>,
}

impl MemStorage {
    pub fn new() -> Self {
        Self {
            uid: 0,
            data: HashMap::new(),
        }
    }
}

impl StorageApi for MemStorage {
    fn get(&mut self, dest: Identifier) -> Result<Option<Message>, BrokerRpcError> {
        Ok(self.data.get_mut(&dest).and_then(|q| q.front().cloned()))
    }

    fn remove(&mut self, dest: Identifier, uid: u64) -> Result<bool, BrokerRpcError> {
        let data = self.data.get_mut(&dest);
        if let Some(data) = data {
            if data.front().map(|m| m.uid) == Some(uid) {
                data.pop_front();
                Ok(true)
            } else {
                Ok(false)
            }
        } else {
            Ok(false)
        }
    }

    fn insert(
        &mut self,
        from: Identifier,
        dest: Identifier,
        msg: String,
    ) -> Result<(), BrokerRpcError> {
        self.uid += 1;
        let msg = Message {
            uid: self.uid,
            from,
            msg,
        };
        self.data.entry(dest).or_default().push_back(msg);
        Ok(())
    }
}
