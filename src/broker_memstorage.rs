use crate::{
    identification::identifier::Identifier,
    rpc::{Message, StorageApi},
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
    fn get(&mut self, dest: Identifier) -> Option<Message> {
        self.data.get_mut(&dest)?.front().cloned()
    }

    fn remove(&mut self, dest: Identifier, uid: u64) -> bool {
        let data = self.data.get_mut(&dest);
        if let Some(data) = data {
            if data.front().map(|m| m.uid) == Some(uid) {
                data.pop_front();
                true
            } else {
                false
            }
        } else {
            false
        }
    }

    fn insert(&mut self, from: Identifier, dest: Identifier, msg: String) {
        self.uid += 1;
        let msg = Message {
            uid: self.uid,
            from,
            msg,
        };
        self.data.entry(dest).or_default().push_back(msg);
    }
}
