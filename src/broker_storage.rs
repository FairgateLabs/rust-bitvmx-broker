// The BrokerStorage uses one key to store the uid and multiple keys to store the messages.
// The key "broker_current_uid" stores the current uid.
// The keys "broker_msg_{dest}_{uid}_{from}" store the messages.
// To list the messages for an specific destination, we use the partial_compare_keys
//     method to get all the keys that start with "broker_msg_{dest}_".
// Then we sort the keys get the oldest message (as uid is incremental).
// To get the info for the message, we split the key and get the from and uid field.

use crate::rpc::{Message, StorageApi};
use std::sync::{Arc, Mutex};
use storage_backend::storage::{KeyValueStore, Storage};

#[derive(Clone)]
pub struct BrokerStorage {
    storage: Arc<Mutex<Storage>>,
}

impl BrokerStorage {
    pub fn new(storage: Arc<Mutex<Storage>>) -> Self {
        Self { storage }
    }
}

fn format_uid(uid: u64) -> String {
    format!("{:0>20}", uid)
}

impl StorageApi for BrokerStorage {
    fn get(&mut self, dest: String) -> Option<Message> {
        let mut keys = self
            .storage
            .lock()
            .unwrap()
            .partial_compare_keys(&format!("broker_msg_{dest}_"))
            .unwrap_or(vec![]);
        if keys.is_empty() {
            return None;
        }
        keys.sort();
        let key = keys.first().unwrap();
        if let Some(msg) = self.storage.lock().unwrap().get(key).unwrap_or(None) {
            let parts: Vec<&str> = key.split('_').collect();
            let uid = parts[3].parse::<u64>().unwrap();
            let from = parts[4].parse::<String>().unwrap();
            return Some(Message { uid, from, msg });
        }
        None
    }

    fn remove(&mut self, dest: String, uid: u64) -> bool {
        let keys = self
            .storage
            .lock()
            .unwrap()
            .partial_compare_keys(&format!("broker_msg_{dest}_{}", format_uid(uid)))
            .unwrap_or(vec![]);
        if keys.len() != 1 {
            return false;
        }
        let key = keys.first().unwrap();
        if self.storage.lock().unwrap().delete(key).is_err() {
            return false;
        }
        true
    }

    fn insert(&mut self, from: String, dest: String, msg: String) {
        let uid: u64 = self
            .storage
            .lock()
            .unwrap()
            .get("broker_current_uid")
            .unwrap_or(None)
            .unwrap_or(0)
            + 1;
        let _ = self
            .storage
            .lock()
            .unwrap()
            .set("broker_current_uid", uid, None);
        let _ = self.storage.lock().unwrap().set(
            &format!("broker_msg_{dest}_{}_{from}", format_uid(uid)),
            msg,
            None,
        );
    }
}
