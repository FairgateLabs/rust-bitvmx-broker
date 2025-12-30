// The BrokerStorage uses one key to store the uid and multiple keys to store the messages.
// The key "broker_current_uid" stores the current uid.
// The keys "broker_msg_{dest}_{uid}_{from}" store the messages.
// To list the messages for an specific destination, we use the partial_compare_keys
//     method to get all the keys that start with "broker_msg_{dest}_".
// Then we sort the keys get the oldest message (as uid is incremental).
// To get the info for the message, we split the key and get the from and uid field.

use crate::identification::identifier::Identifier;
use crate::rpc::errors::BrokerRpcError;
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
    fn get(&mut self, dest: Identifier) -> Result<Option<Message>, BrokerRpcError> {
        let storage_lock = self
            .storage
            .lock()
            .map_err(|_| BrokerRpcError::MutexError("storage".to_string()))?;
        let mut keys = storage_lock
            .partial_compare_keys(&format!("broker_msg_{dest}_"))
            .unwrap_or(vec![]);
        if keys.is_empty() {
            return Ok(None);
        }
        keys.sort();
        let key = keys.first().unwrap();
        if let Some(msg) = storage_lock.get(key).unwrap_or(None) {
            let parts: Vec<&str> = key.split('_').collect();
            let uid = parts[3]
                .parse::<u64>()
                .map_err(|e| BrokerRpcError::ParseError(format!("Failed to parse uid: {e}")))?;
            let from = parts[4].parse::<Identifier>().map_err(|e| {
                BrokerRpcError::ParseError(format!("Failed to parse Identifier: {e}"))
            })?;
            return Ok(Some(Message { uid, from, msg }));
        }
        Ok(None)
    }

    fn get_all(&mut self, dest: Identifier) -> Result<Vec<Message>, BrokerRpcError> {
        let storage_lock = self
            .storage
            .lock()
            .map_err(|_| BrokerRpcError::MutexError("storage".to_string()))?;
        let mut messages = Vec::new();
        let mut keys = storage_lock
            .partial_compare_keys(&format!("broker_msg_{dest}_"))
            .unwrap_or(vec![]);
        keys.sort();
        for key in keys {
            if let Some(msg) = storage_lock.get(&key).unwrap_or(None) {
                let parts: Vec<&str> = key.split('_').collect();
                let uid = parts[3]
                    .parse::<u64>()
                    .map_err(|e| BrokerRpcError::ParseError(format!("Failed to parse uid: {e}")))?;
                let from = parts[4].parse::<Identifier>().map_err(|e| {
                    BrokerRpcError::ParseError(format!("Failed to parse Identifier: {e}"))
                })?;
                messages.push(Message { uid, from, msg });
            }
        }
        Ok(messages)
    }

    fn remove(&mut self, dest: Identifier, uid: u64) -> Result<bool, BrokerRpcError> {
        let storage_lock = self
            .storage
            .lock()
            .map_err(|_| BrokerRpcError::MutexError("storage".to_string()))?;
        let keys = storage_lock
            .partial_compare_keys(&format!("broker_msg_{dest}_{}", format_uid(uid)))
            .unwrap_or(vec![]);
        if keys.len() != 1 {
            return Ok(false);
        }
        let key = keys.first().unwrap();
        if storage_lock.delete(key).is_err() {
            return Ok(false);
        }
        Ok(true)
    }

    fn insert(
        &mut self,
        from: Identifier,
        dest: Identifier,
        msg: String,
    ) -> Result<(), BrokerRpcError> {
        let storage_lock = self
            .storage
            .lock()
            .map_err(|_| BrokerRpcError::MutexError("storage".to_string()))?;

        let uid: u64 = storage_lock
            .get("broker_current_uid")
            .unwrap_or(None)
            .unwrap_or(0)
            + 1;

        let _ = storage_lock.set("broker_current_uid", uid, None);
        let _ = storage_lock.set(
            &format!("broker_msg_{dest}_{}_{from}", format_uid(uid)),
            msg,
            None,
        );
        Ok(())
    }
}
