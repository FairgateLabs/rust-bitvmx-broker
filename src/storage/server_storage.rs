// The BrokerServerStorage uses one key to store the uid and multiple keys to store the messages.
// The key "broker/uid" stores the current uid.
// The keys "broker/msgs/{dest}/{uid}/{from}" store the messages.
// To list the messages for an specific destination, we use the partial_compare_keys
//     method to get all the keys that start with "broker/msgs/{dest}/".
// Then we sort the keys get the oldest message (as uid is incremental).
// To get the info for the message, we split the key and get the uid and from fields.

use crate::identification::identifier::Identifier;
use crate::rpc::errors::MutexExt;
use crate::rpc::Message;
use crate::storage::errors::BrokerStorageError;
use std::sync::{Arc, Mutex};
use storage_backend::{
    storage::{KeyValueStore, Storage},
    storage_config::StorageConfig,
};

const UID_KEY: &str = "broker/uid";
const MSGS_PREFIX: &str = "broker/msgs";

#[derive(Clone)]
pub struct BrokerServerStorage {
    storage: Arc<Mutex<Storage>>,
}

fn format_uid(uid: u64) -> String {
    format!("{:0>20}", uid)
}

impl BrokerServerStorage {
    pub fn new(path: &str) -> Result<Self, BrokerStorageError> {
        let storage_config = StorageConfig::new(path.to_string(), None); //TODO: assuming password is always none.
        Ok(Self {
            storage: Arc::new(Mutex::new(Storage::new(&storage_config)?)),
        })
    }

    fn msgs_prefix(dest: &Identifier) -> String {
        format!("{MSGS_PREFIX}/{dest}/")
    }

    fn msg_key(dest: &Identifier, uid: u64, from: &Identifier) -> String {
        format!("{}{}/{from}", Self::msgs_prefix(dest), format_uid(uid))
    }

    // Splits "broker/msgs/{dest}/{uid}/{from}" into the uid and the sender.
    fn decode_key(key: &str) -> Result<(u64, Identifier), BrokerStorageError> {
        let parts: Vec<&str> = key.split('/').collect();
        if parts.len() != 5 {
            return Err(BrokerStorageError::MalformedKey(key.to_string()));
        }
        let uid = parts[3]
            .parse::<u64>()
            .map_err(|_| BrokerStorageError::MalformedKey(key.to_string()))?;
        let from = parts[4]
            .parse::<Identifier>()
            .map_err(BrokerStorageError::InvalidIdentifier)?;
        Ok((uid, from))
    }

    pub fn get(&self, dest: Identifier) -> Result<Option<Message>, BrokerStorageError> {
        Ok(self.get_all(dest)?.into_iter().next())
    }

    // Messages waiting for dest, oldest first.
    pub fn get_all(&self, dest: Identifier) -> Result<Vec<Message>, BrokerStorageError> {
        let storage = self.storage.lock_or_err::<BrokerStorageError>("storage")?;
        let mut keys = storage
            .partial_compare_keys(&Self::msgs_prefix(&dest), None)
            .unwrap_or(vec![]);
        keys.sort();

        let mut messages = Vec::new();
        for key in keys {
            if let Some(msg) = storage.get(&key, None).unwrap_or(None) {
                let (uid, from) = Self::decode_key(&key)?;
                messages.push(Message { uid, from, msg });
            }
        }
        Ok(messages)
    }

    pub fn remove(&self, dest: Identifier, uid: u64) -> Result<bool, BrokerStorageError> {
        let storage = self.storage.lock_or_err::<BrokerStorageError>("storage")?;
        let prefix = format!("{}{}", Self::msgs_prefix(&dest), format_uid(uid));
        let keys = storage
            .partial_compare_keys(&prefix, None)
            .unwrap_or(vec![]);
        if keys.len() != 1 {
            return Ok(false);
        }
        Ok(storage.remove(&keys[0], None).is_ok())
    }

    pub fn insert(
        &self,
        from: Identifier,
        dest: Identifier,
        msg: String,
    ) -> Result<(), BrokerStorageError> {
        let storage = self.storage.lock_or_err::<BrokerStorageError>("storage")?;

        let uid: u64 = storage.get(UID_KEY, None).unwrap_or(None).unwrap_or(0) + 1;

        let _ = storage.set(UID_KEY, uid, None);
        let _ = storage.set(&Self::msg_key(&dest, uid, &from), msg, None);
        Ok(())
    }
}
