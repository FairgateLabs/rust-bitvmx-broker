// The BrokerServerStorage uses one key to store the uid and multiple keys to store the messages.
// The key "broker/uid" stores the current uid.
// The keys "broker/msgs/{dest}/{uid}/{from}" store the messages.
// The key "broker/count/{from}/{dest}" stores how many messages that sender has waiting for that destination.
// To list the messages for an specific destination, we use the partial_compare_keys
//     method to get all the keys that start with "broker/msgs/{dest}/".
// To get the info for the message, we split the key and get the uid and from fields.

use crate::identification::identifier::{validate_pubkey_hash, Identifier};
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
const COUNT_PREFIX: &str = "broker/count";

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

    fn count_key(from: &Identifier, dest: &Identifier) -> Result<String, BrokerStorageError> {
        validate_pubkey_hash(&from.pubkey_hash).map_err(BrokerStorageError::InvalidIdentifier)?;
        validate_pubkey_hash(&dest.pubkey_hash).map_err(BrokerStorageError::InvalidIdentifier)?;
        Ok(format!("{COUNT_PREFIX}/{from}/{dest}"))
    }

    fn msg_key(
        dest: &Identifier,
        uid: u64,
        from: &Identifier,
    ) -> Result<String, BrokerStorageError> {
        validate_pubkey_hash(&dest.pubkey_hash).map_err(BrokerStorageError::InvalidIdentifier)?;
        validate_pubkey_hash(&from.pubkey_hash).map_err(BrokerStorageError::InvalidIdentifier)?;
        Ok(format!(
            "{}{}/{from}",
            Self::msgs_prefix(dest),
            format_uid(uid)
        ))
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

    /// How many messages from one sender are waiting for a specific destination.
    pub fn get_count_for_identifier(
        &self,
        from: &Identifier,
        dest: &Identifier,
    ) -> Result<u64, BrokerStorageError> {
        let storage = self.storage.lock_or_err::<BrokerStorageError>("storage")?;
        Ok(storage
            .get(&Self::count_key(from, dest)?, None)?
            .unwrap_or(0))
    }

    // The oldest message waiting for dest.
    pub fn get(&self, dest: Identifier) -> Result<Option<Message>, BrokerStorageError> {
        let storage = self.storage.lock_or_err::<BrokerStorageError>("storage")?;
        let keys = storage.partial_compare_keys(&Self::msgs_prefix(&dest), None)?;
        let Some(key) = keys.first() else {
            return Ok(None);
        };
        let Some(msg) = storage.get(key, None)? else {
            return Ok(None);
        };
        let (uid, from) = Self::decode_key(key)?;
        Ok(Some(Message { uid, from, msg }))
    }

    // Messages waiting for dest, oldest first.
    pub fn get_all(&self, dest: Identifier) -> Result<Vec<Message>, BrokerStorageError> {
        let storage = self.storage.lock_or_err::<BrokerStorageError>("storage")?;
        // Already ordered by uid.
        let keys = storage.partial_compare_keys(&Self::msgs_prefix(&dest), None)?;

        let mut messages = Vec::new();
        for key in keys {
            if let Some(msg) = storage.get(&key, None)? {
                let (uid, from) = Self::decode_key(&key)?;
                messages.push(Message { uid, from, msg });
            }
        }
        Ok(messages)
    }

    pub fn remove(&self, dest: Identifier, uid: u64) -> Result<bool, BrokerStorageError> {
        let storage = self.storage.lock_or_err::<BrokerStorageError>("storage")?;
        let prefix = format!("{}{}", Self::msgs_prefix(&dest), format_uid(uid));
        let keys = storage.partial_compare_keys(&prefix, None)?;
        if keys.len() != 1 {
            // No such message stored for this destination. Reached when the uid was already
            // acknowledged, when it never existed, or when it belongs to another destination. None of
            // those is an error, so the caller is told the message was not there instead of failing.
            return Ok(false);
        }

        // The sender is part of the key, so the pair whose count drops is read back out of it.
        let (_, from) = Self::decode_key(&keys[0])?;
        let count_key = Self::count_key(&from, &dest)?;
        let count: u64 = storage.get(&count_key, None)?.unwrap_or(0);

        let tx = storage.begin_transaction();
        let removed = storage
            .remove(&keys[0], Some(tx))
            .and_then(|_| storage.set(&count_key, count.saturating_sub(1), Some(tx)));

        match removed {
            Ok(()) => {
                storage.commit_transaction(tx)?;
                Ok(true)
            }
            Err(e) => {
                let _ = storage.rollback_transaction(tx);
                Err(e.into())
            }
        }
    }

    pub fn insert(
        &self,
        from: Identifier,
        dest: Identifier,
        msg: String,
    ) -> Result<(), BrokerStorageError> {
        let storage = self.storage.lock_or_err::<BrokerStorageError>("storage")?;

        let count_key = Self::count_key(&from, &dest)?;
        let count: u64 = storage.get(&count_key, None)?.unwrap_or(0);

        let uid: u64 = storage.get(UID_KEY, None)?.unwrap_or(0) + 1;
        let key = Self::msg_key(&dest, uid, &from)?;

        // The new uid, the message it names and the count of stored messages are written together.
        let tx = storage.begin_transaction();
        let written = storage
            .set(UID_KEY, uid, Some(tx))
            .and_then(|_| storage.set(&key, msg, Some(tx)))
            .and_then(|_| storage.set(&count_key, count + 1, Some(tx)));

        match written {
            Ok(()) => Ok(storage.commit_transaction(tx)?),
            Err(e) => {
                let _ = storage.rollback_transaction(tx);
                Err(e.into())
            }
        }
    }
}
