// The BrokerNodeStorage holds the out, in and dead letter queues of a single BrokerNode.
// The key "broker/{queue}/{name}/uid" stores the current uid of a queue.
// The keys "broker/{queue}/{name}/msgs/{uid}/{pubk_hash}/{tag}" store the messages, where tag is
//     the destination address for the out and dead letter queues, and the sender id for the in queue.
// It runs on the single threaded storage the caller owns, so it takes an Rc and never locks.

use crate::identification::identifier::{validate_pubkey_hash, Identifier, PubkHash};
use crate::rpc::Message;
use crate::storage::errors::BrokerStorageError;
use std::net::SocketAddr;
use std::rc::Rc;
use storage_backend::storage::{KeyValueStore, Storage};

pub enum QueueType {
    OutQueue,
    InQueue,
    DeadLetterQueue, // For messages that could not be delivered
}

impl QueueType {
    fn as_str(&self) -> &'static str {
        match self {
            QueueType::OutQueue => "outqueue",
            QueueType::InQueue => "inqueue",
            QueueType::DeadLetterQueue => "deadletterqueue",
        }
    }
}

pub struct BrokerNodeStorage {
    storage: Rc<Storage>,
    name: String,
}

impl BrokerNodeStorage {
    pub fn new(storage: Rc<Storage>, name: &str) -> Self {
        Self {
            storage,
            name: name.to_string(),
        }
    }

    fn msg_key(
        &self,
        queue: &QueueType,
        uid: u64,
        pubk_hash: &str,
        tag: &str,
    ) -> Result<String, BrokerStorageError> {
        validate_pubkey_hash(pubk_hash).map_err(BrokerStorageError::InvalidIdentifier)?;
        Ok(format!(
            "broker/{}/{}/msgs/{}/{}/{}",
            queue.as_str(),
            self.name,
            uid,
            pubk_hash,
            tag
        ))
    }

    fn msgs_prefix(&self, queue: &QueueType) -> String {
        format!("broker/{}/{}/msgs/", queue.as_str(), self.name)
    }

    fn uid_key(&self, queue: &QueueType) -> String {
        format!("broker/{}/{}/uid", queue.as_str(), self.name)
    }

    fn next_uid(&self, queue: &QueueType) -> Result<u64, BrokerStorageError> {
        let key = self.uid_key(queue);
        let uid: u64 = self.storage.get(&key, None)?.unwrap_or(0) + 1;
        self.storage.set(&key, uid, None)?;
        Ok(uid)
    }

    // Splits the trailing fields out of a key, which sit at index 5 and 6.
    fn key_fields(key: &str) -> Result<(&str, &str), BrokerStorageError> {
        let parts: Vec<&str> = key.split('/').collect();
        if parts.len() != 7 {
            return Err(BrokerStorageError::MalformedKey(key.to_string()));
        }
        Ok((parts[5], parts[6]))
    }

    // Destination of an out or dead letter row.
    pub fn dest_from_key(key: &str) -> Result<(PubkHash, SocketAddr), BrokerStorageError> {
        let (pubk_hash, address) = Self::key_fields(key)?;
        let address = address
            .parse()
            .map_err(|_| BrokerStorageError::MalformedKey(key.to_string()))?;
        Ok((pubk_hash.to_string(), address))
    }

    // Sender of an in queue row.
    pub fn sender_from_key(key: &str) -> Result<Identifier, BrokerStorageError> {
        let (pubk_hash, id) = Self::key_fields(key)?;
        let id = id
            .parse::<u8>()
            .map_err(|_| BrokerStorageError::MalformedKey(key.to_string()))?;
        Ok(Identifier::new(pubk_hash.to_string(), id))
    }

    // Keys of a queue ordered by the uid embedded in the key. At most max of them when given (the oldest ones).
    pub fn sorted_keys(
        &self,
        queue: &QueueType,
        max: Option<usize>,
    ) -> Result<Vec<String>, BrokerStorageError> {
        let mut keys = self
            .storage
            .partial_compare_keys(&self.msgs_prefix(queue), None)?;
        keys.sort_by_key(|key| {
            key.split('/')
                .nth(4) // index position
                .and_then(|s| s.parse::<u64>().ok())
                .unwrap_or(u64::MAX)
        });
        if let Some(max) = max {
            keys.truncate(max);
        }
        Ok(keys)
    }

    pub fn get(&self, key: &str) -> Result<Option<String>, BrokerStorageError> {
        Ok(self.storage.get(key, None)?)
    }

    pub fn set(&self, key: &str, value: &str) -> Result<(), BrokerStorageError> {
        self.storage.set(key, value, None)?;
        Ok(())
    }

    pub fn remove(&self, key: &str) -> Result<(), BrokerStorageError> {
        self.storage.remove(key, None)?;
        Ok(())
    }

    pub fn enqueue_out(
        &self,
        pubk_hash: &PubkHash,
        address: &SocketAddr,
        raw: &str,
    ) -> Result<(), BrokerStorageError> {
        let uid = self.next_uid(&QueueType::OutQueue)?;
        let key = self.msg_key(&QueueType::OutQueue, uid, pubk_hash, &address.to_string())?;
        self.storage.set(&key, raw, None)?;
        Ok(())
    }

    pub fn enqueue_deadletter(
        &self,
        pubk_hash: &PubkHash,
        address: &SocketAddr,
        raw: &str,
    ) -> Result<(), BrokerStorageError> {
        let uid = self.next_uid(&QueueType::DeadLetterQueue)?;
        let key = self.msg_key(
            &QueueType::DeadLetterQueue,
            uid,
            pubk_hash,
            &address.to_string(),
        )?;
        self.storage.set(&key, raw, None)?;
        Ok(())
    }

    // Moves messages into the in queue in one transaction, keyed by the uid they already carry so
    // the order the broker assigned is preserved.
    pub fn store_in_msgs(&self, msgs: &[Message]) -> Result<(), BrokerStorageError> {
        let tx = self.storage.begin_transaction();
        for msg in msgs {
            let key = self.msg_key(
                &QueueType::InQueue,
                msg.uid,
                &msg.from.pubkey_hash,
                &msg.from.id.to_string(),
            )?;
            self.storage.set(&key, msg.msg.clone(), Some(tx))?;
        }
        self.storage.commit_transaction(tx)?;
        Ok(())
    }
}
