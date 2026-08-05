use crate::{
    identification::identifier::Identifier,
    rpc::{
        errors::{BrokerError, MutexExt},
        Message,
    },
    storage::StorageApi,
};
use std::sync::{Arc, Mutex};

pub struct LocalChannel<S: StorageApi> {
    my_id: Identifier, // Public key hash
    storage: Arc<Mutex<S>>,
}

impl<S> LocalChannel<S>
where
    S: StorageApi,
{
    pub fn new(my_id: Identifier, storage: Arc<Mutex<S>>) -> Self {
        Self { my_id, storage }
    }

    pub fn new_simple(pubk_hash: String, storage: Arc<Mutex<S>>) -> Self {
        let my_id = Identifier {
            pubkey_hash: pubk_hash,
            id: 0, // Default to 0 if not provided
        };
        Self::new(my_id, storage)
    }

    pub fn send(&self, dest: &Identifier, msg: String) -> Result<bool, BrokerError> {
        self.storage.lock_or_err::<BrokerError>("storage")?.insert(
            self.my_id.clone(),
            dest.clone(),
            msg,
        )?;
        Ok(true)
    }

    pub fn get(&self) -> Result<Option<Message>, BrokerError> {
        Ok(self
            .storage
            .lock_or_err::<BrokerError>("storage")?
            .get(self.my_id.clone())?)
    }

    pub fn get_all(&self) -> Result<Vec<Message>, BrokerError> {
        Ok(self
            .storage
            .lock_or_err::<BrokerError>("storage")?
            .get_all(self.my_id.clone())?)
    }

    pub fn ack(&self, uid: u64) -> Result<bool, BrokerError> {
        Ok(self
            .storage
            .lock_or_err::<BrokerError>("storage")?
            .remove(self.my_id.clone(), uid)?)
    }

    pub fn recv(&self) -> Result<Option<(String, Identifier)>, BrokerError> {
        if let Some(msg) = self.get()? {
            self.ack(msg.uid)?;
            Ok(Some((msg.msg, msg.from)))
        } else {
            Ok(None)
        }
    }
}
