use crate::{
    identification::identifier::Identifier,
    rpc::{errors::BrokerError, Message},
    storage::BrokerServerStorage,
};
/// A local channel for communication between the broker and its clients.
pub struct LocalChannel {
    my_id: Identifier, // Public key hash
    storage: BrokerServerStorage,
}

impl LocalChannel {
    /// Only a BrokerServer can build one, so the channel always shares the storage of the
    /// server it talks to. See BrokerServer::create_local_channel.
    pub(crate) fn new(my_id: Identifier, storage: BrokerServerStorage) -> Self {
        Self { my_id, storage }
    }

    pub fn send(&self, dest: &Identifier, msg: String) -> Result<(), BrokerError> {
        self.storage.insert(self.my_id.clone(), dest.clone(), msg)?;
        Ok(())
    }

    pub fn get(&self) -> Result<Option<Message>, BrokerError> {
        Ok(self.storage.get(self.my_id.clone())?)
    }

    pub fn get_all(&self) -> Result<Vec<Message>, BrokerError> {
        Ok(self.storage.get_all(self.my_id.clone(), None)?)
    }

    /// Like [`LocalChannel::get_all`] but stops at max. What is left over stays in storage for the next call.
    pub(crate) fn get_up_to(&self, max: usize) -> Result<Vec<Message>, BrokerError> {
        Ok(self.storage.get_all(self.my_id.clone(), Some(max))?)
    }

    pub fn ack(&self, uid: u64) -> Result<bool, BrokerError> {
        Ok(self.storage.remove(self.my_id.clone(), uid)?)
    }

    /// Acknowledges before the caller has seen the message, so a failure afterwards loses it. Use
    /// [`LocalChannel::get`] and [`LocalChannel::ack`] separately when the message must survive that.
    pub fn recv(&self) -> Result<Option<(String, Identifier)>, BrokerError> {
        if let Some(msg) = self.get()? {
            self.ack(msg.uid)?;
            Ok(Some((msg.msg, msg.from)))
        } else {
            Ok(None)
        }
    }
}
