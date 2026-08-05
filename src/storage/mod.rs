use crate::identification::identifier::Identifier;
use crate::rpc::{errors::BrokerRpcError, Message};

pub mod memory;

#[cfg(feature = "storagebackend")]
pub mod db;

pub trait StorageApi {
    fn get(&mut self, dest: Identifier) -> Result<Option<Message>, BrokerRpcError>;
    fn get_all(&mut self, dest: Identifier) -> Result<Vec<Message>, BrokerRpcError>;
    fn insert(
        &mut self,
        from: Identifier,
        dest: Identifier,
        msg: String,
    ) -> Result<(), BrokerRpcError>;
    fn remove(&mut self, dest: Identifier, uid: u64) -> Result<bool, BrokerRpcError>;
}
