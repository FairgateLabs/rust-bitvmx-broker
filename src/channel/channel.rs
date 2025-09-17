use crate::{
    identification::{allow_list::AllowList, identifier::Identifier},
    rpc::{
        errors::{BrokerError, MutexExt},
        sync_client::SyncClient,
        tls_helper::Cert,
        BrokerConfig, Message, StorageApi,
    },
};
use std::{
    net::{IpAddr, Ipv4Addr},
    sync::{Arc, Mutex},
};

#[derive(Clone, Debug)]
pub struct DualChannel {
    client: SyncClient,
    my_id: Identifier,
    dest_id: Identifier, // Identifier of the destination
}

impl DualChannel {
    // The config is of the node you want to connect to
    pub fn new(
        config: &BrokerConfig,
        my_cert: Cert,
        my_id: Option<u8>,
        my_ip: IpAddr,
        allow_list: Option<Arc<Mutex<AllowList>>>, // If it's None, the allow list will contain only the one in config
    ) -> Result<Self, crate::rpc::errors::BrokerError> {
        let allow_list = match allow_list {
            Some(al) => al,
            None => {
                let server_identifier = Identifier::new(config.get_pubk_hash(), 0, config.get_ip()); // ID is 0 for the server
                AllowList::from_identifiers(vec![server_identifier]).map_err(|e| {
                    BrokerError::Other(format!(
                        "Failed to create allow list from config identifier: {}",
                        e
                    ))
                })?
            }
        };
        let client = SyncClient::new(config, my_cert.clone(), allow_list)?;
        let my_id = Identifier {
            pubkey_hash: my_cert.get_pubk_hash()?,
            id: Some(my_id.unwrap_or(0)), // Default to 0 if not provided
            ip: my_ip,
        };
        let dest_id = Identifier {
            pubkey_hash: config.get_pubk_hash(),
            id: Some(config.get_id()),
            ip: config.get_ip(),
        };
        Ok(Self {
            client,
            my_id,
            dest_id,
        })
    }

    // Do not use in production, this is for testing purposes only
    pub fn new_simple(
        config: &BrokerConfig,
        my_id: u8,
    ) -> Result<(Self, Identifier), crate::rpc::errors::BrokerError> {
        let my_cert = Cert::new()?;
        let my_ip = IpAddr::V4(Ipv4Addr::LOCALHOST);
        let allow_list = AllowList::new();
        allow_list
            .lock_or_err::<BrokerError>("allow_llist")?
            .allow_all();
        let my_identifier = Identifier {
            pubkey_hash: my_cert.get_pubk_hash()?,
            id: Some(my_id),
            ip: my_ip,
        };
        Ok((
            Self::new(config, my_cert, Some(my_id), my_ip, Some(allow_list))?,
            my_identifier,
        ))
    }

    pub fn send(
        &self,
        dest: Identifier,
        msg: String,
    ) -> Result<bool, crate::rpc::errors::BrokerError> {
        self.client.send_msg(self.my_id.id.unwrap_or(0), dest, msg)
    }

    // Dest is the identifier in config
    pub fn send_server(&self, msg: String) -> Result<bool, crate::rpc::errors::BrokerError> {
        self.client
            .send_msg(self.my_id.id.unwrap_or(0), self.dest_id.clone(), msg)
    }

    pub fn recv(&self) -> Result<Option<(String, Identifier)>, crate::rpc::errors::BrokerError> {
        if let Some(msg) = self.client.get_msg(self.my_id.clone())? {
            self.client.ack(self.my_id.clone(), msg.uid)?;
            Ok(Some((msg.msg, msg.from)))
        } else {
            Ok(None)
        }
    }
}

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
            id: Some(0), // Default to 0 if not provided
            ip: IpAddr::V4(Ipv4Addr::LOCALHOST),
        };
        Self::new(my_id, storage)
    }
    /*  fn get(&mut self, dest: String) -> Option<Message>;
    fn insert(&mut self, from: String, dest: String, msg: String);
    fn remove(&mut self, dest: String, uid: u64) -> bool;*/
    pub fn send(&self, dest: Identifier, msg: String) -> Result<bool, BrokerError> {
        self.storage
            .lock_or_err::<BrokerError>("storage")?
            .insert(self.my_id.clone(), dest, msg);
        Ok(true)
    }

    pub fn get(&self, dest: Identifier) -> Result<Option<Message>, BrokerError> {
        Ok(self
            .storage
            .lock_or_err::<BrokerError>("storage")?
            .get(dest))
    }

    pub fn ack(&self, dest: Identifier, uid: u64) -> Result<bool, BrokerError> {
        Ok(self
            .storage
            .lock_or_err::<BrokerError>("storage")?
            .remove(dest, uid))
    }

    pub fn recv(&self) -> Result<Option<(String, Identifier)>, BrokerError> {
        if let Some(msg) = self.get(self.my_id.clone())? {
            self.ack(self.my_id.clone(), msg.uid)?;
            Ok(Some((msg.msg, msg.from)))
        } else {
            Ok(None)
        }
    }
}
