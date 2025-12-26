use std::{
    net::SocketAddr,
    rc::Rc,
    sync::{Arc, Mutex},
};

use storage_backend::{
    storage::{KeyValueStore, Storage},
    storage_config::StorageConfig,
};
use tracing::{error, info};

const COMMS_ID: u8 = 0;

use crate::{
    broker_storage::BrokerStorage,
    channel::channel::LocalChannel,
    identification::{
        allow_list::AllowList,
        identifier::{Identifier, PubkHash},
        routing::RoutingTable,
    },
    rpc::{
        errors::BrokerError, sync_client::SyncClient, sync_server::BrokerSync, tls_helper::Cert,
        BrokerConfig,
    },
};

#[derive(Debug)]
pub enum ReceiveHandlerChannel {
    Msg(Identifier, Vec<u8>), //Id, Msg
    Error(BrokerError),
}

pub struct QueueChannel {
    name: String,
    server: BrokerSync,
    local_channel: LocalChannel<BrokerStorage>,
    cert: Cert,
    address: SocketAddr,
    storage: Rc<Storage>,
    allow_list: Arc<Mutex<AllowList>>,
    routing_table: Arc<Mutex<RoutingTable>>,
}

impl QueueChannel {
    pub fn new(
        name: &str,
        address: SocketAddr,
        privk: &str, //File with PEM format
        storage: Rc<Storage>,
        storage_path: Option<String>,
        allow_list_path: &str,
        routing_table_path: &str,
    ) -> Result<Self, BrokerError> {
        // Initialize path for receiving message storage
        let storage_path = match storage_path {
            Some(path) => path,
            None => format!("/tmp/broker_comms_{}", address.port()),
        };
        let config = StorageConfig::new(storage_path.clone(), None);
        let broker_backend = Storage::new(&config)?;
        let broker_backend = Arc::new(Mutex::new(broker_backend));
        let broker_storage = Arc::new(Mutex::new(BrokerStorage::new(broker_backend)));

        let cert = Cert::from_key_file(privk)?;
        let pubk_hash = cert.get_pubk_hash()?;
        let broker_config =
            BrokerConfig::new(address.port(), Some(address.ip()), pubk_hash.clone());

        let allow_list = AllowList::from_file(allow_list_path)?;
        let routing_table = RoutingTable::load_from_file(routing_table_path)?;

        let server = BrokerSync::new(
            &broker_config,
            broker_storage.clone(),
            cert.clone(),
            allow_list.clone(),
            routing_table.clone(),
        )?;

        let local_channel = LocalChannel::new(
            Identifier {
                pubkey_hash: pubk_hash.clone(),
                id: COMMS_ID,
            },
            broker_storage.clone(),
        );

        Ok(Self {
            name: name.to_string(),
            server,
            local_channel,
            cert,
            address,
            storage,
            allow_list,
            routing_table,
        })
    }

    fn storage_key(&self, id: u64, pubk_hash: &PubkHash, address: &SocketAddr) -> String {
        format!(
            "broker/queue/{}/msgs/{}/{}/{}",
            self.name, id, pubk_hash, address
        )
    }

    fn storage_idx_key(&self) -> String {
        format!("broker/queue/{}/uid", self.name)
    }

    fn get_next_idx(&self) -> Result<u64, BrokerError> {
        let key = self.storage_idx_key();
        let current_idx: u64 = self.storage.get(&key).unwrap_or(None).unwrap_or(0) + 1;
        self.storage.set(&key, current_idx, None)?;
        Ok(current_idx)
    }

    fn enqueue_msg(
        &self,
        pubk_hash: &PubkHash,
        address: &SocketAddr,
        data: Vec<u8>,
    ) -> Result<(), BrokerError> {
        let idx = self.get_next_idx()?;
        let key = self.storage_key(idx, pubk_hash, address);
        let data = serde_json::to_string(&data)?;

        self.storage.set(&key, data, None)?;

        Ok(())
    }

    pub fn send(
        &self,
        pubk_hash: &PubkHash,
        address: SocketAddr,
        data: Vec<u8>,
    ) -> Result<(), BrokerError> {
        self.enqueue_msg(pubk_hash, &address, data)?;

        Ok(())
    }

    pub fn tick(&self) -> Result<(), BrokerError> {
        let mut storage_keys = self
            .storage
            .partial_compare_keys(&format!("broker/queue/{}/msgs/", self.name))?
            .into_iter()
            .collect::<Vec<String>>();

        storage_keys.sort();

        //TODO: send up to X messages per tick
        //TOOD: split in pubk_hash batcher to avoid one destination flooding the rest
        //TODO: limit rate of sending and retries
        for key in storage_keys {
            if let Some(data) = self.storage.get(&key)? {
                let parts: Vec<&str> = key.split('/').collect();
                if parts.len() < 7 {
                    continue;
                }
                let pubk_hash = parts[5];
                let address_str = parts[6];
                info!(
                    "Attempting to send queued message to {} at {}",
                    pubk_hash, address_str
                );
                let address: SocketAddr = address_str.parse()?;

                if self
                    .internal_send(&address, pubk_hash, data)
                    .is_ok_and(|x| x)
                {
                    self.storage.delete(&key)?;
                }
            }
        }

        Ok(())
    }

    fn internal_send(
        &self,
        address: &SocketAddr,
        dest_pubk_hash: &str,
        msg: String,
    ) -> Result<bool, BrokerError> {
        // It doesnt check address when sending data, only when receiving
        let server_config = BrokerConfig::new(
            address.port(),
            Some(address.ip()),
            dest_pubk_hash.to_string(),
        );

        let sync_client =
            SyncClient::new(&server_config, self.cert.clone(), self.allow_list.clone())?;

        let identifier = Identifier::new(dest_pubk_hash.to_string(), COMMS_ID);
        sync_client.send_msg(COMMS_ID, identifier, msg)
    }

    //TODO: Simplify check/internal_check/get
    pub fn check_receive(&mut self) -> Option<ReceiveHandlerChannel> {
        match self.internal_check_receive() {
            Ok(Some(receive)) => Some(receive),
            Ok(None) => None,
            Err(err) => {
                error!("{}", err);
                None
            }
        }
    }

    fn internal_check_receive(&mut self) -> Result<Option<ReceiveHandlerChannel>, BrokerError> {
        match self.get()? {
            Some((id, data)) => {
                let data = serde_json::from_str::<Vec<u8>>(&data.to_string())?;
                info!("Receive data from id: {}: {:?}", id, data);
                Ok(Some(ReceiveHandlerChannel::Msg(id, data)))
            }
            None => Ok(None),
        }
    }

    fn get(&self) -> Result<Option<(Identifier, String)>, BrokerError> {
        //TODO: move all into inbound queue, and if successful ack then remove from there
        if let Some((data, identifier)) = self.local_channel.recv()? {
            info!(
                "Received data {:?} from broker with id {}",
                data, identifier
            );
            Ok(Some((identifier, data)))
        } else {
            Ok(None)
        }
    }

    pub fn get_pubk_hash(&self) -> Result<PubkHash, BrokerError> {
        let pubk_hash = self.cert.get_pubk_hash()?;
        Ok(pubk_hash)
    }

    pub fn get_address(&self) -> SocketAddr {
        self.address
    }

    pub fn close(&mut self) {
        self.server.close();
    }

    pub fn get_routing_table(&self) -> Arc<Mutex<RoutingTable>> {
        Arc::clone(&self.routing_table)
    }

    pub fn get_allow_list(&self) -> Arc<Mutex<AllowList>> {
        Arc::clone(&self.allow_list)
    }
}
