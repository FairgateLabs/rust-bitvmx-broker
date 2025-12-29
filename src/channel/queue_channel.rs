use std::{
    net::SocketAddr,
    rc::Rc,
    sync::{Arc, Mutex},
};

use storage_backend::{
    storage::{KeyValueStore, Storage},
    storage_config::StorageConfig,
};
use tokio::runtime::Runtime;
use tracing::{info, warn};

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
    rt: Arc<Mutex<Runtime>>,
}

enum QueueType {
    OutQueue,
    InQueue,
}

impl ToString for QueueType {
    fn to_string(&self) -> String {
        match self {
            QueueType::OutQueue => "outqueue".to_string(),
            QueueType::InQueue => "inqueue".to_string(),
        }
    }
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

        let rt = Arc::new(Mutex::new(Runtime::new()?));

        Ok(Self {
            name: name.to_string(),
            server,
            local_channel,
            cert,
            address,
            storage,
            allow_list,
            routing_table,
            rt,
        })
    }

    fn storage_out_key(&self, id: u64, pubk_hash: &PubkHash, address: &SocketAddr) -> String {
        format!(
            "broker/{}/{}/msgs/{}/{}/{}",
            QueueType::OutQueue.to_string(),
            self.name,
            id,
            pubk_hash,
            address
        )
    }

    fn storage_in_key(&self, id: u64, identifier: &Identifier) -> String {
        format!(
            "broker/{}/{}/msgs/{}/{}/{}",
            QueueType::InQueue.to_string(),
            self.name,
            id,
            identifier.pubkey_hash,
            identifier.id
        )
    }

    fn storage_idx_key(&self, queue: &QueueType) -> String {
        format!("broker/{}/{}/uid", queue.to_string(), self.name)
    }

    fn partial_compare_keys(&self, queue: &QueueType) -> String {
        format!("broker/{}/{}/msgs/", queue.to_string(), self.name)
    }

    fn get_next_idx(&self, queue: &QueueType) -> Result<u64, BrokerError> {
        let key = self.storage_idx_key(queue);
        let current_idx: u64 = self.storage.get(&key).unwrap_or(None).unwrap_or(0) + 1;
        self.storage.set(&key, current_idx, None)?;
        Ok(current_idx)
    }

    fn enqueue_out_msg(
        &self,
        pubk_hash: &PubkHash,
        address: &SocketAddr,
        data: Vec<u8>,
    ) -> Result<(), BrokerError> {
        let idx = self.get_next_idx(&QueueType::OutQueue)?;
        let key = self.storage_out_key(idx, pubk_hash, address);
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
        self.enqueue_out_msg(pubk_hash, &address, data)?;
        Ok(())
    }

    fn process_out_queue(&self) -> Result<(), BrokerError> {
        let mut storage_keys = self
            .storage
            .partial_compare_keys(&self.partial_compare_keys(&QueueType::OutQueue))?
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
                } else {
                    warn!(
                        "Failed to send queued message to {} at {}",
                        pubk_hash, address_str
                    );
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

        let sync_client = SyncClient::new_with_runtime(
            &server_config,
            self.cert.clone(),
            self.allow_list.clone(),
            self.rt.clone(),
        )?;

        let identifier = Identifier::new(dest_pubk_hash.to_string(), COMMS_ID);
        sync_client.send_msg(COMMS_ID, identifier, msg)
    }

    fn process_in_queue(&self) -> Result<(), BrokerError> {
        let tx = self.storage.begin_transaction();

        let mut msg_uids = vec![];
        for msg in self.local_channel.get_all()? {
            msg_uids.push(msg.uid);
            let key = self.storage_in_key(msg.uid, &msg.from);
            self.storage.set(&key, msg.msg, Some(tx))?;
        }
        self.storage.commit_transaction(tx)?;

        info!(
            "Moved {} messages from localchannel to inqueu",
            msg_uids.len()
        );
        for uid in msg_uids {
            self.local_channel.ack(uid)?;
        }

        Ok(())
    }

    pub fn tick(&self) -> Result<(), BrokerError> {
        self.process_out_queue()?;
        self.process_in_queue()?;
        Ok(())
    }

    pub fn check_receive(&mut self) -> Result<Vec<ReceiveHandlerChannel>, BrokerError> {
        let mut storage_keys = self
            .storage
            .partial_compare_keys(&self.partial_compare_keys(&QueueType::InQueue))?
            .into_iter()
            .collect::<Vec<String>>();

        storage_keys.sort();

        let mut messages = vec![];

        for key in storage_keys {
            if let Some(data) = self.storage.get(&key)? {
                let x: String = data;
                let parts: Vec<&str> = key.split('/').collect();
                if parts.len() < 7 {
                    continue;
                }
                let pubk_hash = parts[5];
                let id = parts[6];

                let msg = Identifier::new(pubk_hash.to_string(), id.parse::<u8>()?);
                let data = serde_json::from_str::<Vec<u8>>(&x)?;

                messages.push(ReceiveHandlerChannel::Msg(msg, data));

                self.storage.delete(&key)?;
            }
        }

        Ok(messages)
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
