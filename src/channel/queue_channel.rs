use std::{
    collections::HashMap,
    net::SocketAddr,
    rc::Rc,
    sync::{Arc, Mutex},
};

use serde::{Deserialize, Serialize};
use storage_backend::{
    storage::{KeyValueStore, Storage},
    storage_config::StorageConfig,
};
use tokio::runtime::Runtime;
use tracing::{info, warn};

const COMMS_ID: u8 = 0;
const MAX_MSGS_PER_TICK_UTILIZATION: f64 = 0.5; // 50% of capacity
const MAX_SEND_ATTEMPTS: u8 = 5; // Max attempts to send a message before moving to dead letter queue

use crate::{
    broker_storage::BrokerStorage,
    channel::channel::LocalChannel,
    identification::{
        allow_list::AllowList,
        identifier::{Identifier, PubkHash},
        routing::RoutingTable,
    },
    rpc::{
        errors::BrokerError,
        rate_limiter::{RATE_LIMIT_CAPACITY, TOKENS_PER_MESSAGE},
        sync_client::SyncClient,
        sync_server::BrokerSync,
        tls_helper::Cert,
        BrokerConfig,
    },
};

#[derive(Debug)]
pub enum ReceiveHandlerChannel {
    Msg(Identifier, Vec<u8>), //Id, Msg
    Error(BrokerError),
}

#[derive(Serialize, Deserialize)]
struct OutgoingMsg {
    payload: Vec<u8>,
    ctx: String, // Program context
    attempts: u8,
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
    DeadLetterQueue, // For messages that could not be delivered
}

impl ToString for QueueType {
    fn to_string(&self) -> String {
        match self {
            QueueType::OutQueue => "outqueue".to_string(),
            QueueType::InQueue => "inqueue".to_string(),
            QueueType::DeadLetterQueue => "deadletterqueue".to_string(),
        }
    }
}

impl QueueChannel {
    pub fn new(
        name: &str,
        address: SocketAddr,
        privk: &str,
        storage: Rc<Storage>,
        storage_path: Option<String>,
        allow_list: Arc<Mutex<AllowList>>,
        routing_table: Arc<Mutex<RoutingTable>>,
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

        let cert = Cert::new_with_privk(privk)?;
        let pubk_hash = cert.get_pubk_hash()?;
        let broker_config =
            BrokerConfig::new(address.port(), Some(address.ip()), pubk_hash.clone());

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

    pub fn new_with_paths(
        name: &str,
        address: SocketAddr,
        privk: &str, //File with PEM format
        storage: Rc<Storage>,
        storage_path: Option<String>,
        allow_list: &str,
        routing_table: &str,
    ) -> Result<Self, BrokerError> {
        let allow_list = AllowList::from_file(allow_list)?;
        let routing_table = RoutingTable::from_file(routing_table)?;
        let privk = std::fs::read_to_string(privk)?;
        Self::new(
            name,
            address,
            &privk,
            storage,
            storage_path,
            allow_list,
            routing_table,
        )
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

    fn storage_deadletter_key(
        &self,
        id: u64,
        pubk_hash: &PubkHash,
        address: &SocketAddr,
    ) -> String {
        format!(
            "broker/{}/{}/msgs/{}/{}/{}",
            QueueType::DeadLetterQueue.to_string(),
            self.name,
            id,
            pubk_hash,
            address
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
        ctx: &str,
        pubk_hash: &PubkHash,
        address: &SocketAddr,
        data: Vec<u8>,
    ) -> Result<(), BrokerError> {
        let idx = self.get_next_idx(&QueueType::OutQueue)?;
        let key = self.storage_out_key(idx, pubk_hash, address);
        let msg = OutgoingMsg {
            payload: data,
            ctx: ctx.to_string(),
            attempts: 0, // initial attempt
        };

        self.storage.set(&key, serde_json::to_string(&msg)?, None)?;

        Ok(())
    }

    fn enqueue_deadletter_msg(
        &self,
        pubk_hash: &PubkHash,
        address: &SocketAddr,
        data: &str,
    ) -> Result<(), BrokerError> {
        let idx = self.get_next_idx(&QueueType::DeadLetterQueue)?;
        let key = self.storage_deadletter_key(idx, pubk_hash, address);

        self.storage.set(&key, data, None)?;

        Ok(())
    }

    pub fn send(
        &self,
        ctx: &str,
        pubk_hash: &PubkHash,
        address: SocketAddr,
        data: Vec<u8>,
    ) -> Result<(), BrokerError> {
        self.enqueue_out_msg(ctx, pubk_hash, &address, data)?;
        Ok(())
    }

    fn process_out_queue(&self) -> Result<(), BrokerError> {
        let mut storage_keys = self
            .storage
            .partial_compare_keys(&self.partial_compare_keys(&QueueType::OutQueue))?
            .into_iter()
            .collect::<Vec<String>>();
        storage_keys.sort_by_key(|key| {
            key.split('/')
                .nth(4) // index position
                .and_then(|s| s.parse::<u64>().ok())
                .unwrap_or(u64::MAX)
        });

        // send up to 50% of max capacity messages per tick
        let mut sent_per_dest: HashMap<String, usize> = HashMap::new();
        let max_per_dest = self.max_msgs_per_tick(MAX_MSGS_PER_TICK_UTILIZATION); // use 50% of capacity

        for key in storage_keys {
            if let Some(raw) = self.storage.get::<_, String>(&key)? {
                let mut msg: OutgoingMsg = serde_json::from_str(&raw)?;
                let parts: Vec<&str> = key.split('/').collect();
                if parts.len() < 7 {
                    continue;
                }
                let pubk_hash = parts[5];
                let address_str = parts[6];

                let address: SocketAddr = address_str.parse()?;

                // check if destination has not exceeded max messages per tick by destination pubk_hash
                let sent = sent_per_dest.entry(pubk_hash.to_owned()).or_insert(0);
                if *sent >= max_per_dest {
                    continue; // destination exhausted for this tick
                }

                info!(
                    "Attempting to send queued message to {} at {}",
                    pubk_hash, address_str
                );

                if self
                    .internal_send(&address, pubk_hash, serde_json::to_string(&msg.payload)?)
                    .is_ok_and(|x| x)
                {
                    self.storage.delete(&key)?;
                    *sent += 1;
                } else {
                    warn!(
                        "Failed to send queued message to {} at {}",
                        pubk_hash, address_str
                    );
                    msg.attempts += 1;

                    // If max attempts reached, move to dead letter queue
                    if msg.attempts >= MAX_SEND_ATTEMPTS {
                        warn!(
                            "Dropping message to {} after {} attempts",
                            pubk_hash, msg.attempts
                        );
                        self.enqueue_deadletter_msg(&pubk_hash.to_string(), &address, &raw)?;
                        self.storage.delete(&key)?;
                    } else {
                        self.storage.set(&key, serde_json::to_string(&msg)?, None)?;
                    }

                    *sent = max_per_dest; // stop trying to send to this destination this tick
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

    fn check_reception(
        &mut self,
        queue_type: &QueueType,
    ) -> Result<Vec<(ReceiveHandlerChannel, Option<String>)>, BrokerError> {
        let mut storage_keys = self
            .storage
            .partial_compare_keys(&self.partial_compare_keys(queue_type))?
            .into_iter()
            .collect::<Vec<String>>();
        storage_keys.sort_by_key(|key| {
            key.split('/')
                .nth(4) // index position
                .and_then(|s| s.parse::<u64>().ok())
                .unwrap_or(u64::MAX)
        });

        let mut messages = vec![];

        for key in storage_keys {
            if let Some(data) = self.storage.get(&key)? {
                let x: String = data;
                let parts: Vec<&str> = key.split('/').collect();
                if parts.len() < 7 {
                    continue;
                }
                let pubk_hash = parts[5];

                let (identifier, data, ctx) = match queue_type {
                    QueueType::InQueue => {
                        let id = parts[6].parse::<u8>()?;
                        let identifier = Identifier::new(pubk_hash.to_string(), id);
                        let data = serde_json::from_str::<Vec<u8>>(&x)?;
                        (identifier, data, None)
                    }
                    QueueType::DeadLetterQueue => {
                        // No receiver id in deadletter, use COMMS_ID as default
                        let identifier = Identifier::new(pubk_hash.to_string(), COMMS_ID);
                        let msg = serde_json::from_str::<OutgoingMsg>(&x)?;
                        let data = msg.payload;
                        (identifier, data, Some(msg.ctx))
                    }
                    _ => continue,
                };

                messages.push((ReceiveHandlerChannel::Msg(identifier, data), ctx));

                self.storage.delete(&key)?;
            }
        }

        Ok(messages)
    }

    pub fn check_receive(&mut self) -> Result<Vec<ReceiveHandlerChannel>, BrokerError> {
        self.check_reception(&QueueType::InQueue)?
            .into_iter()
            .map(|(channel, err)| {
                if let Some(err) = err {
                    Err(BrokerError::InvalidMessageContext {
                        expected: "None".to_owned(),
                        got: err,
                    })
                } else {
                    Ok(channel)
                }
            })
            .collect()
    }

    // Returns messages in dead letter queue with their corresponding context
    pub fn check_deadletter(
        &mut self,
    ) -> Result<Vec<(ReceiveHandlerChannel, String)>, BrokerError> {
        self.check_reception(&QueueType::DeadLetterQueue)?
            .into_iter()
            .map(|(channel, err)| {
                if let Some(err) = err {
                    Ok((channel, err))
                } else {
                    Err(BrokerError::InvalidMessageContext {
                        expected: "Some context".to_owned(),
                        got: "None".to_owned(),
                    })
                }
            })
            .collect()
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

    fn max_msgs_per_tick(&self, utilization: f64) -> usize {
        assert!((0.0..=1.0).contains(&utilization));

        let max_msgs = RATE_LIMIT_CAPACITY / TOKENS_PER_MESSAGE;
        ((max_msgs as f64) * utilization).floor() as usize
    }
}

#[cfg(test)]
mod tests {
    use std::{fs, path::PathBuf};

    use tracing_subscriber::{
        fmt::format::FmtSpan, layer::SubscriberExt, util::SubscriberInitExt, EnvFilter,
    };

    use super::*;

    const PRIVK1: &str = "b'-----BEGIN PRIVATE KEY-----\nMIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQDhzkbFynswfys/\nVNbM4hzYNKCdAuxYI/jysOPkRHGhlJe+71EE9F2CpAZnjevBsUWxi3+LatfMZjwi\nUz/l3iC6ow8Dsar0BO6RmWQR8Uf/1sx+WNjBk2woISPb60oXbXYj8AVUqYUUSo/Q\nRF5kuGT7dsMvUAx8Irn93w4A5VXx+FLn3r38Tymv7qOMT5cO1xrNStsluBD1RdPj\nz+B6b+7woAKqkrNFR+ZH0HUUKldA+A+pGElQLODyLB7OwxHgKtEsFdyiiDuKW2mP\nsk2dsab9HCNdo9cViA9UbeykDXq7h0/7gYg9XBH8LqqXYpSk/LE6T8k1RVa9EBxV\nRpYqlvFPAgMBAAECggEAV64pfRQq0aIPwP/IiLYkTS/iThWcgH03ZcWaOED7fqqc\nYd+7rhjVVq0qb3uEWCnlzhNE63YJZa0tHIcHANNIEjDO27hZkXd4y8CsQutV8doO\nfeEyCbic/tgffH3Yv1AZ18qTx1QsAL0TKuPhY2rWi26KTAzhTDKP1iyO23ox7Uqs\nwWChuHWyw7SmECRmjKOjTLs1Axea3fos6ERgEv/KZiTi+a9he5JuHOXO6aKTvHI7\nlTAMdloy1CnK6G3Ql7LfBeX20hIwDSZNgp5naB6NjJiDTbxxlGj7apW6hquzJpRP\n1Tn2YLvVKl5bdAOHh44wHBhZR9COjxUT+uASYRb5wQKBgQD7FTe3VPrsi6ejo7db\n9SwTUjsTQKoxrfoNc0xPzGGwKyyArGM++NQI1CZuQQDXVoYl+JC1JOcTLjjW/TYu\nwVGAr63bjtYjU0e8NZzum3nIZ7rpyHJpnbCLBc678KNCvblD4u/Vl1bx/9vRiCTx\n9S0r/LJ54Jr3Ohx9feYERc4K/QKBgQDmOlWNHwFlC2pkYI/0biXWybQZWvz+C5x3\nJO6tf0ykRk2sBEcp07JMhJsE+r4B+lHNSWalkX409Fn6x2ch/6tLP0X+viM5nr+2\nRpGHLpUBeq4+RKMmUS/NgY2DoRV1DRnfk4Vt0BZy5Voc4OVQz0zohwFzYhY60ThR\nV3UJ9HbdOwKBgQCcBS8+CNxzqMRe9xi1V8AvsWVsLT6U6Fr9iKve2k3JvspEmtqB\nAvYfFlVbJaF0Lhvl9HNXXLsKPCqtzWKh4xbWNFSAnl2KTfHBjj8aNhqS4YJQS3Jt\nFsPhX5Z7SqjojCRXfukxfH1Wm3ro1QTAJW4Qa1IsUdl5zu5tPJJ2DTpfsQKBgCii\nXR0mPsnFxQZoYKAEnNsXCJl9DLAN/pSsyQ+IK0/HNMhKjQDd41dMBExRsR2KP8va\ny6onTr4r7oGrlhFTHbmPNlxq1K7DzRRvyhmw6A21yHEnDiCiLay40/BKiw34vPtP\n/znNg1jOECSOsQqdO/bCdUgXJNNGwAjjRb33Ds+nAoGAW76wLk1lwD2tZ8KgMRUU\ni0BkY7eDXPskxCP6BjFq10J/1dC/dsLO9mZfwl2BJ2D+gGmcIzdSb5p1LkuniGuv\nV+/lSa8bdUKwtd5l+CZ0OMqmHryQZICqGeG5uREYv5eqs4mDiuM8QkZdOZUKWzPc\nwWJXrp5cQtvgjS/HyjHB69o=\n-----END PRIVATE KEY-----\n'";
    const PRIVK2: &str = "b'-----BEGIN PRIVATE KEY-----\nMIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQCeJYILLK2EpGP9\nCrlEeHL1hYODftAUxJTacRezNNuyAqqP04H0IFffXhdz/f54HnYnaN1VrMGNQlR5\nBashFjZa7fVEFp3osVgNEPNu63MA1Gr7o4BakopRbMx7jUyhmlJXNP3VX5tZEha+\nV7GOZEeh2Ej3pehnE/E6SD16Ez9aaGydFgrMALHjT2NfucK0XCcDvMbq53PsBaLm\nnH5TLnvtZvYmdyDoUe+RvlwaRAHv4AWDOElhQrj970giHWY6i9QgqrlTIYN5cQrD\nM6kNj1SaBtCNpG/wIK3NMLW7PAYeEKTopwdsFuVL+1e0IAsTIVpDC1mb3r2GlPji\n0GaMLBAHAgMBAAECggEAFPHDvMYgfuIkqeULL1HCa9jQV5Bqb22vhxSWPnIgLH2k\n6CJrYhEMgjUcZwy68F6caFC/i3KzOYmQ1WxWQy4Fadp88pUKOcCO+EAH9WcyVmhL\neOMpAxXIQstlc3F9tiNRh2IpweIFGXFHWNMVXVXTlNAnrcCnvEsMVhsuJSY6bDcV\n5ejQKE8kM8F30FzD2mii36XamsreMpQBAIlm0i1HH/8PpynUQ12bb2M0T/FR9C5V\nAbfeLUOgrzWgBs9hxmlBzILusJFjv7OvwIkF97GgoAyLKqFmxzncwQUTqh9iH2Js\nemN6Qg+vPIg2Et8Ku9XEX+CSXvDwFckB2Z14jqQw8QKBgQDPHDzAFDSTl+aPH+vd\n01wxtaFyP7KP2OaRabW1qzTPww87agbN3wPJqBBf9lEjVeGNjLrp2NyHX6Wfnt5V\nlpeWts13/M43rju2JJwOrfZnwJsJgQ9ZEQw30e1LWeiGpr0kcWlv2059tEiKgBwY\nNlw6evsCyFjrIuSqgg3riO9xMQKBgQDDel5TfTJ3BJZlgFYnU1YxUZDQ1mcMDnSK\ntdRLdpVWTEkjzf0a6rGJYla0NoqQdH9qDfimVMY6+RQLZVdhhXDVnQuwV0CK9ERY\nQWy/PEoPvIagTXgKJ8fKLYcG420fJJtPmTSEoPZg1PXtuABNj/68bI7ONL5CY6gO\n8iFJU0sGtwKBgA6mlLWRuFZofGrLe0fp16+8hXsrflomocjPjYcYYVgBGGa/jVOq\n3v244c+oAP1a6eW1etNn/9GjtnegKWIskPScYdSHEZ9mt9qepFt1euTD/zOg6ZEH\nX7HjK8IUzhoYWXDmhOrgvKCvzCHgBhzAW63XXUJJIeEgSsS1Bn8O5MFBAoGAMuiv\noDa+6dg8AvtFdMBzdiyz9m+gLrelCmsIew7LHcqIUdbX0CbHTexagFykAbMVa91v\noIH7jmhIHB+sfi1ukXNxE9/lY0rycbm4RKXC9A45UY5bcOmjUrhArj6UsMOr3zMb\nRl9VSyqrUdnV2l1iDliHaJS76DZkEmBk4t/abkkCgYEAxkk3skKgRJPt2bFLzdHV\n3Au24P/Cyqf1LIfXpuJcMBfAhw55g6DOLR4O0BH+s7cZk8hrGVeI9WyhC5EgzZrF\nBjTlZFqFtsz5psj1oNqgr/JnO2fL3csxbDR81q9uSSzdlN7BlzBpdQahi53K9MHi\nZDNGUy5a/PopNnWSzfHYUas=\n-----END PRIVATE KEY-----\n'";
    const PRIVK3: &str = "b'-----BEGIN PRIVATE KEY-----\nMIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQDK3zkTXQMEWbzL\nSRRBO7Wd657dQ/EifekFOIsDtiWHpjOdMRN9H25dVCkm5aBY2zNn62DzZcOlB57z\nUosALiPiyLrcDEu6w6efl3ZikkYD4gbfSKEAGDn1rLS/eUlM61hrgv7ibeqc8grA\nOo9ksWk9JKalCs0gRkufJn9fmiKmKDYDYkzMfSWZ0hDSL6kcy1ZfQLjDpwT6TJXm\nwVN7X6y25Men1v///qlXlBuIf/o1KtXG2v31NWHP0rxHiu5nCG1vGGenGF8y1puK\nVf+OhyqzPhter9gi5wqLo6QQjzyJt/71WDydVmjMDz30QDJrokV8JFu2zPJiG99u\nrIs9BqyfAgMBAAECggEAVn2ho0A5y46In3B6Gq+eqAOuuK3BLc/ZWxj2p2/uAy2X\n/rHQGb2fO1noq4UlfgyCF5FxxYNCzGZ53Un5KewB76tdgvgZBzhoC/GyjqbHA9vG\ny0X3IgeyGiv16VYHqqwBh+CS0y1CY4QLklXFEYxTjjZEd8OpnVNq5SCwGC2qDQT/\nSXOmY9YhZmE1gi5wsNhe3a03jLsn6ccekZ82jDI8z8zY0H8hfgf5yCDW23HgiHIB\ncGoFv1h+LWl2Qs+cTV9C98XEM/Xf/xBZC6fiydeNOY65OGnDDs1EtpB7KUxI/WKe\niHVAa9iZ1Rt+pJS9ebvfdU0Zim2iJmjA1RpdSwQvPQKBgQD9iMTXvdt6L/arNMhX\nnY+kjHZ/LWF0zWppXc0NHhL8YynyqDqe9ba6M1f+HAtZ/bFNGzmRNBJ/2D8s8js7\nMlfvzZ2Q0+Uhpr3YY4cOfT+WlCRWCoRMcn/EwrhpvV3OJA5jUSxIiroyWNPD3Bdl\nQeRL7LJAjkryfxNX/uCPGegTzQKBgQDM2FGakoqWZ3lMAwFOYRMnarbc5ZQ2Fly4\ns99elNDqMivcrY211Ni6ZcygvEs/vTB701l/w00K/NpF7UBaImj1FGjw1t+gG2IZ\n5VlHkk8+BahIn6nLK2/Ndkzla3I+LvLduU+n0FIQnx3r6tIX3R5yo453BigaSHq/\nvZLyH7TuGwKBgGIBmsYjOFJ1dA8eqktkNwDO44eqDUBPn9D3V6q4c3JpCvAoo/CK\n34X/DwbF5IV3EjDSU2CUFoqhF1rSkJ8DiQbEHyK7JpnpkP2zC6RIOmqE/b7c9eNv\nZ4CyHQOTFk33ljBCUrIAHpYTzFisHccgv5Wx+/4Eg2hWQy4C8t+ejh4JAoGBAJiL\n+3FV8fkBw7XUgxOAfUgcU2N7YH1K9+/gm9aOkmnlxP5JDMA9asyc5N9KeetUk5eT\nFBJuOaCWHmJ2xTaaa3kfouq/ybcszUiloHAJSBPTGLhElqijh1YF5EvxURl30wtF\nZkl9fK++HwVCUQTOeU879+sxXYn9MdQ6dAT1kcLDAoGAH0Pt2LzCX+loETpz2P3i\n4pWnQmc07kfF/KS80IFYRSs4hPO46kEHwstaQDH/6zM/LEow+nln+ribDW+tTQXq\nE/Z5XaLXjZzecdJid8gGGZXUAlbt6HAoftr3xRJTbL94uwNQlHILYwnrfFAPirp1\nrlxUtNVH/gHzfECrVUmwuCM=\n-----END PRIVATE KEY-----\n'";

    const CTX: &str = "test_context";

    fn get_allow_routing() -> (Arc<Mutex<AllowList>>, Arc<Mutex<RoutingTable>>) {
        let allow_list = AllowList::new();
        allow_list.lock().unwrap().allow_all();
        let routing_table = RoutingTable::new();
        routing_table.lock().unwrap().allow_all();
        (allow_list, routing_table)
    }

    fn get_storage(port: u16) -> Rc<Storage> {
        let storage_path = format!("/tmp/test_storage_{}.db", port);
        let config = StorageConfig::new(storage_path.clone(), None);
        let storage = Storage::new(&config).unwrap();
        Rc::new(storage)
    }

    struct PeerInfo {
        privk: String,
        address: SocketAddr,
        storage: Rc<Storage>,
    }
    impl PeerInfo {
        fn new(privk: &str, port: u16) -> Self {
            let storage = get_storage(port);
            Self {
                privk: privk.to_string(),
                address: SocketAddr::from(([127, 0, 0, 1], port)),
                storage,
            }
        }
    }

    fn get_peers_info(port: u16) -> (PeerInfo, PeerInfo, PeerInfo) {
        (
            PeerInfo::new(PRIVK1, port),
            PeerInfo::new(PRIVK2, port + 1),
            PeerInfo::new(PRIVK3, port + 2),
        )
    }

    fn get_peer_info(port: u16, peer: u8) -> PeerInfo {
        let (privk, port) = match peer {
            1 => (PRIVK1, port),
            2 => (PRIVK2, port + 1),
            3 => (PRIVK3, port + 2),
            _ => panic!("Invalid peer number"),
        };
        PeerInfo::new(privk, port)
    }

    fn get_queue_channels(port: u16) -> (QueueChannel, QueueChannel, QueueChannel) {
        let (allow_list, routing_table) = get_allow_routing();
        let (peer1, peer2, peer3) = get_peers_info(port);

        let queue_channel1 = QueueChannel::new(
            "testqueue",
            peer1.address,
            &peer1.privk,
            peer1.storage.clone(),
            None,
            allow_list.clone(),
            routing_table.clone(),
        )
        .unwrap();

        let queue_channel2 = QueueChannel::new(
            "testqueue",
            peer2.address,
            &peer2.privk,
            peer2.storage.clone(),
            None,
            allow_list.clone(),
            routing_table.clone(),
        )
        .unwrap();

        let queue_channel3 = QueueChannel::new(
            "testqueue",
            peer3.address,
            &peer3.privk,
            peer3.storage.clone(),
            None,
            allow_list.clone(),
            routing_table.clone(),
        )
        .unwrap();

        (queue_channel1, queue_channel2, queue_channel3)
    }

    // Get single queue channel for tests (peer1, peer2, or peer3)
    fn get_queue_channel(port: u16, peer: u8) -> QueueChannel {
        let (allow_list, routing_table) = get_allow_routing();
        let selected_peer = get_peer_info(port, peer);
        let queue_channel = QueueChannel::new(
            "testqueue",
            selected_peer.address,
            &selected_peer.privk,
            selected_peer.storage.clone(),
            None,
            allow_list.clone(),
            routing_table.clone(),
        )
        .unwrap();

        queue_channel
    }

    fn assert_msgs_received(
        received_msgs: &Vec<ReceiveHandlerChannel>,
        expected_msgs: &Vec<Vec<u8>>,
        expected_pubk_hashes: &Vec<PubkHash>,
    ) {
        assert_eq!(received_msgs.len(), expected_msgs.len());
        for (i, received_msg) in received_msgs.iter().enumerate() {
            match received_msg {
                ReceiveHandlerChannel::Msg(identifier, data) => {
                    assert_eq!(data, &expected_msgs[i]);
                    assert_eq!(identifier.pubkey_hash, expected_pubk_hashes[i]);
                }
                _ => panic!("Expected message"),
            }
        }
    }

    fn cleanup_storage(start_port: u16, count: u16) {
        for port in start_port..start_port + count {
            let _ = fs::remove_dir_all(&PathBuf::from(format!("/tmp/storage_queue_{}.db", port)));
            let _ = fs::remove_file(&PathBuf::from(format!("/tmp/broker_comms_{}.db", port)));
        }
    }

    #[test]
    fn test_send_receive() {
        init_tracing().unwrap();
        let port = 12000;
        cleanup_storage(port, 3);

        let (mut queue_channel1, mut queue_channel2, _queue_channel3) = get_queue_channels(port);

        let msg = b"Hello, World!".to_vec();

        queue_channel1
            .send(
                CTX,
                &queue_channel2.get_pubk_hash().unwrap(),
                queue_channel2.get_address(),
                msg.clone(),
            )
            .unwrap();

        queue_channel1.tick().unwrap();
        queue_channel2.tick().unwrap();

        let received_msgs = queue_channel2.check_receive().unwrap();
        assert_msgs_received(
            &received_msgs,
            &vec![msg],
            &vec![queue_channel1.get_pubk_hash().unwrap()],
        );

        // Close and cleanup
        cleanup_storage(port, 3);
        queue_channel1.close();
        queue_channel2.close();
    }

    #[test]
    fn test_concurrent_sending() {
        let port = 12003;
        cleanup_storage(port, 3);

        let (mut queue_channel1, mut queue_channel2, _queue_channel3) = get_queue_channels(port);

        let msg1 = b"Message from Channel 1".to_vec();
        let msg2 = b"Message from Channel 2".to_vec();

        queue_channel1
            .send(
                CTX,
                &queue_channel2.get_pubk_hash().unwrap(),
                queue_channel2.get_address(),
                msg1.clone(),
            )
            .unwrap();
        queue_channel2
            .send(
                CTX,
                &queue_channel1.get_pubk_hash().unwrap(),
                queue_channel1.get_address(),
                msg2.clone(),
            )
            .unwrap();

        queue_channel1.tick().unwrap();
        queue_channel2.tick().unwrap();
        queue_channel1.tick().unwrap(); // Extra tick so that channel1 can process incoming msg

        let received_msgs1 = queue_channel1.check_receive().unwrap();
        let received_msgs2 = queue_channel2.check_receive().unwrap();

        assert_msgs_received(
            &received_msgs1,
            &vec![msg2],
            &vec![queue_channel2.get_pubk_hash().unwrap()],
        );

        assert_msgs_received(
            &received_msgs2,
            &vec![msg1],
            &vec![queue_channel1.get_pubk_hash().unwrap()],
        );

        // Close and cleanup
        cleanup_storage(port, 3);
        queue_channel1.close();
        queue_channel2.close();
    }

    #[test]
    fn test_reconnecting() {
        let port = 12006;
        cleanup_storage(port, 3);

        let (mut queue_channel1, mut queue_channel2, _queue_channel3) = get_queue_channels(port);

        let msg = b"Persistent Message".to_vec();

        queue_channel1
            .send(
                CTX,
                &queue_channel2.get_pubk_hash().unwrap(),
                queue_channel2.get_address(),
                msg.clone(),
            )
            .unwrap();

        // Simulate reconnecting by closing and dropping queue_channel2 and creating a new one
        queue_channel2.close();
        drop(queue_channel2);
        queue_channel1.tick().unwrap();
        queue_channel2 = get_queue_channel(port, 2);

        // After reconnecting no messages should be received yet
        let received_msgs = queue_channel2.check_receive().unwrap();
        assert_eq!(received_msgs.len(), 0);

        // Tick again to process any queued messages
        queue_channel1.tick().unwrap();
        queue_channel2.tick().unwrap();
        let received_msgs = queue_channel2.check_receive().unwrap();
        assert_msgs_received(
            &received_msgs,
            &vec![msg],
            &vec![queue_channel1.get_pubk_hash().unwrap()],
        );

        // Close and cleanup
        cleanup_storage(port, 3);
        queue_channel1.close();
        queue_channel2.close();
    }

    #[test]
    fn test_message_ordering() {
        let port = 12009;
        cleanup_storage(port, 3);

        let (mut sender, mut receiver, _) = get_queue_channels(port);

        let mut sent_msgs = Vec::new();
        let mut expected_hashes = Vec::new();

        // Send 15 messages
        for i in 0..15u8 {
            let msg = format!("msg-{}", i).into_bytes();
            sent_msgs.push(msg.clone());
            expected_hashes.push(sender.get_pubk_hash().unwrap());

            sender
                .send(
                    CTX,
                    &receiver.get_pubk_hash().unwrap(),
                    receiver.get_address(),
                    msg,
                )
                .unwrap();
        }

        sender.tick().unwrap();
        receiver.tick().unwrap();

        let received = receiver.check_receive().unwrap();

        assert_eq!(received.len(), 15);

        // Verify FIFO order
        for (i, recv) in received.iter().enumerate() {
            match recv {
                ReceiveHandlerChannel::Msg(_, data) => {
                    assert_eq!(data, &sent_msgs[i], "Message order violated at index {}", i);
                }
                _ => panic!("Expected Msg"),
            }
        }

        cleanup_storage(port, 3);
        sender.close();
        receiver.close();
    }

    #[test]
    fn test_max_msgs_per_tick_per_destination() {
        let port = 12012;
        cleanup_storage(port, 3);

        let (mut sender, mut receiver1, mut receiver2) = get_queue_channels(port);
        let max_per_dest = sender.max_msgs_per_tick(MAX_MSGS_PER_TICK_UTILIZATION);

        // Send more than allowed per tick
        let excess_msgs = 3;
        let total_msgs = max_per_dest + excess_msgs;

        // Enqueue messages for both receivers
        let mut sent_msgs_r1 = Vec::new();
        let mut sent_msgs_r2 = Vec::new();
        for i in 0..total_msgs {
            let msg1 = format!("r1-msg-{i}").into_bytes();
            let msg2 = format!("r2-msg-{i}").into_bytes();

            sender
                .send(
                    CTX,
                    &receiver1.get_pubk_hash().unwrap(),
                    receiver1.get_address(),
                    msg1.clone(),
                )
                .unwrap();

            sender
                .send(
                    CTX,
                    &receiver2.get_pubk_hash().unwrap(),
                    receiver2.get_address(),
                    msg2.clone(),
                )
                .unwrap();

            sent_msgs_r1.push(msg1);
            sent_msgs_r2.push(msg2);
        }

        // First tick: should only send up to max_per_dest
        sender.tick().unwrap();
        receiver1.tick().unwrap();
        receiver2.tick().unwrap();
        let recv1_first = receiver1.check_receive().unwrap();
        let recv2_first = receiver2.check_receive().unwrap();
        assert_eq!(recv1_first.len(), max_per_dest);
        assert_eq!(recv2_first.len(), max_per_dest);

        // Second tick: remaining messages should be delivered
        sender.tick().unwrap();
        receiver1.tick().unwrap();
        receiver2.tick().unwrap();
        let recv1_second = receiver1.check_receive().unwrap();
        let recv2_second = receiver2.check_receive().unwrap();
        assert_eq!(recv1_second.len(), excess_msgs);
        assert_eq!(recv2_second.len(), excess_msgs);

        // Validate contents
        let recv1_all: Vec<Vec<u8>> = recv1_first
            .into_iter()
            .chain(recv1_second.into_iter())
            .map(|msg| match msg {
                ReceiveHandlerChannel::Msg(_, data) => data,
                _ => panic!("Unexpected error"),
            })
            .collect();
        let recv2_all: Vec<Vec<u8>> = recv2_first
            .into_iter()
            .chain(recv2_second.into_iter())
            .map(|msg| match msg {
                ReceiveHandlerChannel::Msg(_, data) => data,
                _ => panic!("Unexpected error"),
            })
            .collect();
        assert_eq!(recv1_all, sent_msgs_r1);
        assert_eq!(recv2_all, sent_msgs_r2);

        cleanup_storage(port, 3);
        sender.close();
        receiver1.close();
        receiver2.close();
    }

    #[test]
    fn test_deadletter() {
        let port = 12015;
        cleanup_storage(port, 3);

        let (mut sender, mut receiver, _) = get_queue_channels(port);

        // Close receiver server to simulate disconnection
        let receiver_addr = receiver.get_address();
        let receiver_pubk_hash = receiver.get_pubk_hash().unwrap();
        receiver.close();
        drop(receiver);

        let msg = b"deadletter-message".to_vec();

        sender
            .send(CTX, &receiver_pubk_hash, receiver_addr, msg.clone())
            .unwrap();

        // Tick sender enough times to exceed MAX_SEND_ATTEMPTS
        for _ in 0..=MAX_SEND_ATTEMPTS {
            sender.tick().unwrap();
        }

        let deadletters = sender.check_deadletter().unwrap();
        assert_eq!(deadletters.len(), 1);
        match &deadletters[0] {
            (ReceiveHandlerChannel::Msg(_, data), ctx) => {
                assert_eq!(data, &msg);
                assert_eq!(ctx, CTX);
            }
            _ => panic!("Expected dead letter message"),
        }

        // Cleanup
        cleanup_storage(port, 3);
        sender.close();
    }

    pub fn init_tracing() -> anyhow::Result<()> {
        let filter = EnvFilter::builder()
            .parse("info,tarpc=off") // Include everything at "info"
            .expect("Invalid filter");

        tracing_subscriber::registry()
            .with(filter)
            .with(tracing_subscriber::fmt::layer().with_span_events(FmtSpan::NEW | FmtSpan::CLOSE))
            .try_init()?;
        Ok(())
    }
}
