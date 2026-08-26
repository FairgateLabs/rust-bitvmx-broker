use std::{
    collections::HashMap,
    net::SocketAddr,
    rc::Rc,
    sync::{Arc, Mutex},
};

use bitvmx_settings::settings;
use serde::{Deserialize, Serialize};
use storage_backend::storage::Storage;
use tokio::runtime::Runtime;
use tracing::{info, warn};

use crate::{
    channel::local::LocalChannel,
    identification::{
        allow_list::AllowList,
        identifier::{Identifier, PubkHash},
        routing::RoutingTable,
    },
    retry::{now_ms, RetryPolicy, RetryState},
    rpc::{
        client::BrokerClient,
        config::BrokerSettings,
        errors::{BrokerError, MutexExt},
        server::BrokerServer,
        tls_helper::Cert,
        BrokerConfig,
    },
    settings::COMMS_ID,
    storage::{BrokerNodeStorage, QueueType},
};

#[derive(Debug)]
pub enum ReceivedMessage {
    Msg(Identifier, String), //Id, Msg
}

// What the node was built for. Peers talk to other brokers over the network, services hand messages
// to components that share this process. Only the constructors and send differ, the rest is common.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum NodeMode {
    Peers,
    Services,
}

impl NodeMode {
    fn as_str(&self) -> &'static str {
        match self {
            NodeMode::Peers => "peers",
            NodeMode::Services => "services",
        }
    }
}

#[derive(Serialize, Deserialize)]
struct OutgoingMsg {
    payload: String,
    ctx: String, // Program context
    retry: RetryState,
}

pub struct BrokerNode {
    server: BrokerServer,
    local_channel: LocalChannel,
    cert: Cert,
    address: SocketAddr,
    storage: BrokerNodeStorage,
    allow_list: Arc<Mutex<AllowList>>,
    routing_table: Arc<Mutex<RoutingTable>>,
    retry_policy: RetryPolicy,
    rt: Arc<Mutex<Runtime>>,
    broker_settings: BrokerSettings,
    local_id: Identifier, // Which of the destinations the server holds messages for (own for Peers, chosen for Services)
    mode: NodeMode,
}

impl BrokerNode {
    #[allow(clippy::too_many_arguments)]
    fn new(
        name: &str,
        address: SocketAddr,
        server_privk: &str,
        storage: Rc<Storage>,
        server_storage_path: &str,
        allow_list: Arc<Mutex<AllowList>>,
        routing_table: Arc<Mutex<RoutingTable>>,
        local_id: Identifier,
        mode: NodeMode,
        broker_settings: BrokerSettings,
    ) -> Result<Self, BrokerError> {
        let cert = Cert::new_with_privk(server_privk)?;
        let broker_config = BrokerConfig::new(
            address.port(),
            Some(address.ip()),
            Some(broker_settings.clone()),
        );

        let server = BrokerServer::new(
            &broker_config,
            server_storage_path,
            cert.clone(),
            allow_list.clone(),
            routing_table.clone(),
        )?;

        let local_channel = server.create_local_channel(local_id.clone());

        let retry_policy = RetryPolicy::new(&broker_settings.broker_node_config)?;

        let rt = Arc::new(Mutex::new(Runtime::new()?));

        Ok(Self {
            server,
            local_channel,
            cert,
            address,
            storage: BrokerNodeStorage::new(storage, name),
            allow_list,
            routing_table,
            retry_policy,
            rt,
            broker_settings,
            local_id,
            mode,
        })
    }

    /// A node that exchanges messages with other brokers over the network.
    /// It accepts only messages addressed to its local_id.
    pub fn new_peers(
        name: &str,
        address: SocketAddr,
        server_privk: &str,
        storage: Rc<Storage>,
        server_storage_path: &str,
        allow_list: Arc<Mutex<AllowList>>,
        broker_settings: BrokerSettings,
    ) -> Result<Self, BrokerError> {
        let local_id = Identifier {
            pubkey_hash: Cert::new_with_privk(server_privk)?.get_pubk_hash()?,
            id: COMMS_ID,
        };

        let routing_table = RoutingTable::new();
        routing_table
            .lock_or_err::<BrokerError>("routing_table")?
            .allow_only_to(&local_id);

        Self::new(
            name,
            address,
            server_privk,
            storage,
            server_storage_path,
            allow_list,
            routing_table,
            local_id,
            NodeMode::Peers,
            broker_settings,
        )
    }

    pub fn new_peers_with_paths(
        name: &str,
        address: SocketAddr,
        server_privk: &str, //File with PEM format
        storage: Rc<Storage>,
        server_storage_path: &str,
        allow_list: &str,
        broker_settings: BrokerSettings,
    ) -> Result<Self, BrokerError> {
        let allow_list = AllowList::from_file(allow_list)?;
        let server_privk = settings::decrypt_or_read_file(server_privk)?;
        Self::new_peers(
            name,
            address,
            &server_privk,
            storage,
            server_storage_path,
            allow_list,
            broker_settings,
        )
    }

    /// A node that serves several components, each holding its own destination on one server.
    /// Its server holds a destination per component. The local_id indicates which of them this
    /// node reads and which one it stamps as the sender.
    /// The routing table that decides who may write to whom.
    #[allow(clippy::too_many_arguments)]
    pub fn new_services(
        name: &str,
        address: SocketAddr,
        server_privk: &str,
        storage: Rc<Storage>,
        server_storage_path: &str,
        allow_list: Arc<Mutex<AllowList>>,
        routing_table: Arc<Mutex<RoutingTable>>,
        local_id: Identifier,
        broker_settings: BrokerSettings,
    ) -> Result<Self, BrokerError> {
        Self::new(
            name,
            address,
            server_privk,
            storage,
            server_storage_path,
            allow_list,
            routing_table,
            local_id,
            NodeMode::Services,
            broker_settings,
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub fn new_services_with_paths(
        name: &str,
        address: SocketAddr,
        server_privk: &str, //File with PEM format
        storage: Rc<Storage>,
        server_storage_path: &str,
        allow_list: &str,
        routing_table: &str,
        local_id: Identifier,
        broker_settings: BrokerSettings,
    ) -> Result<Self, BrokerError> {
        let allow_list = AllowList::from_file(allow_list)?;
        let routing_table = RoutingTable::from_file(routing_table)?;
        let server_privk = settings::decrypt_or_read_file(server_privk)?;
        Self::new_services(
            name,
            address,
            &server_privk,
            storage,
            server_storage_path,
            allow_list,
            routing_table,
            local_id,
            broker_settings,
        )
    }

    fn require_mode(&self, mode: NodeMode) -> Result<(), BrokerError> {
        if self.mode != mode {
            return Err(BrokerError::WrongNodeMode(self.mode.as_str().to_string()));
        }
        Ok(())
    }
    /// This method is only necessary for e2e testing. Could be hidden with a feature-flag and activated only as dev-dependency.
    /// Exposes the channel to send messages to another component on this broker. Only available on a node
    ///  created with [`BrokerNode::new_services`]. Do not use this to send messages to the node's own local_id
    pub fn create_local_channel(&self, id: Identifier) -> Result<LocalChannel, BrokerError> {
        self.require_mode(NodeMode::Services)?;
        if id == self.local_id {
            return Err(BrokerError::LocalChannelForOwnId);
        }
        Ok(self.server.create_local_channel(id))
    }

    fn enqueue_out_msg(
        &self,
        ctx: &str,
        pubk_hash: &PubkHash,
        address: &SocketAddr,
        data: String,
    ) -> Result<(), BrokerError> {
        let msg = OutgoingMsg {
            payload: data,
            ctx: ctx.to_string(),
            retry: RetryState::new(now_ms()?), // Initial attempt
        };

        self.storage
            .enqueue_out(pubk_hash, address, &serde_json::to_string(&msg)?)?;

        Ok(())
    }

    /// Queue a message for another broker. The out queue is drained by `tick`.
    /// This can only be called on a node created with [`BrokerNode::new_peers`],
    pub fn send_peer(
        &self,
        ctx: &str,
        pubk_hash: &PubkHash,
        address: SocketAddr,
        data: String,
    ) -> Result<(), BrokerError> {
        self.require_mode(NodeMode::Peers)?;
        self.enqueue_out_msg(ctx, pubk_hash, &address, data)?;
        Ok(())
    }

    /// Hand a message to another component on this broker.
    /// This can only be called on a node created with [`BrokerNode::new_services`],
    pub fn send_service(&self, dest: &Identifier, data: String) -> Result<(), BrokerError> {
        self.require_mode(NodeMode::Services)?;
        self.local_channel.send(dest, data)
    }

    /// Removes a row that could not be read and reports it as absent, so the caller skips it and
    /// keeps going.
    fn discard_row_on_err<T, E: std::fmt::Display>(
        &self,
        key: &str,
        result: Result<T, E>,
    ) -> Result<Option<T>, BrokerError> {
        match result {
            Ok(value) => Ok(Some(value)),
            Err(e) => {
                warn!("Discarding unreadable row {}: {}", key, e);
                self.storage.remove(key)?;
                Ok(None)
            }
        }
    }

    fn process_out_queue(&self) -> Result<(), BrokerError> {
        // send up to 50% of max capacity messages per tick
        let mut sent_per_dest: HashMap<String, usize> = HashMap::new();
        let max_per_dest = self.max_msgs_per_tick(
            self.broker_settings
                .broker_node_config
                .max_msgs_per_tick_utilization,
        ); // use 50% of capacity
        let now = now_ms()?;

        for key in self.storage.sorted_keys(&QueueType::OutQueue, None)? {
            if let Some(raw) = self.storage.get(&key)? {
                let Some((pubk_hash, address)) =
                    self.discard_row_on_err(&key, BrokerNodeStorage::dest_from_key(&key))?
                else {
                    continue;
                };

                // check if destination has not exceeded max messages per tick by destination pubk_hash
                let sent = sent_per_dest.entry(pubk_hash.clone()).or_insert(0);
                if *sent >= max_per_dest {
                    continue; // destination exhausted for this tick
                }
                let Some(mut msg) =
                    self.discard_row_on_err(&key, serde_json::from_str::<OutgoingMsg>(&raw))?
                else {
                    continue;
                };
                if msg.retry.is_ready(now) == false {
                    continue;
                }

                if msg.retry.get_attempts() > 0 {
                    info!(
                        "Attempt number {} to send queued message to {} at {}",
                        msg.retry.get_attempts() + 1,
                        pubk_hash,
                        address
                    );
                }

                let attempt_to_send = self.internal_send(&address, &pubk_hash, &msg.payload);
                if attempt_to_send.as_ref().is_ok_and(|x| *x) {
                    self.storage.remove(&key)?;
                    *sent += 1;
                } else {
                    // Ok(false) is the broker refusing the route.
                    let reason = match &attempt_to_send {
                        Ok(_) => "routing denied".to_string(),
                        Err(e) => e.to_string(),
                    };
                    warn!(
                        "Failed to send queued message to {} at {}: {}",
                        pubk_hash, address, reason
                    );

                    msg.retry.record_attempt(&self.retry_policy, now);

                    // If max attempts reached, move to dead letter queue
                    if self.retry_policy.is_exhausted(&msg.retry) {
                        warn!(
                            "moving message to dead letter queue for {} at {} after {} attempts",
                            pubk_hash,
                            address,
                            msg.retry.get_attempts()
                        );
                        self.storage
                            .enqueue_deadletter(&pubk_hash, &address, &raw)?;
                        self.storage.remove(&key)?;
                    } else {
                        self.storage.set(&key, &serde_json::to_string(&msg)?)?;
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
        msg: &str,
    ) -> Result<bool, BrokerError> {
        // Check if the destination is in the allow list
        if !self
            .allow_list
            .lock_or_err::<BrokerError>("allow_list")?
            .is_allowed(&dest_pubk_hash.to_string(), address.ip())
        {
            return Err(BrokerError::UnauthorizedFingerprint(
                dest_pubk_hash.to_string(),
            ));
        }

        let server_config = BrokerConfig::new(
            address.port(),
            Some(address.ip()),
            Some(self.broker_settings.clone()),
        );

        // Exactly one broker is acceptable here, so the connection carries a list holding only it.
        let dest_allow_list = AllowList::new();
        dest_allow_list
            .lock_or_err::<BrokerError>("dest_allow_list")?
            .add_entry(dest_pubk_hash.to_string(), Some(address.ip()));

        let client = BrokerClient::new_with_runtime(
            &server_config,
            self.cert.clone(),
            dest_allow_list,
            self.rt.clone(),
        )?;

        let identifier = Identifier::new(dest_pubk_hash.to_string(), COMMS_ID);
        client.send_msg(COMMS_ID, identifier, msg.to_string())
    }

    fn process_in_queue(&self) -> Result<(), BrokerError> {
        let incoming = self.local_channel.get_all()?;
        self.storage.store_in_msgs(&incoming)?;

        if incoming.len() > 0 {
            info!(
                "Moved {} messages from localchannel to inqueue",
                incoming.len()
            );
        }
        for msg in incoming {
            self.local_channel.ack(msg.uid)?;
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
        max: Option<usize>,
    ) -> Result<Vec<(ReceivedMessage, Option<String>)>, BrokerError> {
        let mut messages = vec![];

        for key in self.storage.sorted_keys(queue_type, max)? {
            if let Some(x) = self.storage.get(&key)? {
                let (identifier, data, ctx) = match queue_type {
                    QueueType::InQueue => {
                        let Some(identifier) = self
                            .discard_row_on_err(&key, BrokerNodeStorage::sender_from_key(&key))?
                        else {
                            continue;
                        };
                        (identifier, x, None)
                    }
                    QueueType::DeadLetterQueue => {
                        // No receiver id in deadletter, use COMMS_ID as default
                        let Some((pubk_hash, _)) =
                            self.discard_row_on_err(&key, BrokerNodeStorage::dest_from_key(&key))?
                        else {
                            continue;
                        };
                        let identifier = Identifier::new(pubk_hash, COMMS_ID);
                        let Some(msg) =
                            self.discard_row_on_err(&key, serde_json::from_str::<OutgoingMsg>(&x))?
                        else {
                            continue;
                        };
                        (identifier, msg.payload, Some(msg.ctx))
                    }
                    _ => continue,
                };

                messages.push((ReceivedMessage::Msg(identifier, data), ctx));

                self.storage.remove(&key)?;
            }
        }

        Ok(messages)
    }

    /// Returns the messages in the in queue, at most max of them, oldest first. None takes everything waiting.
    pub fn check_receive(
        &mut self,
        max: Option<usize>,
    ) -> Result<Vec<ReceivedMessage>, BrokerError> {
        self.check_reception(&QueueType::InQueue, max)?
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

    /// Returns messages in dead letter queue with their corresponding context, at most max of them.
    pub fn check_deadletter(
        &mut self,
        max: Option<usize>,
    ) -> Result<Vec<(ReceivedMessage, String)>, BrokerError> {
        self.check_reception(&QueueType::DeadLetterQueue, max)?
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

    /// Hash of the certificate this node presents, which is how a remote peer addresses its server.
    pub fn get_pubk_hash(&self) -> Result<PubkHash, BrokerError> {
        let pubk_hash = self.cert.get_pubk_hash()?;
        Ok(pubk_hash)
    }

    /// The destination this node reads messages for, and the sender it stamps on what it sends.
    pub fn get_local_id(&self) -> Identifier {
        self.local_id.clone()
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

        let max_msgs = self.broker_settings.rate_limiter_config.rate_limit_capacity
            / self.broker_settings.rate_limiter_config.tokens_per_message;
        ((max_msgs as f64) * utilization).floor() as usize
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::channel::remote::RemoteChannel;
    use std::{fs, path::PathBuf};
    use storage_backend::storage_config::StorageConfig;
    use tracing_subscriber::{
        fmt::format::FmtSpan, layer::SubscriberExt, util::SubscriberInitExt, EnvFilter,
    };

    const PRIVK1: &str = "b'-----BEGIN PRIVATE KEY-----\nMIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQDhzkbFynswfys/\nVNbM4hzYNKCdAuxYI/jysOPkRHGhlJe+71EE9F2CpAZnjevBsUWxi3+LatfMZjwi\nUz/l3iC6ow8Dsar0BO6RmWQR8Uf/1sx+WNjBk2woISPb60oXbXYj8AVUqYUUSo/Q\nRF5kuGT7dsMvUAx8Irn93w4A5VXx+FLn3r38Tymv7qOMT5cO1xrNStsluBD1RdPj\nz+B6b+7woAKqkrNFR+ZH0HUUKldA+A+pGElQLODyLB7OwxHgKtEsFdyiiDuKW2mP\nsk2dsab9HCNdo9cViA9UbeykDXq7h0/7gYg9XBH8LqqXYpSk/LE6T8k1RVa9EBxV\nRpYqlvFPAgMBAAECggEAV64pfRQq0aIPwP/IiLYkTS/iThWcgH03ZcWaOED7fqqc\nYd+7rhjVVq0qb3uEWCnlzhNE63YJZa0tHIcHANNIEjDO27hZkXd4y8CsQutV8doO\nfeEyCbic/tgffH3Yv1AZ18qTx1QsAL0TKuPhY2rWi26KTAzhTDKP1iyO23ox7Uqs\nwWChuHWyw7SmECRmjKOjTLs1Axea3fos6ERgEv/KZiTi+a9he5JuHOXO6aKTvHI7\nlTAMdloy1CnK6G3Ql7LfBeX20hIwDSZNgp5naB6NjJiDTbxxlGj7apW6hquzJpRP\n1Tn2YLvVKl5bdAOHh44wHBhZR9COjxUT+uASYRb5wQKBgQD7FTe3VPrsi6ejo7db\n9SwTUjsTQKoxrfoNc0xPzGGwKyyArGM++NQI1CZuQQDXVoYl+JC1JOcTLjjW/TYu\nwVGAr63bjtYjU0e8NZzum3nIZ7rpyHJpnbCLBc678KNCvblD4u/Vl1bx/9vRiCTx\n9S0r/LJ54Jr3Ohx9feYERc4K/QKBgQDmOlWNHwFlC2pkYI/0biXWybQZWvz+C5x3\nJO6tf0ykRk2sBEcp07JMhJsE+r4B+lHNSWalkX409Fn6x2ch/6tLP0X+viM5nr+2\nRpGHLpUBeq4+RKMmUS/NgY2DoRV1DRnfk4Vt0BZy5Voc4OVQz0zohwFzYhY60ThR\nV3UJ9HbdOwKBgQCcBS8+CNxzqMRe9xi1V8AvsWVsLT6U6Fr9iKve2k3JvspEmtqB\nAvYfFlVbJaF0Lhvl9HNXXLsKPCqtzWKh4xbWNFSAnl2KTfHBjj8aNhqS4YJQS3Jt\nFsPhX5Z7SqjojCRXfukxfH1Wm3ro1QTAJW4Qa1IsUdl5zu5tPJJ2DTpfsQKBgCii\nXR0mPsnFxQZoYKAEnNsXCJl9DLAN/pSsyQ+IK0/HNMhKjQDd41dMBExRsR2KP8va\ny6onTr4r7oGrlhFTHbmPNlxq1K7DzRRvyhmw6A21yHEnDiCiLay40/BKiw34vPtP\n/znNg1jOECSOsQqdO/bCdUgXJNNGwAjjRb33Ds+nAoGAW76wLk1lwD2tZ8KgMRUU\ni0BkY7eDXPskxCP6BjFq10J/1dC/dsLO9mZfwl2BJ2D+gGmcIzdSb5p1LkuniGuv\nV+/lSa8bdUKwtd5l+CZ0OMqmHryQZICqGeG5uREYv5eqs4mDiuM8QkZdOZUKWzPc\nwWJXrp5cQtvgjS/HyjHB69o=\n-----END PRIVATE KEY-----\n'";
    const PRIVK2: &str = "b'-----BEGIN PRIVATE KEY-----\nMIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQCeJYILLK2EpGP9\nCrlEeHL1hYODftAUxJTacRezNNuyAqqP04H0IFffXhdz/f54HnYnaN1VrMGNQlR5\nBashFjZa7fVEFp3osVgNEPNu63MA1Gr7o4BakopRbMx7jUyhmlJXNP3VX5tZEha+\nV7GOZEeh2Ej3pehnE/E6SD16Ez9aaGydFgrMALHjT2NfucK0XCcDvMbq53PsBaLm\nnH5TLnvtZvYmdyDoUe+RvlwaRAHv4AWDOElhQrj970giHWY6i9QgqrlTIYN5cQrD\nM6kNj1SaBtCNpG/wIK3NMLW7PAYeEKTopwdsFuVL+1e0IAsTIVpDC1mb3r2GlPji\n0GaMLBAHAgMBAAECggEAFPHDvMYgfuIkqeULL1HCa9jQV5Bqb22vhxSWPnIgLH2k\n6CJrYhEMgjUcZwy68F6caFC/i3KzOYmQ1WxWQy4Fadp88pUKOcCO+EAH9WcyVmhL\neOMpAxXIQstlc3F9tiNRh2IpweIFGXFHWNMVXVXTlNAnrcCnvEsMVhsuJSY6bDcV\n5ejQKE8kM8F30FzD2mii36XamsreMpQBAIlm0i1HH/8PpynUQ12bb2M0T/FR9C5V\nAbfeLUOgrzWgBs9hxmlBzILusJFjv7OvwIkF97GgoAyLKqFmxzncwQUTqh9iH2Js\nemN6Qg+vPIg2Et8Ku9XEX+CSXvDwFckB2Z14jqQw8QKBgQDPHDzAFDSTl+aPH+vd\n01wxtaFyP7KP2OaRabW1qzTPww87agbN3wPJqBBf9lEjVeGNjLrp2NyHX6Wfnt5V\nlpeWts13/M43rju2JJwOrfZnwJsJgQ9ZEQw30e1LWeiGpr0kcWlv2059tEiKgBwY\nNlw6evsCyFjrIuSqgg3riO9xMQKBgQDDel5TfTJ3BJZlgFYnU1YxUZDQ1mcMDnSK\ntdRLdpVWTEkjzf0a6rGJYla0NoqQdH9qDfimVMY6+RQLZVdhhXDVnQuwV0CK9ERY\nQWy/PEoPvIagTXgKJ8fKLYcG420fJJtPmTSEoPZg1PXtuABNj/68bI7ONL5CY6gO\n8iFJU0sGtwKBgA6mlLWRuFZofGrLe0fp16+8hXsrflomocjPjYcYYVgBGGa/jVOq\n3v244c+oAP1a6eW1etNn/9GjtnegKWIskPScYdSHEZ9mt9qepFt1euTD/zOg6ZEH\nX7HjK8IUzhoYWXDmhOrgvKCvzCHgBhzAW63XXUJJIeEgSsS1Bn8O5MFBAoGAMuiv\noDa+6dg8AvtFdMBzdiyz9m+gLrelCmsIew7LHcqIUdbX0CbHTexagFykAbMVa91v\noIH7jmhIHB+sfi1ukXNxE9/lY0rycbm4RKXC9A45UY5bcOmjUrhArj6UsMOr3zMb\nRl9VSyqrUdnV2l1iDliHaJS76DZkEmBk4t/abkkCgYEAxkk3skKgRJPt2bFLzdHV\n3Au24P/Cyqf1LIfXpuJcMBfAhw55g6DOLR4O0BH+s7cZk8hrGVeI9WyhC5EgzZrF\nBjTlZFqFtsz5psj1oNqgr/JnO2fL3csxbDR81q9uSSzdlN7BlzBpdQahi53K9MHi\nZDNGUy5a/PopNnWSzfHYUas=\n-----END PRIVATE KEY-----\n'";
    const PRIVK3: &str = "b'-----BEGIN PRIVATE KEY-----\nMIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQDK3zkTXQMEWbzL\nSRRBO7Wd657dQ/EifekFOIsDtiWHpjOdMRN9H25dVCkm5aBY2zNn62DzZcOlB57z\nUosALiPiyLrcDEu6w6efl3ZikkYD4gbfSKEAGDn1rLS/eUlM61hrgv7ibeqc8grA\nOo9ksWk9JKalCs0gRkufJn9fmiKmKDYDYkzMfSWZ0hDSL6kcy1ZfQLjDpwT6TJXm\nwVN7X6y25Men1v///qlXlBuIf/o1KtXG2v31NWHP0rxHiu5nCG1vGGenGF8y1puK\nVf+OhyqzPhter9gi5wqLo6QQjzyJt/71WDydVmjMDz30QDJrokV8JFu2zPJiG99u\nrIs9BqyfAgMBAAECggEAVn2ho0A5y46In3B6Gq+eqAOuuK3BLc/ZWxj2p2/uAy2X\n/rHQGb2fO1noq4UlfgyCF5FxxYNCzGZ53Un5KewB76tdgvgZBzhoC/GyjqbHA9vG\ny0X3IgeyGiv16VYHqqwBh+CS0y1CY4QLklXFEYxTjjZEd8OpnVNq5SCwGC2qDQT/\nSXOmY9YhZmE1gi5wsNhe3a03jLsn6ccekZ82jDI8z8zY0H8hfgf5yCDW23HgiHIB\ncGoFv1h+LWl2Qs+cTV9C98XEM/Xf/xBZC6fiydeNOY65OGnDDs1EtpB7KUxI/WKe\niHVAa9iZ1Rt+pJS9ebvfdU0Zim2iJmjA1RpdSwQvPQKBgQD9iMTXvdt6L/arNMhX\nnY+kjHZ/LWF0zWppXc0NHhL8YynyqDqe9ba6M1f+HAtZ/bFNGzmRNBJ/2D8s8js7\nMlfvzZ2Q0+Uhpr3YY4cOfT+WlCRWCoRMcn/EwrhpvV3OJA5jUSxIiroyWNPD3Bdl\nQeRL7LJAjkryfxNX/uCPGegTzQKBgQDM2FGakoqWZ3lMAwFOYRMnarbc5ZQ2Fly4\ns99elNDqMivcrY211Ni6ZcygvEs/vTB701l/w00K/NpF7UBaImj1FGjw1t+gG2IZ\n5VlHkk8+BahIn6nLK2/Ndkzla3I+LvLduU+n0FIQnx3r6tIX3R5yo453BigaSHq/\nvZLyH7TuGwKBgGIBmsYjOFJ1dA8eqktkNwDO44eqDUBPn9D3V6q4c3JpCvAoo/CK\n34X/DwbF5IV3EjDSU2CUFoqhF1rSkJ8DiQbEHyK7JpnpkP2zC6RIOmqE/b7c9eNv\nZ4CyHQOTFk33ljBCUrIAHpYTzFisHccgv5Wx+/4Eg2hWQy4C8t+ejh4JAoGBAJiL\n+3FV8fkBw7XUgxOAfUgcU2N7YH1K9+/gm9aOkmnlxP5JDMA9asyc5N9KeetUk5eT\nFBJuOaCWHmJ2xTaaa3kfouq/ybcszUiloHAJSBPTGLhElqijh1YF5EvxURl30wtF\nZkl9fK++HwVCUQTOeU879+sxXYn9MdQ6dAT1kcLDAoGAH0Pt2LzCX+loETpz2P3i\n4pWnQmc07kfF/KS80IFYRSs4hPO46kEHwstaQDH/6zM/LEow+nln+ribDW+tTQXq\nE/Z5XaLXjZzecdJid8gGGZXUAlbt6HAoftr3xRJTbL94uwNQlHILYwnrfFAPirp1\nrlxUtNVH/gHzfECrVUmwuCM=\n-----END PRIVATE KEY-----\n'";

    const CTX: &str = "test_context";

    fn get_allow_routing_settings() -> (
        Arc<Mutex<AllowList>>,
        Arc<Mutex<RoutingTable>>,
        BrokerSettings,
    ) {
        let allow_list = AllowList::new();
        allow_list.lock().unwrap().set_allow_all(true);
        let routing_table = RoutingTable::new();
        routing_table.lock().unwrap().allow_all();
        let settings = BrokerSettings::new("config/broker_settings.yaml").unwrap();
        (allow_list, routing_table, settings)
    }

    // Test storages live under target/tmp, never in the crate root or the system temp directory.
    fn tmp_path(name: &str, port: u16) -> String {
        let dir = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("target/tmp");
        let _ = fs::create_dir_all(&dir);
        dir.join(format!("{}_{}", name, port))
            .to_string_lossy()
            .into_owned()
    }

    fn get_storage(port: u16) -> Rc<Storage> {
        let config = StorageConfig::new(tmp_path("test_storage", port), None);
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

    fn get_broker_nodes(port: u16) -> (BrokerNode, BrokerNode, BrokerNode) {
        let (_, _, settings) = get_allow_routing_settings();
        get_broker_nodes_with_settings(port, settings)
    }

    fn get_broker_nodes_with_settings(
        port: u16,
        settings: BrokerSettings,
    ) -> (BrokerNode, BrokerNode, BrokerNode) {
        let (allow_list, _, _) = get_allow_routing_settings();
        let (peer1, peer2, peer3) = get_peers_info(port);

        let broker_node1 = BrokerNode::new_peers(
            "testqueue",
            peer1.address,
            &peer1.privk,
            peer1.storage.clone(),
            &tmp_path("broker_comms", peer1.address.port()),
            allow_list.clone(),
            settings.clone(),
        )
        .unwrap();

        let broker_node2 = BrokerNode::new_peers(
            "testqueue",
            peer2.address,
            &peer2.privk,
            peer2.storage.clone(),
            &tmp_path("broker_comms", peer2.address.port()),
            allow_list.clone(),
            settings.clone(),
        )
        .unwrap();

        let broker_node3 = BrokerNode::new_peers(
            "testqueue",
            peer3.address,
            &peer3.privk,
            peer3.storage.clone(),
            &tmp_path("broker_comms", peer3.address.port()),
            allow_list.clone(),
            settings,
        )
        .unwrap();

        (broker_node1, broker_node2, broker_node3)
    }

    fn get_service_node(port: u16, local_id: &Identifier) -> BrokerNode {
        let (allow_list, routing_table, settings) = get_allow_routing_settings();
        let peer = PeerInfo::new(PRIVK1, port);
        BrokerNode::new_services(
            "testservices",
            peer.address,
            &peer.privk,
            peer.storage.clone(),
            &tmp_path("broker_comms", peer.address.port()),
            allow_list,
            routing_table,
            local_id.clone(),
            settings,
        )
        .unwrap()
    }

    // Get single queue channel for tests (peer1, peer2, or peer3)
    fn get_broker_node(port: u16, peer: u8) -> BrokerNode {
        let (allow_list, _, settings) = get_allow_routing_settings();
        let selected_peer = get_peer_info(port, peer);
        let broker_node = BrokerNode::new_peers(
            "testqueue",
            selected_peer.address,
            &selected_peer.privk,
            selected_peer.storage.clone(),
            &tmp_path("broker_comms", selected_peer.address.port()),
            allow_list.clone(),
            settings,
        )
        .unwrap();

        broker_node
    }

    fn assert_msgs_received(
        received_msgs: &Vec<ReceivedMessage>,
        expected_msgs: &Vec<String>,
        expected_pubk_hashes: &Vec<PubkHash>,
    ) {
        assert_eq!(received_msgs.len(), expected_msgs.len());
        for (i, received_msg) in received_msgs.iter().enumerate() {
            match received_msg {
                ReceivedMessage::Msg(identifier, data) => {
                    assert_eq!(data, &expected_msgs[i]);
                    assert_eq!(identifier.pubkey_hash, expected_pubk_hashes[i]);
                }
            }
        }
    }

    fn cleanup_storage(start_port: u16, count: u16) {
        for port in start_port..start_port + count {
            let _ = fs::remove_dir_all(&PathBuf::from(tmp_path("test_storage", port)));
            let _ = fs::remove_dir_all(&PathBuf::from(tmp_path("broker_comms", port)));
        }
    }

    #[test]
    fn test_send_receive() {
        init_tracing().unwrap();
        let port = 12000;
        cleanup_storage(port, 3);

        let (mut broker_node1, mut broker_node2, mut broker_node3) = get_broker_nodes(port);

        let msg = "Hello, World!".to_string();

        broker_node1
            .send_peer(
                CTX,
                &broker_node2.get_pubk_hash().unwrap(),
                broker_node2.get_address(),
                msg.clone(),
            )
            .unwrap();

        broker_node1.tick().unwrap();
        broker_node2.tick().unwrap();

        let received_msgs = broker_node2.check_receive(None).unwrap();
        assert_msgs_received(
            &received_msgs,
            &vec![msg],
            &vec![broker_node1.get_pubk_hash().unwrap()],
        );

        // Close and cleanup
        broker_node1.close();
        broker_node2.close();
        broker_node3.close();
        drop(broker_node1);
        drop(broker_node2);
        drop(broker_node3);
        cleanup_storage(port, 3);
    }

    #[test]
    fn test_concurrent_sending() {
        let port = 12003;
        cleanup_storage(port, 3);

        let (mut broker_node1, mut broker_node2, mut broker_node3) = get_broker_nodes(port);

        let msg1 = "Message from Channel 1".to_string();
        let msg2 = "Message from Channel 2".to_string();

        broker_node1
            .send_peer(
                CTX,
                &broker_node2.get_pubk_hash().unwrap(),
                broker_node2.get_address(),
                msg1.clone(),
            )
            .unwrap();
        broker_node2
            .send_peer(
                CTX,
                &broker_node1.get_pubk_hash().unwrap(),
                broker_node1.get_address(),
                msg2.clone(),
            )
            .unwrap();

        broker_node1.tick().unwrap();
        broker_node2.tick().unwrap();
        broker_node1.tick().unwrap(); // Extra tick so that channel1 can process incoming msg

        let received_msgs1 = broker_node1.check_receive(None).unwrap();
        let received_msgs2 = broker_node2.check_receive(None).unwrap();

        assert_msgs_received(
            &received_msgs1,
            &vec![msg2],
            &vec![broker_node2.get_pubk_hash().unwrap()],
        );

        assert_msgs_received(
            &received_msgs2,
            &vec![msg1],
            &vec![broker_node1.get_pubk_hash().unwrap()],
        );

        // Close and cleanup
        broker_node1.close();
        broker_node2.close();
        broker_node3.close();
        drop(broker_node1);
        drop(broker_node2);
        drop(broker_node3);
        cleanup_storage(port, 3);
    }

    #[ignore = "working on windows but failing on linux, need to investigate"]
    #[test]
    fn test_reconnecting() {
        let port = 12006;
        cleanup_storage(port, 3);

        let (mut broker_node1, mut broker_node2, mut broker_node3) = get_broker_nodes(port);

        let msg = "Persistent Message".to_string();

        broker_node1
            .send_peer(
                CTX,
                &broker_node2.get_pubk_hash().unwrap(),
                broker_node2.get_address(),
                msg.clone(),
            )
            .unwrap();

        // Simulate reconnecting by closing and dropping broker_node2 and creating a new one
        broker_node2.close();
        drop(broker_node2);
        broker_node1.tick().unwrap();
        broker_node2 = get_broker_node(port, 2);

        // After reconnecting no messages should be received yet
        let received_msgs = broker_node2.check_receive(None).unwrap();
        assert_eq!(received_msgs.len(), 0);

        // Tick again to process any queued messages
        broker_node1.tick().unwrap();
        broker_node2.tick().unwrap();
        let received_msgs = broker_node2.check_receive(None).unwrap();
        assert_msgs_received(
            &received_msgs,
            &vec![msg],
            &vec![broker_node1.get_pubk_hash().unwrap()],
        );

        // Close and cleanup
        broker_node1.close();
        broker_node2.close();
        broker_node3.close();
        drop(broker_node1);
        drop(broker_node2);
        drop(broker_node3);
        cleanup_storage(port, 3);
    }

    #[test]
    fn test_message_ordering() {
        let port = 12009;
        cleanup_storage(port, 3);

        let (mut sender, mut receiver, mut broker_node3) = get_broker_nodes(port);

        let mut sent_msgs = Vec::new();
        let mut expected_hashes = Vec::new();

        // Send 15 messages
        for i in 0..15u8 {
            let msg = format!("msg-{}", i);
            sent_msgs.push(msg.clone());
            expected_hashes.push(sender.get_pubk_hash().unwrap());

            sender
                .send_peer(
                    CTX,
                    &receiver.get_pubk_hash().unwrap(),
                    receiver.get_address(),
                    msg,
                )
                .unwrap();
        }

        sender.tick().unwrap();
        receiver.tick().unwrap();

        let received = receiver.check_receive(None).unwrap();

        assert_eq!(received.len(), 15);

        // Verify FIFO order
        for (i, recv) in received.iter().enumerate() {
            match recv {
                ReceivedMessage::Msg(_, data) => {
                    assert_eq!(data, &sent_msgs[i], "Message order violated at index {}", i);
                }
            }
        }

        sender.close();
        receiver.close();
        broker_node3.close();
        drop(sender);
        drop(receiver);
        drop(broker_node3);
        cleanup_storage(port, 3);
    }

    #[test]
    fn test_max_msgs_per_tick_per_destination() {
        let port = 12012;
        cleanup_storage(port, 3);

        let (_, _, mut settings) = get_allow_routing_settings();
        settings.rate_limiter_config.rate_limit_capacity = 100;
        settings.broker_node_config.max_msgs_per_tick_utilization = 0.1;

        let (mut sender, mut receiver1, mut receiver2) =
            get_broker_nodes_with_settings(port, settings.clone());
        let max_per_dest =
            sender.max_msgs_per_tick(settings.broker_node_config.max_msgs_per_tick_utilization);
        assert_eq!(max_per_dest, 5);

        // Send more than allowed per tick
        let excess_msgs = 3;
        let total_msgs = max_per_dest + excess_msgs;

        // Enqueue messages for both receivers
        let mut sent_msgs_r1 = Vec::new();
        let mut sent_msgs_r2 = Vec::new();
        for i in 0..total_msgs {
            let msg1 = format!("r1-msg-{i}");
            let msg2 = format!("r2-msg-{i}");

            sender
                .send_peer(
                    CTX,
                    &receiver1.get_pubk_hash().unwrap(),
                    receiver1.get_address(),
                    msg1.clone(),
                )
                .unwrap();

            sender
                .send_peer(
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
        let recv1_first = receiver1.check_receive(None).unwrap();
        let recv2_first = receiver2.check_receive(None).unwrap();
        assert_eq!(recv1_first.len(), max_per_dest);
        assert_eq!(recv2_first.len(), max_per_dest);

        // Second tick: remaining messages should be delivered
        sender.tick().unwrap();
        receiver1.tick().unwrap();
        receiver2.tick().unwrap();
        let recv1_second = receiver1.check_receive(None).unwrap();
        let recv2_second = receiver2.check_receive(None).unwrap();
        assert_eq!(recv1_second.len(), excess_msgs);
        assert_eq!(recv2_second.len(), excess_msgs);

        // Validate contents
        let recv1_all: Vec<String> = recv1_first
            .into_iter()
            .chain(recv1_second.into_iter())
            .map(|msg| match msg {
                ReceivedMessage::Msg(_, data) => data,
            })
            .collect();
        let recv2_all: Vec<String> = recv2_first
            .into_iter()
            .chain(recv2_second.into_iter())
            .map(|msg| match msg {
                ReceivedMessage::Msg(_, data) => data,
            })
            .collect();
        assert_eq!(recv1_all, sent_msgs_r1);
        assert_eq!(recv2_all, sent_msgs_r2);

        sender.close();
        receiver1.close();
        receiver2.close();
        drop(sender);
        drop(receiver1);
        drop(receiver2);
        cleanup_storage(port, 3);
    }

    #[test]
    fn test_deadletter() {
        let port = 12015;
        cleanup_storage(port, 3);

        let (_, _, settings) = get_allow_routing_settings();
        let (mut sender, mut receiver, mut broker_node3) = get_broker_nodes(port);

        // Close receiver server to simulate disconnection
        let receiver_addr = receiver.get_address();
        let receiver_pubk_hash = receiver.get_pubk_hash().unwrap();
        receiver.close();
        drop(receiver);

        let msg = "deadletter-message".to_string();

        sender
            .send_peer(CTX, &receiver_pubk_hash, receiver_addr, msg.clone())
            .unwrap();

        // Keep ticking until message appears in dead letter queue or timeout
        let start = std::time::Instant::now();
        let timeout = std::time::Duration::from_millis(
            settings.broker_node_config.retry_max_delay_msecs
                * settings.broker_node_config.max_send_attempts as u64,
        );

        loop {
            sender.tick().unwrap();

            let deadletters = sender.check_deadletter(None).unwrap();
            if !deadletters.is_empty() {
                assert_eq!(deadletters.len(), 1);
                match &deadletters[0] {
                    (ReceivedMessage::Msg(_, data), ctx) => {
                        assert_eq!(data, &msg);
                        assert_eq!(ctx, CTX);
                    }
                }
                break;
            }

            if start.elapsed() > timeout {
                panic!("Timed out waiting for message to reach dead letter queue");
            }

            std::thread::sleep(std::time::Duration::from_millis(100));
        }

        sender.close();
        broker_node3.close();
        drop(sender);
        drop(broker_node3);
        cleanup_storage(port, 3);
    }

    // Two components exchanging messages through one services broker: bitvmx hosts the broker and
    // reads its own destination, the emulator dials in over TLS and reads its own.
    #[test]
    fn test_service_send_receive() {
        let port = 12018;
        cleanup_storage(port, 1);

        let bitvmx_id = Identifier::new("bitvmx_component".to_string(), 0);
        let mut bitvmx = get_service_node(port, &bitvmx_id);
        assert_eq!(bitvmx.get_local_id(), bitvmx_id);

        // The emulator is a plain client: no server and no node of its own.
        let (_, _, settings) = get_allow_routing_settings();
        let (allow_list, _, _) = get_allow_routing_settings();
        let address = bitvmx.get_address();
        let config = BrokerConfig::new(address.port(), Some(address.ip()), Some(settings));
        let emulator_cert = Cert::new_with_privk(PRIVK2).unwrap();
        let emulator_id = Identifier::new(emulator_cert.get_pubk_hash().unwrap(), 0);
        let emulator = RemoteChannel::new(
            &config,
            emulator_cert,
            Some(0),
            allow_list,
            bitvmx.get_pubk_hash().unwrap(),
        )
        .unwrap();

        // Emulator to bitvmx. The sender is derived from the certificate the emulator presented.
        assert!(emulator
            .send(&bitvmx_id, "job finished".to_string())
            .unwrap());
        bitvmx.tick().unwrap();
        assert_msgs_received(
            &bitvmx.check_receive(None).unwrap(),
            &vec!["job finished".to_string()],
            &vec![emulator_id.pubkey_hash.clone()],
        );

        // Bitvmx back to the emulator, which reads its own destination with get and ack.
        bitvmx
            .send_service(&emulator_id, "next job".to_string())
            .unwrap();
        let reply = emulator.get().unwrap().unwrap();
        assert_eq!(reply.msg, "next job");
        assert_eq!(reply.from, bitvmx_id);
        assert!(emulator.ack(reply.uid).unwrap());
        assert!(emulator.get().unwrap().is_none());

        bitvmx.close();
        drop(bitvmx);
        cleanup_storage(port, 1);
    }

    // A tick moves everything into the in queue, but the caller decides how much of it to take.
    #[test]
    fn test_check_receive_max() {
        let port = 12021;
        cleanup_storage(port, 3);

        let (mut sender, mut receiver, mut broker_node3) = get_broker_nodes(port);

        for i in 0..5u8 {
            sender
                .send_peer(
                    CTX,
                    &receiver.get_pubk_hash().unwrap(),
                    receiver.get_address(),
                    format!("msg-{}", i),
                )
                .unwrap();
        }
        sender.tick().unwrap();
        receiver.tick().unwrap();

        // Oldest first, and the rest stay queued.
        let first = receiver.check_receive(Some(2)).unwrap();
        assert_msgs_received(
            &first,
            &vec!["msg-0".to_string(), "msg-1".to_string()],
            &vec![sender.get_pubk_hash().unwrap(); 2],
        );

        // A cap larger than what is waiting takes what there is, without ticking again.
        let rest = receiver.check_receive(Some(10)).unwrap();
        assert_msgs_received(
            &rest,
            &vec![
                "msg-2".to_string(),
                "msg-3".to_string(),
                "msg-4".to_string(),
            ],
            &vec![sender.get_pubk_hash().unwrap(); 3],
        );

        assert!(receiver.check_receive(None).unwrap().is_empty());

        sender.close();
        receiver.close();
        broker_node3.close();
        drop(sender);
        drop(receiver);
        drop(broker_node3);
        cleanup_storage(port, 3);
    }

    // A row that cannot be read is dropped and the drain carries on, so the messages behind it are delivered.
    #[test]
    fn test_unreadable_row_is_discarded_and_the_rest_arrive() {
        let port = 12024;
        cleanup_storage(port, 3);

        let (mut sender, mut receiver, mut broker_node3) = get_broker_nodes(port);

        let poison_key = format!(
            "broker/inqueue/testqueue/msgs/0/{}/not-an-id",
            sender.get_pubk_hash().unwrap()
        );
        receiver.storage.set(&poison_key, "unreadable").unwrap();

        for i in 0..2u8 {
            sender
                .send_peer(
                    CTX,
                    &receiver.get_pubk_hash().unwrap(),
                    receiver.get_address(),
                    format!("msg-{}", i),
                )
                .unwrap();
        }
        sender.tick().unwrap();
        receiver.tick().unwrap();

        let received = receiver.check_receive(None).unwrap();
        assert_msgs_received(
            &received,
            &vec!["msg-0".to_string(), "msg-1".to_string()],
            &vec![sender.get_pubk_hash().unwrap(); 2],
        );
        assert!(
            receiver.storage.get(&poison_key).unwrap().is_none(),
            "the unreadable row should be removed, not retried on every tick"
        );

        sender.close();
        receiver.close();
        broker_node3.close();
        drop(sender);
        drop(receiver);
        drop(broker_node3);
        cleanup_storage(port, 3);
    }

    #[test]
    fn test_nodes_built_from_files() {
        let peer_port = 12030;
        let service_port = 12031;
        cleanup_storage(peer_port, 2);

        // The path constructors read the key, the allow list and the routing table off disk.
        let dir = tmp_path("node_config", peer_port);
        fs::create_dir_all(&dir).unwrap();
        let privk_path = format!("{dir}/node.key");
        let allow_path = format!("{dir}/allowlist.yaml");
        let routing_path = format!("{dir}/routing.yaml");
        fs::write(&privk_path, PRIVK1).unwrap();
        fs::write(&allow_path, "allow_all").unwrap();
        {
            let routing = RoutingTable::new();
            routing.lock().unwrap().allow_all();
            routing.lock().unwrap().save_to_file(&routing_path).unwrap();
        }

        let settings = BrokerSettings::new("config/broker_settings.yaml").unwrap();
        let peer_info = PeerInfo::new(PRIVK1, peer_port);
        let mut peers = BrokerNode::new_peers_with_paths(
            "testpaths",
            peer_info.address,
            &privk_path,
            peer_info.storage.clone(),
            &tmp_path("broker_comms", peer_port),
            &allow_path,
            settings.clone(),
        )
        .unwrap();

        // The identity comes from the key file, not from anything the caller passed separately.
        let expected_hash = Cert::new_with_privk(PRIVK1)
            .unwrap()
            .get_pubk_hash()
            .unwrap();
        assert_eq!(peers.get_pubk_hash().unwrap(), expected_hash);
        assert_eq!(peers.get_address(), peer_info.address);
        assert_eq!(
            peers.get_local_id(),
            Identifier::new(expected_hash, COMMS_ID)
        );

        // The allow list is the one the file described.
        assert!(peers.get_allow_list().lock().unwrap().is_allow_all());

        // A peers node accepts only what is addressed to itself.
        let own_id = peers.get_local_id();
        let elsewhere = Identifier::new("someone_else".to_string(), 0);
        {
            let routing = peers.get_routing_table();
            let routing = routing.lock().unwrap();
            assert!(routing.can_route(&elsewhere, &own_id));
            assert!(!routing.can_route(&own_id, &elsewhere));
        }

        // Local channels belong to the services shape, so a peers node refuses to hand one out.
        assert!(matches!(
            peers.create_local_channel(elsewhere.clone()),
            Err(BrokerError::WrongNodeMode(_))
        ));
        peers.close();
        drop(peers);

        let local_id = Identifier::new("service_address".to_string(), 0);
        let service_info = PeerInfo::new(PRIVK2, service_port);
        let mut services = BrokerNode::new_services_with_paths(
            "testpaths",
            service_info.address,
            &privk_path,
            service_info.storage.clone(),
            &tmp_path("broker_comms", service_port),
            &allow_path,
            &routing_path,
            local_id.clone(),
            settings,
        )
        .unwrap();

        // A services node keeps the routing table the file described.
        {
            let routing = services.get_routing_table();
            assert!(routing.lock().unwrap().can_route(&elsewhere, &local_id));
        }

        // It serves other destinations, but not the one it reads for itself.
        assert!(services.create_local_channel(elsewhere).is_ok());
        assert!(matches!(
            services.create_local_channel(local_id),
            Err(BrokerError::LocalChannelForOwnId)
        ));
        services.close();
        drop(services);

        let _ = fs::remove_dir_all(&dir);
        cleanup_storage(peer_port, 2);
    }

    #[test]
    fn test_send_rejects_the_other_mode() {
        let service_port = 12019;
        let peer_port = 12020;
        cleanup_storage(service_port, 2);

        let local_id = Identifier::new("service_address".to_string(), 0);

        let mut services = get_service_node(service_port, &local_id);
        let address = services.get_address();
        assert!(matches!(
            services.send_peer(CTX, &"somepeer".to_string(), address, "x".to_string()),
            Err(BrokerError::WrongNodeMode(_))
        ));
        services.close();
        drop(services);

        let mut peers = get_broker_node(peer_port, 1);
        assert!(matches!(
            peers.send_service(&local_id, "x".to_string()),
            Err(BrokerError::WrongNodeMode(_))
        ));
        peers.close();
        drop(peers);

        cleanup_storage(service_port, 2);
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
