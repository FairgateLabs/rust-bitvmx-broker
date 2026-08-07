use super::{service::run, BrokerConfig};
use crate::channel::local::LocalChannel;
use crate::storage::BrokerServerStorage;
use crate::{
    identification::{allow_list::AllowList, identifier::Identifier, routing::RoutingTable},
    rpc::{
        errors::{BrokerError, MutexExt},
        tls_helper::Cert,
    },
};
use std::sync::{Arc, Mutex};
use tokio::{runtime::Runtime, sync::mpsc};
use tracing::warn;

pub struct BrokerServer {
    rt: Runtime,
    shutdown_tx: mpsc::Sender<()>,
    storage: BrokerServerStorage,
}

impl BrokerServer {
    // The server owns its storage: it opens server_storage_path itself so that no two components
    // can end up on different handles of the same messages. Never give this path to anything else.
    pub fn new(
        config: &BrokerConfig,
        server_storage_path: &str,
        cert: Cert,
        allow_list: Arc<Mutex<AllowList>>,
        routing: Arc<Mutex<RoutingTable>>,
    ) -> Result<Self, BrokerError> {
        let storage = BrokerServerStorage::new(server_storage_path)?;

        let rt = Runtime::new()?;

        let (shutdown_tx, shutdown_rx) = mpsc::channel(1);

        let (server_started_tx, mut server_started_rx) = mpsc::channel(1);

        rt.spawn(run(
            shutdown_rx,
            server_started_tx,
            storage.clone(),
            config.clone(),
            cert.clone(),
            allow_list.clone(),
            routing.clone(),
        ));

        // Wait for server to start
        rt.block_on(async {
            match server_started_rx.recv().await {
                Some(()) => Ok(()),
                None => {
                    warn!(
                        "Broker server failed to start (sender dropped) with config: {:?}",
                        config
                    );
                    Err(BrokerError::ServerStartError(format!(
                        "Server failed to start with config: {:?}",
                        config
                    )))
                }
            }
        })?;

        Ok(Self {
            rt,
            shutdown_tx,
            storage,
        })
    }

    // Do not use in production, this is for testing purposes only
    pub fn new_simple(
        config: &BrokerConfig,
        server_storage_path: &str,
        cert: Cert,
    ) -> Result<Self, BrokerError> {
        let allow_list = AllowList::new();
        allow_list
            .lock_or_err::<BrokerError>("allow_list")?
            .set_allow_all(true);

        let routing = RoutingTable::new();
        routing.lock_or_err::<BrokerError>("routing")?.allow_all();

        Self::new(config, server_storage_path, cert, allow_list, routing)
    }

    // A local channel shares the storage of this server, which is the only way for both to see the
    // same messages. This is why LocalChannel cannot be built on its own.
    pub fn create_local_channel(&self, id: Identifier) -> LocalChannel {
        LocalChannel::new(id, self.storage.clone())
    }

    pub fn close(&mut self) {
        self.rt.block_on(async {
            let _ = self.shutdown_tx.send(()).await;
        });
    }
}
