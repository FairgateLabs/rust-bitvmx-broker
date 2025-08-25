use super::{server::run, BrokerConfig, StorageApi};
use crate::{
    identification::{allow_list::AllowList, routing::RoutingTable},
    rpc::{
        errors::{BrokerError, MutexExt},
        tls_helper::Cert,
    },
};
use std::sync::{Arc, Mutex};
use tokio::{runtime::Runtime, sync::mpsc};

pub struct BrokerSync {
    rt: Runtime,
    shutdown_tx: mpsc::Sender<()>,
}

impl BrokerSync {
    pub fn new<S>(
        config: &BrokerConfig,
        storage: Arc<Mutex<S>>,
        cert: Cert,
        allow_list: Arc<Mutex<AllowList>>,
        routing: Arc<Mutex<RoutingTable>>,
    ) -> Result<Self, BrokerError>
    where
        S: 'static + Send + Sync + StorageApi + Clone,
    {
        let rt = Runtime::new()?;

        let (shutdown_tx, shutdown_rx) = mpsc::channel(1);

        rt.spawn(run(
            shutdown_rx,
            storage.clone(),
            config.clone(),
            cert.clone(),
            allow_list.clone(),
            routing.clone(),
        ));

        Ok(Self { rt, shutdown_tx })
    }

    // Do not use in production, this is for testing purposes only
    pub fn new_simple<S>(
        config: &BrokerConfig,
        storage: Arc<Mutex<S>>,
        cert: Cert,
    ) -> Result<Self, BrokerError>
    where
        S: 'static + Send + Sync + StorageApi + Clone,
    {
        let rt = Runtime::new()?;

        let (shutdown_tx, shutdown_rx) = mpsc::channel(1);

        let allow_list = AllowList::new();
        allow_list
            .lock_or_err::<BrokerError>("allow_list")?
            .allow_all();

        let routing = RoutingTable::new();
        routing.lock_or_err::<BrokerError>("routing")?.allow_all();

        rt.spawn(run(
            shutdown_rx,
            storage.clone(),
            config.clone(),
            cert.clone(),
            allow_list.clone(),
            routing.clone(),
        ));

        Ok(Self { rt, shutdown_tx })
    }

    pub fn close(&mut self) {
        self.rt.block_on(async {
            let _ = self.shutdown_tx.send(()).await;
        });
    }
}
