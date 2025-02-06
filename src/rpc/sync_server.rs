use std::sync::{Arc, Mutex};

use tokio::{runtime::Runtime, sync::mpsc};

use super::{server::run, BrokerConfig, StorageApi};

pub struct BrokerSync {
    rt: Runtime,
    shutdown_tx: mpsc::Sender<()>,
}

impl BrokerSync {
    pub fn new<S>(config: &BrokerConfig, storage: Arc<Mutex<S>>) -> Self
    where
        S: 'static + Send + Sync + StorageApi + Clone,
    {
        let rt = Runtime::new().unwrap();

        let (shutdown_tx, shutdown_rx) = mpsc::channel(1);

        rt.spawn(run(shutdown_rx, storage.clone(), config.clone()));

        Self { rt, shutdown_tx }
    }

    pub fn close(&mut self) {
        self.rt.block_on(async {
            let _ = self.shutdown_tx.send(()).await;
        });
    }
}
