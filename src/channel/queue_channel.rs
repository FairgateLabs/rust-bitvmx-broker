use std::{net::SocketAddr, rc::Rc};

use storage_backend::storage::Storage;

use crate::{
    broker_storage::BrokerStorage,
    channel::channel::LocalChannel,
    identification::identifier::PubkHash,
    rpc::{errors::BrokerError, sync_server::BrokerSync, tls_helper::Cert},
};

pub struct QueueChannel {
    server: BrokerSync,
    local_channel: LocalChannel<BrokerStorage>,
    cert: Cert,
    address: SocketAddr,
    storage: Rc<Storage>,
}

/*

impl QueueChannel {



    pub fn send(
        &self,
        pubk_hash: &PubkHash,
        address: SocketAddr,
        data: Vec<u8>,
    ) -> Result<(), BrokerError> {
        let data = serde_json::to_string(&data)?;

        self.storage.write(key, value)


        self.broker
            .put(
                address.port(),
                Some(address.ip()),
                pubk_hash.to_string(),
                data,
            )
            .map_err(|e| OperatorCommsError::BrokerError(e.to_string()))?;

        Ok(())
    }
}
*/
