use tokio::runtime::Runtime;

use crate::{
    identification::{allow_list::AllowList, identifier::Identifier},
    rpc::{
        client::BrokerClient,
        errors::{BrokerError, MutexExt},
        tls_helper::Cert,
        BrokerConfig,
    },
};
use std::sync::{Arc, Mutex};

#[derive(Clone, Debug)]
pub struct RemoteChannel {
    client: BrokerClient,
    my_id: Identifier,
    dest_id: Identifier, // Identifier of the destination
}

impl RemoteChannel {
    // The config is of the node you want to connect to
    pub fn new(
        config: &BrokerConfig,
        my_cert: Cert,
        my_id: Option<u8>,
        allow_list: Arc<Mutex<AllowList>>,
    ) -> Result<Self, crate::rpc::errors::BrokerError> {
        let client = BrokerClient::new(config, my_cert.clone(), allow_list)?;
        let my_id = Identifier {
            pubkey_hash: my_cert.get_pubk_hash()?,
            id: my_id.unwrap_or(0), // Default to 0 if not provided
        };
        let dest_id = Identifier {
            pubkey_hash: config.get_pubk_hash(),
            id: config.get_id(),
        };
        Ok(Self {
            client,
            my_id,
            dest_id,
        })
    }

    pub fn new_with_runtime(
        config: &BrokerConfig,
        my_cert: Cert,
        my_id: Option<u8>,
        allow_list: Arc<Mutex<AllowList>>,
        rt: Arc<Mutex<Runtime>>,
    ) -> Result<Self, crate::rpc::errors::BrokerError> {
        let client = BrokerClient::new_with_runtime(config, my_cert.clone(), allow_list, rt)?;
        let my_id = Identifier {
            pubkey_hash: my_cert.get_pubk_hash()?,
            id: my_id.unwrap_or(0), // Default to 0 if not provided
        };
        let dest_id = Identifier {
            pubkey_hash: config.get_pubk_hash(),
            id: config.get_id(),
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
        let allow_list = AllowList::new();
        allow_list
            .lock_or_err::<BrokerError>("allow_list")?
            .allow_all();
        let my_identifier = Identifier {
            pubkey_hash: my_cert.get_pubk_hash()?,
            id: my_id,
        };
        Ok((
            Self::new(config, my_cert, Some(my_id), allow_list)?,
            my_identifier,
        ))
    }

    pub fn send(
        &self,
        dest: &Identifier,
        msg: String,
    ) -> Result<bool, crate::rpc::errors::BrokerError> {
        self.client.send_msg(self.my_id.id, dest.clone(), msg)
    }

    // Dest is the identifier in config
    pub fn send_server(&self, msg: String) -> Result<bool, crate::rpc::errors::BrokerError> {
        self.client
            .send_msg(self.my_id.id, self.dest_id.clone(), msg)
    }

    pub fn recv(&self) -> Result<Option<(String, Identifier)>, crate::rpc::errors::BrokerError> {
        if let Some(msg) = self.client.get_msg(self.my_id.id.clone())? {
            self.client.ack(self.my_id.id.clone(), msg.uid)?;
            Ok(Some((msg.msg, msg.from)))
        } else {
            Ok(None)
        }
    }
}
