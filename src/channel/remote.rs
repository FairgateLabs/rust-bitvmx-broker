use tokio::runtime::Runtime;

use crate::{
    identification::{
        allow_list::AllowList,
        identifier::{Identifier, PubkHash},
    },
    rpc::{
        client::BrokerClient,
        errors::{BrokerError, MutexExt},
        tls_helper::Cert,
        BrokerConfig, Message,
    },
    settings::SERVER_ID,
};
use std::sync::{Arc, Mutex};

#[derive(Clone, Debug)]
pub struct RemoteChannel {
    client: BrokerClient,
    my_id: Identifier,
    server_id: Identifier, // The broker itself
}

impl RemoteChannel {
    // The config is of the node you want to connect to
    pub fn new(
        config: &BrokerConfig,
        my_cert: Cert,
        my_id: Option<u8>,
        allow_list: Arc<Mutex<AllowList>>,
        server_pubk_hash: PubkHash,
    ) -> Result<Self, crate::rpc::errors::BrokerError> {
        let client = BrokerClient::new(config, my_cert.clone(), allow_list)?;
        let my_id = Identifier {
            pubkey_hash: my_cert.get_pubk_hash()?,
            id: my_id.unwrap_or(0), // Default to 0 if not provided
        };
        let server_id = Identifier::new(server_pubk_hash, SERVER_ID);
        Ok(Self {
            client,
            my_id,
            server_id,
        })
    }

    pub fn new_with_runtime(
        config: &BrokerConfig,
        my_cert: Cert,
        my_id: Option<u8>,
        allow_list: Arc<Mutex<AllowList>>,
        server_pubk_hash: PubkHash,
        rt: Arc<Mutex<Runtime>>,
    ) -> Result<Self, crate::rpc::errors::BrokerError> {
        let client = BrokerClient::new_with_runtime(config, my_cert.clone(), allow_list, rt)?;
        let my_id = Identifier {
            pubkey_hash: my_cert.get_pubk_hash()?,
            id: my_id.unwrap_or(0), // Default to 0 if not provided
        };
        let server_id = Identifier::new(server_pubk_hash, SERVER_ID);
        Ok(Self {
            client,
            my_id,
            server_id,
        })
    }

    // Do not use in production, this is for testing purposes only
    pub fn new_simple(
        config: &BrokerConfig,
        my_id: u8,
        server_pubk_hash: PubkHash,
    ) -> Result<(Self, Identifier), crate::rpc::errors::BrokerError> {
        let my_cert = Cert::new_simple()?;
        let allow_list = AllowList::new();
        allow_list
            .lock_or_err::<BrokerError>("allow_list")?
            .set_allow_all(true);
        let my_identifier = Identifier {
            pubkey_hash: my_cert.get_pubk_hash()?,
            id: my_id,
        };
        Ok((
            Self::new(config, my_cert, Some(my_id), allow_list, server_pubk_hash)?,
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

    // Addresses the broker itself, built from the server hash given at construction.
    pub fn send_server(&self, msg: String) -> Result<bool, crate::rpc::errors::BrokerError> {
        self.client
            .send_msg(self.my_id.id, self.server_id.clone(), msg)
    }

    pub fn get(&self) -> Result<Option<Message>, crate::rpc::errors::BrokerError> {
        self.client.get_msg(self.my_id.id)
    }

    pub fn ack(&self, uid: u64) -> Result<bool, crate::rpc::errors::BrokerError> {
        self.client.ack(self.my_id.id, uid)
    }

    /// Acknowledges before the caller has seen the message, so a failure afterwards loses it. Use
    /// [`RemoteChannel::get`] and [`RemoteChannel::ack`] separately when the message must survive that.
    pub fn recv(&self) -> Result<Option<(String, Identifier)>, crate::rpc::errors::BrokerError> {
        if let Some(msg) = self.client.get_msg(self.my_id.id)? {
            self.client.ack(self.my_id.id, msg.uid)?;
            Ok(Some((msg.msg, msg.from)))
        } else {
            Ok(None)
        }
    }
}
