use bitvmx_broker::{
    identification::{
        allow_list::AllowList,
        identifier::{Identifier, PubkHash},
        routing::RoutingTable,
    },
    rpc::{
        errors::{BrokerError, MutexExt},
        server::BrokerServer,
        tls_helper::Cert,
        BrokerConfig,
    },
    RemoteChannel,
};
use rsa::{pkcs8::EncodePrivateKey, rand_core::OsRng, RsaPrivateKey};
use std::net::IpAddr;

const TEST_RSA_BITS: usize = 2048;

/// Test-only constructors kept outside the library's release API.
pub trait CertTestExt {
    fn new_simple() -> Result<Self, BrokerError>
    where
        Self: Sized;
}

impl CertTestExt for Cert {
    fn new_simple() -> Result<Self, BrokerError> {
        let key = RsaPrivateKey::new(&mut OsRng, TEST_RSA_BITS)?;
        let pem = key.to_pkcs8_pem(Default::default())?;
        Cert::new_with_privk(pem.as_str())
    }
}

pub trait BrokerConfigTestExt {
    fn new_only_address(
        server_port: u16,
        server_ip: Option<IpAddr>,
    ) -> Result<(Self, Identifier, Cert), BrokerError>
    where
        Self: Sized;
}

impl BrokerConfigTestExt for BrokerConfig {
    fn new_only_address(
        server_port: u16,
        server_ip: Option<IpAddr>,
    ) -> Result<(Self, Identifier, Cert), BrokerError> {
        let cert = Cert::new_simple()?;
        let identifier = Identifier::new(cert.get_pubk_hash()?, bitvmx_broker::settings::SERVER_ID);
        Ok((Self::new(server_port, server_ip, None), identifier, cert))
    }
}

pub trait RemoteChannelTestExt {
    fn new_simple(
        config: &BrokerConfig,
        my_id: u8,
        server_pubk_hash: PubkHash,
    ) -> Result<(Self, Identifier), BrokerError>
    where
        Self: Sized;
}

impl RemoteChannelTestExt for RemoteChannel {
    fn new_simple(
        config: &BrokerConfig,
        my_id: u8,
        server_pubk_hash: PubkHash,
    ) -> Result<(Self, Identifier), BrokerError> {
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
}

pub trait BrokerServerTestExt {
    fn new_simple(
        config: &BrokerConfig,
        server_storage_path: &str,
        cert: Cert,
    ) -> Result<Self, BrokerError>
    where
        Self: Sized;
}

impl BrokerServerTestExt for BrokerServer {
    fn new_simple(
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
}
