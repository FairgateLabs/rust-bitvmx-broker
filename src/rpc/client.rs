use std::{
    net::{IpAddr, Ipv4Addr, SocketAddr},
    sync::Arc,
};

use tokio::{net::TcpStream, runtime::Runtime, sync::Mutex};

use super::{errors::BrokerError, BrokerConfig, Message};
use crate::rpc::BrokerClient;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, ServerName};
use rustls_pemfile;
use std::fs::File;
use std::io::BufReader;
use tarpc::{client, context, serde_transport, tokio_serde::formats::Json};
use tokio_rustls::{
    rustls::{ClientConfig, RootCertStore},
    TlsConnector,
};
use tokio_util::codec::{Framed, LengthDelimitedCodec};

use crate::rpc::tls_helper::load_root_store;

pub struct Client {
    rt: Runtime,
    address: SocketAddr,
    client: Arc<Mutex<Option<BrokerClient>>>,
}

impl Client {
    pub fn new(config: &BrokerConfig) -> Self {
        let rt = Runtime::new().unwrap();
        let address = SocketAddr::new(
            config.ip.unwrap_or(IpAddr::V4(Ipv4Addr::LOCALHOST)),
            config.port,
        );

        Self {
            rt,
            address,
            client: Arc::new(Mutex::new(None)),
        }
    }

    async fn connect(&self) -> Result<(), BrokerError> {
        let stream = TcpStream::connect(self.address).await?;
        stream.set_nodelay(true)?;

        let root_cert_store = load_root_store("cert.pem").unwrap();

        // Client config
        let config = ClientConfig::builder()
            .with_root_certificates(root_cert_store)
            .with_no_client_auth(); // Client is anonymous

        let connector = TlsConnector::from(Arc::new(config));

        // Domain must match certificate CN
        let domain = ServerName::try_from("localhost").unwrap();

        let tls_stream = connector.connect(domain, stream).await?;

        let framed = Framed::new(tls_stream, LengthDelimitedCodec::new());
        let transport = serde_transport::new(framed, Json::default());

        let client = BrokerClient::new(client::Config::default(), transport).spawn();

        let mut locked = self.client.lock().await;
        *locked = Some(client);

        Ok(())
    }

    async fn get_or_connect(&self) -> Result<BrokerClient, BrokerError> {
        let mut locked = self.client.lock().await;

        if locked.is_none() {
            drop(locked); // release lock before await
            self.connect().await?;
            locked = self.client.lock().await;
        }

        locked
            .as_ref()
            .cloned()
            .ok_or_else(|| BrokerError::Disconnected)
    }

    async fn async_send_msg(&self, from: u32, dest: u32, msg: String) -> Result<bool, BrokerError> {
        let client = self.get_or_connect().await?;
        Ok(client.send(context::current(), from, dest, msg).await?)
    }

    async fn async_get_msg(&self, dest: u32) -> Result<Option<Message>, BrokerError> {
        let client = self.get_or_connect().await?;
        Ok(client.get(context::current(), dest).await?)
    }

    async fn async_ack(&self, dest: u32, uid: u64) -> Result<bool, BrokerError> {
        let client = self.get_or_connect().await?;
        Ok(client.ack(context::current(), dest, uid).await?)
    }

    pub fn send_msg(&self, from: u32, dest: u32, msg: String) -> Result<bool, BrokerError> {
        self.rt.block_on(self.async_send_msg(from, dest, msg))
    }

    pub fn get_msg(&self, dest: u32) -> Result<Option<Message>, BrokerError> {
        self.rt.block_on(self.async_get_msg(dest))
    }

    pub fn ack(&self, dest: u32, uid: u64) -> Result<bool, BrokerError> {
        self.rt.block_on(self.async_ack(dest, uid))
    }
}
