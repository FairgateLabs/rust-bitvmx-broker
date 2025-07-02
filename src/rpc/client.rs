use std::{
    net::{IpAddr, Ipv4Addr, SocketAddr},
    sync::{Arc, Mutex as ArcMutex},
};

use crate::{
    allow_list::AllowList,
    rpc::tls_helper::{ArcAllowList, CertFiles},
};
use rustls::pki_types::ServerName;

use crate::rpc::BrokerClient;
use tarpc::{client, context, serde_transport, tokio_serde::formats::Json};
use tokio::{net::TcpStream, runtime::Runtime, sync::Mutex};
use tokio_rustls::{rustls::ClientConfig, TlsConnector};
use tokio_util::codec::{Framed, LengthDelimitedCodec};

use super::{errors::BrokerError, BrokerConfig, Message};

pub struct Client {
    rt: Runtime,
    address: SocketAddr,
    client: Arc<Mutex<Option<BrokerClient>>>,
    cert_files: CertFiles,
    allow_list: Arc<ArcMutex<AllowList>>,
}

// impl Clone for Client {
//     fn clone(&self) -> Self {
//         let rt = Runtime::new().unwrap();
//         Self {
//             rt: rt,
//             address: self.address,
//             client: Arc::clone(&self.client),
//             cert_files: self.cert_files.clone(),
//             allow_list: self.allow_list,
//         }
//     }
// }

impl Client {
    pub fn new(config: &BrokerConfig) -> Result<Self, BrokerError> {
        let rt = Runtime::new()?;
        let address = SocketAddr::new(
            config.ip.unwrap_or(IpAddr::V4(Ipv4Addr::LOCALHOST)),
            config.port,
        );
        let cert_files = config.cert_files.clone();
        let allow_list = config.allow_list.clone();
        Ok(Self {
            rt,
            address,
            client: Arc::new(Mutex::new(None)),
            cert_files,
            allow_list,
        })
    }

    async fn connect(&self) -> Result<(), BrokerError> {
        let stream = TcpStream::connect(self.address).await?;
        stream.set_nodelay(true)?;

        // Load certs and private key
        let cert = self.cert_files.load_certs()?;
        let key = self.cert_files.load_private_key()?;

        // Client config
        let config = ClientConfig::builder()
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(ArcAllowList::new(self.allow_list.clone())))
            .with_client_auth_cert(cert, key)
            .map_err(|e| BrokerError::TlsError(e.to_string()))?;

        // Load certificate
        let connector = TlsConnector::from(Arc::new(config));
        let domain =
            ServerName::try_from("localhost").map_err(|e| BrokerError::TlsError(e.to_string()))?;
        let tls_stream = connector.connect(domain, stream).await?;

        // Server is authorized
        let framed = Framed::new(tls_stream, LengthDelimitedCodec::new());
        let transport = serde_transport::new(framed, Json::default());
        let client = BrokerClient::new(client::Config::default(), transport).spawn();
        let mut locked = self.client.lock().await;
        *locked = Some(client);
        Ok(())
    }

    async fn get_or_connect(&self) -> Result<BrokerClient, BrokerError> {
        {
            let mut locked = self.client.lock().await;

            if let Some(client) = locked.as_ref().cloned() {
                // Check if the client is still connected
                let test = client.get(context::current(), u32::MAX).await;
                if test.is_ok() {
                    return Ok(client);
                }

                // Client is broken
                *locked = None;
            }
        }

        // Try reconnecting
        if self.connect().await.is_ok() {
            let locked = self.client.lock().await;
            if let Some(client) = locked.as_ref().cloned() {
                return Ok(client);
            }
        }
        Err(BrokerError::Disconnected)
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
