use super::errors::BrokerError;
use crate::{
    identification::{allow_list::AllowList, identifier::Identifier},
    rpc::{
        errors::MutexExt,
        tls_helper::{get_fingerprint_hex, ArcAllowList, Cert},
        BrokerClient, BrokerConfig, Message,
    },
};
use rustls::pki_types::ServerName;
use std::{
    net::{IpAddr, Ipv4Addr, SocketAddr},
    str::FromStr,
    sync::{Arc, Mutex as ArcMutex},
};
use tarpc::{client, context, serde_transport, tokio_serde::formats::Json};
use tokio::{net::TcpStream, runtime::Runtime, sync::Mutex};
use tokio_rustls::{rustls::ClientConfig, TlsConnector};
use tokio_util::codec::{Framed, LengthDelimitedCodec};
use tracing::info;

pub struct Client {
    rt: Runtime,
    address: SocketAddr,
    client: Arc<Mutex<Option<BrokerClient>>>,
    cert: Cert,
    allow_list: Arc<ArcMutex<AllowList>>,
}

impl Clone for Client {
    fn clone(&self) -> Self {
        let rt = Runtime::new().unwrap();
        Self {
            rt,
            address: self.address,
            client: Arc::clone(&self.client),
            cert: self.cert.clone(),
            allow_list: self.allow_list.clone(),
        }
    }
}

impl Client {
    pub fn new(
        config: &BrokerConfig,
        cert: Cert,
        allow_list: Arc<ArcMutex<AllowList>>,
    ) -> Result<Self, BrokerError> {
        let rt = Runtime::new()?;
        let address = SocketAddr::new(
            config.ip.unwrap_or(IpAddr::V4(Ipv4Addr::LOCALHOST)),
            config.port,
        );
        info!("Client address: {}", address);
        Ok(Self {
            rt,
            address,
            client: Arc::new(Mutex::new(None)),
            cert,
            allow_list,
        })
    }

    async fn connect(&self) -> Result<(), BrokerError> {
        let stream = TcpStream::connect(self.address).await?;
        stream.set_nodelay(true)?;

        // Load certs and private key
        let cert = self.cert.get_cert()?;
        let key = self.cert.get_private_key()?;

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
        let peer_certs = tls_stream
            .get_ref()
            .1
            .peer_certificates()
            .ok_or_else(|| BrokerError::TlsError("No peer certificate".into()))?;
        let server_cert = peer_certs
            .first()
            .ok_or_else(|| BrokerError::TlsError("Empty peer certificate list".into()))?;

        // Check against allow list
        let server_fingerprint = get_fingerprint_hex(server_cert)
            .map_err(|e| BrokerError::TlsError(format!("Fingerprint error: {e}")))?;
        let peer_addr = tls_stream.get_ref().0.peer_addr()?;
        let ipaddr = IpAddr::from_str(&peer_addr.ip().to_string())?;
        let allow = self
            .allow_list
            .lock_or_err("allow_llist")?
            .is_allowed(&server_fingerprint, ipaddr);

        if !allow {
            drop(tls_stream);
            return Err(BrokerError::UnauthorizedFingerprint(server_fingerprint));
        }

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
                if client.ping(context::current()).await.is_ok() {
                    return Ok(client);
                }
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

    async fn async_send_msg(
        &self,
        from_id: u8,
        from_port: u16,
        dest: Identifier,
        msg: String,
    ) -> Result<bool, BrokerError> {
        let client = self.get_or_connect().await?;
        Ok(client
            .send(context::current(), from_id, from_port, dest, msg)
            .await?)
    }

    async fn async_get_msg(&self, dest: Identifier) -> Result<Option<Message>, BrokerError> {
        let client = self.get_or_connect().await?;
        Ok(client.get(context::current(), dest).await?)
    }

    async fn async_ack(&self, dest: Identifier, uid: u64) -> Result<bool, BrokerError> {
        let client = self.get_or_connect().await?;
        Ok(client.ack(context::current(), dest, uid).await?)
    }

    pub fn send_msg(
        &self,
        from_id: u8,
        from_port: u16,
        dest: Identifier,
        msg: String,
    ) -> Result<bool, BrokerError> {
        self.rt
            .block_on(self.async_send_msg(from_id, from_port, dest, msg))
    }

    pub fn get_msg(&self, dest: Identifier) -> Result<Option<Message>, BrokerError> {
        self.rt.block_on(self.async_get_msg(dest))
    }

    pub fn ack(&self, dest: Identifier, uid: u64) -> Result<bool, BrokerError> {
        self.rt.block_on(self.async_ack(dest, uid))
    }
}
