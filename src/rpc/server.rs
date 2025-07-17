use super::{BrokerConfig, Message, StorageApi};
use crate::{
    allow_list::{AllowList, Identifier},
    rpc::{
        tls_helper::{get_fingerprint_hex, ArcAllowList, Cert},
        Broker,
    },
};
use futures::StreamExt;
use rustls::ServerConfig;
use std::{
    future::Future,
    net::{IpAddr, Ipv4Addr, SocketAddr},
    str::FromStr,
    sync::{Arc, Mutex},
};
use tarpc::{
    context, serde_transport,
    server::{self, Channel},
    tokio_serde::formats::Json,
};
use tokio::{net::TcpListener, sync::mpsc};
use tokio_rustls::TlsAcceptor;
use tokio_util::codec::{Framed, LengthDelimitedCodec};
use tracing::{error, info};

#[derive(Clone)]
struct BrokerServer<S: StorageApi> {
    _peer: SocketAddr,
    storage: Arc<Mutex<S>>,
}

impl<S> BrokerServer<S>
where
    S: StorageApi,
{
    fn new(peer: SocketAddr, storage: Arc<Mutex<S>>) -> Self {
        Self {
            _peer: peer,
            storage,
        }
    }
}

impl<S> Broker for BrokerServer<S>
where
    S: StorageApi + 'static + Send + Sync,
{
    async fn send(
        self,
        _: context::Context,
        from: Identifier,
        dest: Identifier,
        msg: String,
    ) -> bool {
        self.storage.lock().unwrap().insert(from, dest, msg);
        true
    }

    async fn get(self, _: context::Context, dest: Identifier) -> Option<Message> {
        self.storage.lock().unwrap().get(dest)
    }

    async fn ack(self, _: context::Context, dest: Identifier, uid: u64) -> bool {
        self.storage.lock().unwrap().remove(dest, uid)
    }
}

async fn spawn(fut: impl Future<Output = ()> + Send + 'static) {
    tokio::spawn(fut);
}

type ShutDownSignal = mpsc::Receiver<()>;
pub async fn run<S>(
    mut shutdown: ShutDownSignal,
    storage: Arc<Mutex<S>>,
    config: BrokerConfig,
    cert: Cert,
    allow_list: Arc<Mutex<AllowList>>,
) -> anyhow::Result<()>
where
    S: 'static + Send + Sync + StorageApi + Clone,
{
    let server_addr = (
        config.ip.unwrap_or(IpAddr::V4(Ipv4Addr::LOCALHOST)),
        config.port,
    );
    let listener = TcpListener::bind(server_addr).await?;
    info!(
        "Listening with TLS on port {}",
        listener.local_addr()?.port()
    );

    // Load certs, private key, and allowlist
    let certs = cert.get_cert()?;
    let key = cert.get_private_key()?;

    // Server config
    let client_auth = Arc::new(ArcAllowList::new(allow_list.clone()));
    let server_config = ServerConfig::builder()
        .with_client_cert_verifier(client_auth)
        .with_single_cert(certs, key)?;
    let tls_acceptor = TlsAcceptor::from(Arc::new(server_config));

    tokio::select! {
        _ = async {
            loop {
                info!("Server started, waiting for TLS connections...");
                let (stream, addr) = match listener.accept().await {
                    Ok(conn) => conn,
                    Err(e) => {
                        error!("TCP accept error: {:?}", e);
                        continue;
                    }
                };

                // Clone for async task
                let acceptor = tls_acceptor.clone();
                let storage = storage.clone();
                let allowlist = allow_list.clone();

                // Spawn a new task for each connection
                tokio::spawn(async move {

                    // Perform TLS handshake
                    let tls_stream = match acceptor.accept(stream).await {
                        Ok(tls_stream) => {

                            // Chreck if the client is authorized on the allowlist
                            let peer_addr = match tls_stream.get_ref().0.peer_addr() {
                                Ok(addr) => addr,
                                Err(e) => {
                                    error!("Failed to get peer address: {:?}", e);
                                    return;
                                }
                            };
                            let ipaddr = match IpAddr::from_str(&peer_addr.ip().to_string()) {
                                Ok(ip) => ip,
                                Err(e) => {
                                    error!("Invalid IP address format: {:?}", e);
                                    return;
                                }
                            };
                            let cert = match tls_stream.get_ref().1.peer_certificates() {
                                Some(certs) if !certs.is_empty() => certs[0].clone(),
                                _ => {
                                    error!("No peer certificate found");
                                    return;
                                }
                            };
                            let hex_fingerprint = match get_fingerprint_hex(&cert) {
                                Ok(fingerprint) => fingerprint,
                                Err(e) => {
                                    error!("Failed to get fingerprint: {:?}", e);
                                    return;
                                }
                            };
                            let allow = match allowlist.lock() {
                                Ok(guard) => guard.is_allowed(&hex_fingerprint, None, ipaddr), //TODO: select proper id
                                Err(e) => {
                                    error!("Failed to lock allowlist: {:?}", e);
                                    return;
                                }
                            };
                            match allow {
                                true => tls_stream,
                                false => {
                                    error!("Unauthorized fingerprint with address {}: {}", peer_addr, hex_fingerprint);
                                    return;
                                }
                            }
                        },
                        Err(e) => {
                            error!("TLS handshake failed: {:?}", e);
                            return;
                        }
                    };


                // Client is authorized
                let framed = Framed::new(tls_stream, LengthDelimitedCodec::new()); // Length prefix, message boundaries
                let transport = serde_transport::new(framed, Json::default());
                server::BaseChannel::with_defaults(transport)
                    .execute(BrokerServer::new(addr, storage).serve())
                    .for_each(spawn)
                    .await;
                });
            }
        } => {},
        _ = shutdown.recv() => {
            info!("Shutting down...");
        },
    }

    Ok(())
}
