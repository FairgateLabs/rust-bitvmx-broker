use super::{BrokerConfig, Message, StorageApi};
use crate::{
    identification::{allow_list::AllowList, identifier::Identifier, routing::RoutingTable},
    rpc::{
        errors::{BrokerRpcError, MutexExt},
        tls_helper::{AllowListClientVerifier, Cert},
        Broker,
    },
};
use futures::StreamExt;
use rustls::{RootCertStore, ServerConfig};
use std::{
    future::Future,
    net::{IpAddr, Ipv4Addr},
    str::FromStr,
    sync::{Arc, Mutex},
};
use tarpc::{
    context, serde_transport,
    server::{self, Channel},
    tokio_serde::formats::Json,
};
use tokio::{net::TcpListener, sync::mpsc, task::JoinHandle};
use tokio_rustls::TlsAcceptor;
use tokio_util::{
    codec::{Framed, LengthDelimitedCodec},
    sync::CancellationToken,
};
use tracing::{error, info, warn};

#[derive(Clone)]
pub struct BrokerServer<S: StorageApi> {
    client_pubkey_hash: String,
    storage: Arc<Mutex<S>>,
    routing: Arc<Mutex<RoutingTable>>,
}

impl<S> BrokerServer<S>
where
    S: StorageApi,
{
    fn new(
        client_pubkey_hash: String,
        storage: Arc<Mutex<S>>,
        routing: Arc<Mutex<RoutingTable>>,
    ) -> Self {
        Self {
            client_pubkey_hash,
            storage,
            routing,
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
        from_id: u8,
        dest: Identifier,
        msg: String,
    ) -> Result<bool, BrokerRpcError> {
        let from = Identifier {
            pubkey_hash: self.client_pubkey_hash.clone(),
            id: from_id,
        };
        let allowed = {
            let routing = self.routing.lock_or_err("routing")?;
            routing.can_route(&from, &dest)
        };

        if !allowed {
            warn!("Routing denied: {} cannot send to {}", from, dest);
            return Ok(false);
        }
        self.storage
            .lock_or_err("storage")?
            .insert(from, dest, msg)?;
        Ok(true)
    }

    async fn get(
        self,
        _: context::Context,
        dest_id: u8,
    ) -> Result<Option<Message>, BrokerRpcError> {
        let auth_dest = Identifier {
            pubkey_hash: self.client_pubkey_hash.clone(),
            id: dest_id,
        };
        Ok(self.storage.lock_or_err("storage")?.get(auth_dest)?)
    }

    async fn ack(self, _: context::Context, dest_id: u8, uid: u64) -> Result<bool, BrokerRpcError> {
        let auth_dest = Identifier {
            pubkey_hash: self.client_pubkey_hash.clone(),
            id: dest_id,
        };
        Ok(self
            .storage
            .lock_or_err("storage")?
            .remove(auth_dest, uid)?)
    }

    async fn ping(self, _: context::Context) -> bool {
        true
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
    routing: Arc<Mutex<RoutingTable>>,
) -> anyhow::Result<()>
where
    S: 'static + Send + Sync + StorageApi + Clone,
{
    let server_addr = (
        config
            .ip
            .unwrap_or(IpAddr::V4(Ipv4Addr::from([0, 0, 0, 0]))),
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
    let ca_cert_der = cert.get_ca_cert_der()?;

    // Load CA
    let mut roots = RootCertStore::empty();
    roots.add(ca_cert_der)?;

    // Server config
    let client_verifier = Arc::new(AllowListClientVerifier::new(
        allow_list.clone(),
        roots.into(),
    )?);

    let server_config = ServerConfig::builder()
        .with_client_cert_verifier(client_verifier)
        .with_single_cert(certs, key)?;
    let tls_acceptor = TlsAcceptor::from(Arc::new(server_config));

    let cancellation_token = CancellationToken::new();
    let mut connection_tasks: Vec<JoinHandle<()>> = Vec::new();
    info!("Server started, waiting for TLS connections...");

    tokio::select! {
        _ = async {
            loop {
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
                let routing = routing.clone();
                let cancel_token = cancellation_token.clone();

                // Spawn a new task for each connection
                let task = tokio::spawn(async move {

                    tokio::select! {
                        _ = async{
                            let hex_fingerprint: String;
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
                                    hex_fingerprint = match Cert::get_fingerprint_hex(&cert) {
                                        Ok(fingerprint) => fingerprint,
                                        Err(e) => {
                                            error!("Failed to get fingerprint: {:?}", e);
                                            return;
                                        }
                                    };
                                    let allow = match allowlist.lock() {
                                        Ok(guard) => guard.is_allowed(&hex_fingerprint, ipaddr),
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
                                .execute(BrokerServer::new(hex_fingerprint, storage, routing).serve())
                                .for_each(spawn)
                                .await;

                        } => {},
                        _ = cancel_token.cancelled() => {
                            tracing::debug!("Cancelled connection handler for {}", addr);
                        }
                    }
                });

                connection_tasks.push(task);
            }
        } => {},
        _ = shutdown.recv() => {
            info!("Shutting down...");
            cancellation_token.cancel();

            // Wait for all connection tasks to complete
            for task in connection_tasks {
                if let Err(e) = task.await {
                    error!("Task join error: {:?}", e);
                }
            }

            info!("All connections closed.");
        },
    }

    Ok(())
}
