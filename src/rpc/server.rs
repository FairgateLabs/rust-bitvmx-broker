use super::{api_impl::BrokerApiImpl, BrokerConfig};
use crate::channel::local::LocalChannel;
use crate::storage::BrokerServerStorage;
use crate::{
    identification::{allow_list::AllowList, identifier::Identifier, routing::RoutingTable},
    rpc::{
        config::{MsgSizeConfig, QueueConfig},
        errors::{BrokerError, MutexExt},
        rate_limiter::RateLimiterManager,
        tls_helper::{AllowListClientVerifier, Cert},
        BrokerApi,
    },
};
use futures::StreamExt;
use rustls::{RootCertStore, ServerConfig};
use std::{
    future::Future,
    net::SocketAddr,
    sync::{Arc, Mutex},
};
use tarpc::{
    serde_transport,
    server::{self, Channel},
    tokio_serde::formats::Json,
};
use tokio::{
    net::{TcpListener, TcpStream},
    runtime::Runtime,
    sync::mpsc,
    task::JoinSet,
};
use tokio_rustls::{server::TlsStream, TlsAcceptor};
use tokio_util::{
    codec::{Framed, LengthDelimitedCodec},
    sync::CancellationToken,
};
use tracing::{debug, error, info};

pub struct BrokerServer {
    rt: Runtime,
    shutdown_tx: mpsc::Sender<()>, // Sending asks the accept loop to stop.
    storage: BrokerServerStorage,
}

impl BrokerServer {
    // The server owns its storage: it opens server_storage_path itself so that no two components
    // can end up on different handles of the same messages. Never give this path to anything else.
    pub fn new(
        config: &BrokerConfig,
        server_storage_path: &str,
        cert: Cert,
        allow_list: Arc<Mutex<AllowList>>,
        routing: Arc<Mutex<RoutingTable>>,
    ) -> Result<Self, BrokerError> {
        let storage = BrokerServerStorage::new(server_storage_path)?;
        let rt = Runtime::new()?;
        let (shutdown_tx, shutdown_rx) = mpsc::channel(1);

        let listener = rt
            .block_on(TcpListener::bind(config.bind_addr()))
            .map_err(BrokerError::BindError)?;
        info!(
            "Listening with TLS on port {}",
            listener
                .local_addr()
                .map_err(BrokerError::BindError)?
                .port()
        );

        let handler = ConnectionHandler::new(config, cert, storage.clone(), allow_list, routing)?;
        rt.spawn(handler.accept_loop(listener, shutdown_rx));

        Ok(Self {
            rt,
            shutdown_tx,
            storage,
        })
    }

    // Do not use in production, this is for testing purposes only
    pub fn new_simple(
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

    // A local channel shares the storage of this server, which is the only way for both to see the
    // same messages. This is why LocalChannel cannot be built on its own.
    pub fn create_local_channel(&self, id: Identifier) -> LocalChannel {
        LocalChannel::new(id, self.storage.clone())
    }

    // Asks the accept loop to stop and waits for it to drain the connections still in flight.
    pub fn close(&mut self) {
        let shutdown = &self.shutdown_tx;
        self.rt.block_on(async move {
            let _ = shutdown.send(()).await;
            shutdown.closed().await; // Resolves once the accept loop drops its receiver.
        });
    }
}

// Everything a connection needs: the TLS acceptor, the storage, the allowlist, the routing table, and the rate limiter.
#[derive(Clone)]
struct ConnectionHandler {
    acceptor: TlsAcceptor,
    storage: BrokerServerStorage,
    allow_list: Arc<Mutex<AllowList>>,
    routing: Arc<Mutex<RoutingTable>>,
    rate_limiter: Arc<RateLimiterManager>,
    msg_size_config: MsgSizeConfig,
    queue_config: QueueConfig,
    cancel: CancellationToken,
}

impl ConnectionHandler {
    fn new(
        config: &BrokerConfig,
        cert: Cert,
        storage: BrokerServerStorage,
        allow_list: Arc<Mutex<AllowList>>,
        routing: Arc<Mutex<RoutingTable>>,
    ) -> Result<Self, BrokerError> {
        // Load certs, private key, and allowlist
        let certs = cert.get_cert()?;
        let key = cert.get_private_key()?;
        let ca_cert_der = cert.get_ca_cert_der()?;

        // Load CA
        let mut roots = RootCertStore::empty();
        roots.add(ca_cert_der)?;

        // Server config
        let client_verifier = Arc::new(
            AllowListClientVerifier::new(allow_list.clone(), roots.into())
                .map_err(|e| BrokerError::TlsError(e.to_string()))?,
        );
        let server_config = ServerConfig::builder()
            .with_client_cert_verifier(client_verifier)
            .with_single_cert(certs, key)?;

        let settings = config.get_settings();

        Ok(Self {
            acceptor: TlsAcceptor::from(Arc::new(server_config)),
            storage,
            allow_list,
            routing,
            rate_limiter: Arc::new(RateLimiterManager::new(settings.rate_limiter_config)),
            msg_size_config: settings.msg_size_config,
            queue_config: settings.queue_config,
            cancel: CancellationToken::new(),
        })
    }

    // Accepts connections until asked to stop by the shutdown channel.
    async fn accept_loop(self, listener: TcpListener, mut shutdown: mpsc::Receiver<()>) {
        let mut connections: JoinSet<()> = JoinSet::new();
        info!("Server started, waiting for TLS connections...");

        loop {
            tokio::select! {
                accepted = listener.accept() => match accepted {
                    Ok((stream, addr)) => {
                        connections.spawn(self.clone().handle_connection(stream, addr));
                    }
                    Err(e) => error!("TCP accept error: {:?}", e),
                },

                // If a connection task ends, the result is logged.
                Some(result) = connections.join_next() => {
                    if let Err(e) = result {
                        error!("Task join error: {:?}", e);
                    }
                }

                _ = shutdown.recv() => {
                    info!("Shutting server down...");
                    self.cancel.cancel();
                    while let Some(result) = connections.join_next().await {
                        if let Err(e) = result {
                            error!("Task join error: {:?}", e);
                        }
                    }
                    info!("All connections closed.");
                    return;
                }
            }
        }
    }

    async fn handle_connection(self, stream: TcpStream, addr: SocketAddr) {
        tokio::select! {
            _ = self.serve_connection(stream) => {}
            _ = self.cancel.cancelled() => {
                debug!("Cancelled connection handler for {}", addr);
            }
        }
    }

    async fn serve_connection(&self, stream: TcpStream) {
        // Perform TLS handshake.
        let tls_stream = match self.acceptor.accept(stream).await {
            Ok(tls_stream) => tls_stream,
            Err(e) => {
                error!("TLS handshake failed: {:?}", e);
                return;
            }
        };

        // Get the fingerprint of the client certificate and check if it's authorized.
        let hex_fingerprint = match self.authorized_fingerprint(&tls_stream) {
            Some(fingerprint) => fingerprint,
            None => return,
        };

        // Client is authorized. Set up the transport and serve the API.
        let codec = LengthDelimitedCodec::builder()
            .max_frame_length(self.msg_size_config.max_frame_size_kb * 1024)
            .new_codec();
        let framed = Framed::new(tls_stream, codec); // Length prefix, message boundaries.
        let transport = serde_transport::new(framed, Json::default());
        server::BaseChannel::with_defaults(transport)
            .execute(
                BrokerApiImpl::new(
                    hex_fingerprint,
                    self.storage.clone(),
                    self.routing.clone(),
                    self.rate_limiter.clone(),
                    self.msg_size_config.clone(),
                    self.queue_config.clone(),
                )
                .serve(),
            )
            .for_each(spawn)
            .await;
    }

    // Check if the client is authorized on the allowlist, returning its fingerprint when it is.
    fn authorized_fingerprint(&self, tls_stream: &TlsStream<TcpStream>) -> Option<String> {
        let peer_addr = match tls_stream.get_ref().0.peer_addr() {
            Ok(addr) => addr,
            Err(e) => {
                error!("Failed to get peer address: {:?}", e);
                return None;
            }
        };
        let cert = match tls_stream.get_ref().1.peer_certificates() {
            Some(certs) if !certs.is_empty() => certs[0].clone(),
            _ => {
                error!("No peer certificate found");
                return None;
            }
        };
        let hex_fingerprint = match Cert::get_fingerprint_hex(&cert) {
            Ok(fingerprint) => fingerprint,
            Err(e) => {
                error!("Failed to get fingerprint: {:?}", e);
                return None;
            }
        };
        let allow = match self.allow_list.lock() {
            Ok(guard) => guard.is_allowed(&hex_fingerprint, peer_addr.ip()),
            Err(e) => {
                error!("Failed to lock allowlist: {:?}", e);
                return None;
            }
        };
        if !allow {
            error!(
                "Unauthorized fingerprint with address {}: {}",
                peer_addr, hex_fingerprint
            );
            return None;
        }
        Some(hex_fingerprint)
    }
}

async fn spawn(fut: impl Future<Output = ()> + Send + 'static) {
    tokio::spawn(fut);
}
