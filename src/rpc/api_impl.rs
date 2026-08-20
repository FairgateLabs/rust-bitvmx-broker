use super::Message;
use crate::storage::BrokerServerStorage;
use crate::{
    identification::{identifier::Identifier, routing::RoutingTable},
    rpc::{
        config::{MsgSizeConfig, QueueConfig},
        errors::{BrokerRpcError, MutexExt},
        rate_limiter::RateLimiterManager,
        BrokerApi,
    },
};
use std::sync::{Arc, Mutex};
use tarpc::context;
use tracing::warn;

// One per connection.
#[derive(Clone)]
pub(crate) struct BrokerApiImpl {
    client_pubkey_hash: String,
    storage: BrokerServerStorage,
    routing: Arc<Mutex<RoutingTable>>,
    rate_limiter: Arc<RateLimiterManager>,
    msg_size_config: MsgSizeConfig,
    queue_config: QueueConfig,
}

impl BrokerApiImpl {
    pub(crate) fn new(
        client_pubkey_hash: String,
        storage: BrokerServerStorage,
        routing: Arc<Mutex<RoutingTable>>,
        rate_limiter: Arc<RateLimiterManager>,
        msg_size_config: MsgSizeConfig,
        queue_config: QueueConfig,
    ) -> Self {
        Self {
            client_pubkey_hash,
            storage,
            routing,
            rate_limiter,
            msg_size_config,
            queue_config,
        }
    }
}

impl BrokerApi for BrokerApiImpl {
    async fn send(
        self,
        _: context::Context,
        from_id: u8,
        dest: Identifier,
        msg: String,
    ) -> Result<bool, BrokerRpcError> {
        if !self
            .rate_limiter
            .check_rate_limit(&self.client_pubkey_hash)?
        {
            warn!(
                "Rate limit exceeded trying to send msg for {}",
                self.client_pubkey_hash
            );
            return Err(BrokerRpcError::RateLimitExceeded);
        }
        let from = Identifier {
            pubkey_hash: self.client_pubkey_hash.clone(),
            id: from_id,
        };
        let allowed = {
            let routing = self.routing.lock_or_err::<BrokerRpcError>("routing")?;
            routing.can_route(&from, &dest)
        };

        if !allowed {
            warn!("Routing denied: {} cannot send to {}", from, dest);
            return Ok(false);
        }
        if msg.len() > (self.msg_size_config.max_frame_size_kb - 4) * 1024 {
            // 4 for encoding overhead
            warn!("Message too large: {} bytes", msg.len());
            return Err(BrokerRpcError::MessageTooLarge(
                self.msg_size_config.max_frame_size_kb - 4,
                msg.len() / 1024,
            ));
        }

        // Check queue depth. If the queue is full, reject the message.
        let queue_depth = self.storage.get_count_for_identifier(&from, &dest)?;
        if queue_depth >= self.queue_config.max_queue_depth {
            warn!(
                "Queue from {} to {} is full, it holds {} messages",
                from, dest, queue_depth
            );
            return Err(BrokerRpcError::QueueFull(dest.to_string(), queue_depth));
        }

        self.storage.insert(from, dest, msg)?;
        Ok(true)
    }

    async fn get(
        self,
        _: context::Context,
        dest_id: u8,
    ) -> Result<Option<Message>, BrokerRpcError> {
        if !self
            .rate_limiter
            .check_rate_limit(&self.client_pubkey_hash)?
        {
            warn!(
                "Rate limit exceeded trying to get msg for {}",
                self.client_pubkey_hash
            );
            return Err(BrokerRpcError::RateLimitExceeded);
        }
        let auth_dest = Identifier {
            pubkey_hash: self.client_pubkey_hash.clone(),
            id: dest_id,
        };
        Ok(self.storage.get(auth_dest)?)
    }

    async fn ack(self, _: context::Context, dest_id: u8, uid: u64) -> Result<bool, BrokerRpcError> {
        if !self
            .rate_limiter
            .check_rate_limit(&self.client_pubkey_hash)?
        {
            warn!(
                "Rate limit exceeded trying to ack msg for {}",
                self.client_pubkey_hash
            );
            return Err(BrokerRpcError::RateLimitExceeded);
        }
        let auth_dest = Identifier {
            pubkey_hash: self.client_pubkey_hash.clone(),
            id: dest_id,
        };
        Ok(self.storage.remove(auth_dest, uid)?)
    }

    async fn ping(self, _: context::Context) -> Result<bool, BrokerRpcError> {
        if !self
            .rate_limiter
            .check_rate_limit(&self.client_pubkey_hash)?
        {
            warn!(
                "Rate limit exceeded trying to ping for {}",
                self.client_pubkey_hash
            );
            return Err(BrokerRpcError::RateLimitExceeded);
        }
        Ok(true)
    }
}
