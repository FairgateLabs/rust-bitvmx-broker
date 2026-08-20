use bitvmx_settings::settings::load_config_file;
use serde::{Deserialize, Serialize};
use tracing::warn;

use crate::{
    rpc::errors::BrokerError,
    settings::{
        MAX_FRAME_SIZE_KB, MAX_MSGS_PER_TICK_UTILIZATION, MAX_QUEUE_DEPTH, MAX_SEND_ATTEMPTS,
        RATE_LIMIT_CAPACITY, RATE_LIMIT_REFILL_RATE, RETRY_MAX_DELAY_MSECS, RETRY_MIN_DELAY_MSECS,
        TOKENS_PER_MESSAGE,
    },
};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BrokerSettings {
    #[serde(default)]
    pub rate_limiter_config: RateLimiterConfig,
    #[serde(default)]
    pub broker_node_config: BrokerNodeConfig,
    #[serde(default)]
    pub msg_size_config: MsgSizeConfig,
    #[serde(default)]
    pub queue_config: QueueConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RateLimiterConfig {
    pub rate_limit_capacity: usize,
    pub rate_limit_refill_rate: f64,
    pub tokens_per_message: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BrokerNodeConfig {
    pub max_msgs_per_tick_utilization: f64,
    pub max_send_attempts: u8,
    pub retry_min_delay_msecs: u64,
    pub retry_max_delay_msecs: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MsgSizeConfig {
    pub max_frame_size_kb: usize,
}

/// Bounds how many messages one sender may have waiting for one destination
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QueueConfig {
    pub max_queue_depth: u64,
}

impl Default for RateLimiterConfig {
    fn default() -> Self {
        warn!("No rate limiter config found, using defaults");
        Self {
            rate_limit_capacity: RATE_LIMIT_CAPACITY,
            rate_limit_refill_rate: RATE_LIMIT_REFILL_RATE,
            tokens_per_message: TOKENS_PER_MESSAGE,
        }
    }
}

impl Default for BrokerNodeConfig {
    fn default() -> Self {
        warn!("No queue channel config found, using defaults");
        Self {
            max_msgs_per_tick_utilization: MAX_MSGS_PER_TICK_UTILIZATION,
            max_send_attempts: MAX_SEND_ATTEMPTS,
            retry_min_delay_msecs: RETRY_MIN_DELAY_MSECS,
            retry_max_delay_msecs: RETRY_MAX_DELAY_MSECS,
        }
    }
}

impl Default for MsgSizeConfig {
    fn default() -> Self {
        warn!("No message size config found, using defaults");
        Self {
            max_frame_size_kb: MAX_FRAME_SIZE_KB,
        }
    }
}

impl Default for QueueConfig {
    fn default() -> Self {
        warn!("No queue config found, using defaults");
        Self {
            max_queue_depth: MAX_QUEUE_DEPTH,
        }
    }
}

impl Default for BrokerSettings {
    fn default() -> Self {
        warn!("No broker settings found, using defaults");
        Self {
            rate_limiter_config: RateLimiterConfig::default(),
            broker_node_config: BrokerNodeConfig::default(),
            msg_size_config: MsgSizeConfig::default(),
            queue_config: QueueConfig::default(),
        }
    }
}

impl BrokerSettings {
    pub fn new(path: &str) -> Result<Self, BrokerError> {
        let config = load_config_file::<Self>(Some(path.to_string()))?;
        Ok(config)
    }
}
