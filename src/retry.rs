use serde::{Deserialize, Serialize};
use std::time::{SystemTime, UNIX_EPOCH};
use thiserror::Error;
use tracing::info;

use crate::rpc::config::BrokerNodeConfig;

#[derive(Debug, Clone)]
pub struct RetryPolicy {
    pub step_ms: u64,
    pub min_delay_ms: u64,
    pub max_delay_ms: u64,
    pub max_attempts: u8,
}

impl RetryPolicy {
    pub fn new(config: &BrokerNodeConfig) -> Result<Self, RetryPolicyError> {
        let min_delay_ms = config.retry_min_delay_msecs;
        let max_delay_ms = config.retry_max_delay_msecs;
        let max_attempts = config.max_send_attempts;
        if min_delay_ms > max_delay_ms {
            return Err(RetryPolicyError::MinGreaterThanMax {
                min: min_delay_ms,
                max: max_delay_ms,
            });
        }

        if max_attempts <= 1 {
            return Err(RetryPolicyError::InvalidMaxAttempts(max_attempts));
        }

        let required_range = max_attempts as u64 - 1;
        if max_delay_ms - min_delay_ms < required_range {
            return Err(RetryPolicyError::DelayRangeTooSmall {
                min: min_delay_ms,
                max: max_delay_ms,
                attempts: max_attempts,
            });
        }

        let steps = max_attempts as u64 - 1;
        let step_ms = (max_delay_ms - min_delay_ms).max(steps) / steps;

        Ok(Self {
            step_ms,
            min_delay_ms,
            max_delay_ms,
            max_attempts,
        })
    }

    pub fn get_next_delay(&self, attempts: u8) -> u64 {
        let delay = self.min_delay_ms + self.step_ms * attempts as u64;
        delay.min(self.max_delay_ms)
    }

    // Returns true if no more retries should be attempted.
    pub fn is_exhausted(&self, state: &RetryState) -> bool {
        state.attempts >= self.max_attempts
    }
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct RetryState {
    attempts: u8,
    next_retry_at: u64,
}

impl RetryState {
    pub fn new(now: u64) -> Self {
        Self {
            attempts: 0,
            next_retry_at: now,
        }
    }

    pub fn record_attempt(&mut self, policy: &RetryPolicy, now_ms: u64) {
        let delay = policy.get_next_delay(self.attempts);
        self.attempts += 1;
        info!(
            "Retried attempt {} at {}, next retry in {} ms",
            self.attempts, now_ms, delay
        );
        self.next_retry_at = now_ms + delay;
    }

    pub fn is_ready(&self, now_ms: u64) -> bool {
        now_ms >= self.next_retry_at
    }

    pub fn get_attempts(&self) -> u8 {
        self.attempts
    }
}

pub fn now_ms() -> Result<u64, std::time::SystemTimeError> {
    Ok(SystemTime::now().duration_since(UNIX_EPOCH)?.as_millis() as u64)
}

#[derive(Error, Debug)]
pub enum RetryPolicyError {
    #[error("min_delay_ms ({min}) must be <= max_delay_ms ({max})")]
    MinGreaterThanMax { min: u64, max: u64 },

    #[error("max_attempts must be > 1, got {0}")]
    InvalidMaxAttempts(u8),

    #[error(
        "max_delay_ms - min_delay_ms must be at least max_attempts - 1 \
         (min: {min}, max: {max}, max_attempts: {attempts})"
    )]
    DelayRangeTooSmall { min: u64, max: u64, attempts: u8 },
}
