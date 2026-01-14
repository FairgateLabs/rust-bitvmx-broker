use serde::{Deserialize, Serialize};
use std::time::{SystemTime, UNIX_EPOCH};
use tracing::info;

#[derive(Debug, Clone)]
pub struct RetryPolicy {
    step_ms: u64,
    min_delay_ms: u64,
    max_delay_ms: u64,
    max_attempts: u8,
}

impl RetryPolicy {
    pub fn new(min_delay_ms: u64, max_delay_ms: u64, max_attempts: u8) -> Self {
        assert!(min_delay_ms <= max_delay_ms);
        assert!(max_attempts > 1, "max_attempts must be > 1");
        assert!(
            max_delay_ms - min_delay_ms >= (max_attempts as u64 - 1),
            "max_delay - min_delay must be at least max_attempts - 1"
        );

        let steps = max_attempts as u64 - 1;
        let step_ms = (max_delay_ms - min_delay_ms).max(steps) / steps;

        Self {
            step_ms,
            min_delay_ms,
            max_delay_ms,
            max_attempts,
        }
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
