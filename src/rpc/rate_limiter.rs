use crate::rpc::{config::RateLimiterConfig, errors::BrokerRpcError};
use std::{collections::HashMap, sync::Mutex, time::Instant};

#[derive(Clone)]
pub struct RateLimiter {
    capacity: usize,  // Max tokens
    tokens: usize,    // Current available tokens
    refill_rate: f64, // Tokens added per second
    last_refill: Instant,
}

impl RateLimiter {
    fn new(capacity: usize, refill_rate: f64) -> Self {
        RateLimiter {
            capacity,
            tokens: capacity,
            refill_rate,
            last_refill: Instant::now(),
        }
    }

    fn refill(&mut self) {
        let now = Instant::now();
        let elapsed = now.duration_since(self.last_refill).as_secs_f64();
        let new_tokens = (elapsed * self.refill_rate) as usize;
        if new_tokens > 0 {
            self.tokens = (self.tokens + new_tokens).min(self.capacity);
            self.last_refill = now;
        }
    }

    fn try_consume(&mut self) -> bool {
        self.refill();
        if self.tokens > 0 {
            self.tokens -= 1;
            true
        } else {
            false
        }
    }
}

pub struct RateLimiterManager {
    pubk_hash_limiters: Mutex<HashMap<String, RateLimiter>>,
    rate_limit_capacity: usize,  // Maximum number of requests
    rate_limit_refill_rate: f64, // Tokens refilled per second
}

impl RateLimiterManager {
    pub fn new(rate_limiter_config: RateLimiterConfig) -> Self {
        RateLimiterManager {
            pubk_hash_limiters: Mutex::new(HashMap::new()),
            rate_limit_capacity: rate_limiter_config.rate_limit_capacity,
            rate_limit_refill_rate: rate_limiter_config.rate_limit_refill_rate,
        }
    }

    pub fn new_with_limits(rate_limit_capacity: usize, rate_limit_refill_rate: f64) -> Self {
        RateLimiterManager {
            pubk_hash_limiters: Mutex::new(HashMap::new()),
            rate_limit_capacity,
            rate_limit_refill_rate,
        }
    }

    pub fn check_rate_limit(&self, pubk_hash: &str) -> Result<bool, BrokerRpcError> {
        let mut limiters = self
            .pubk_hash_limiters
            .lock()
            .map_err(|_| BrokerRpcError::MutexError("rate_limiters".to_string()))?;
        let limiter = limiters.entry(pubk_hash.to_string()).or_insert_with(|| {
            RateLimiter::new(self.rate_limit_capacity, self.rate_limit_refill_rate)
        });
        Ok(limiter.try_consume())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{thread::sleep, time::Duration};

    /// Test that a sender can spend its own budget and that it refills over time.
    #[test]
    fn test_spend_and_refill() {
        // Two requests up front, then one more every 100 ms.
        let manager = RateLimiterManager::new_with_limits(2, 10.0);

        assert!(manager.check_rate_limit("peer").unwrap());
        assert!(manager.check_rate_limit("peer").unwrap());
        // The third arrives before any refill, so it is refused rather than queued.
        assert!(!manager.check_rate_limit("peer").unwrap());

        // Budgets are per sender, so one peer spending its own does not touch another's.
        assert!(manager.check_rate_limit("other").unwrap());
        assert!(manager.check_rate_limit("other").unwrap());
        assert!(!manager.check_rate_limit("other").unwrap());

        // Waiting long enough for one token to accrue lets exactly one more request through.
        sleep(Duration::from_millis(150));
        assert!(manager.check_rate_limit("peer").unwrap());
        assert!(!manager.check_rate_limit("peer").unwrap());
    }

    /// Test that the bucket refills to its capacity and no further.
    #[test]
    fn test_bucket_refills() {
        let mut limiter = RateLimiter::new(2, 1000.0);
        assert!(limiter.try_consume());
        assert!(limiter.try_consume());
        assert!(!limiter.try_consume());

        // Far more tokens accrue than the bucket holds, and the surplus is discarded.
        sleep(Duration::from_millis(50));
        limiter.refill();
        assert_eq!(limiter.tokens, limiter.capacity);

        // A manager built from settings starts every sender at the configured capacity.
        let config = RateLimiterConfig {
            rate_limit_capacity: 1,
            rate_limit_refill_rate: 0.0,
            ..Default::default()
        };
        let manager = RateLimiterManager::new(config);
        assert!(manager.check_rate_limit("peer").unwrap());
        // Nothing is refilled at a rate of zero, so the sender stays refused.
        assert!(!manager.check_rate_limit("peer").unwrap());
        sleep(Duration::from_millis(20));
        assert!(!manager.check_rate_limit("peer").unwrap());
    }
}
