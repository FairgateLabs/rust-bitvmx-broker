use crate::{
    rpc::errors::BrokerRpcError,
    settings::{RATE_LIMIT_CAPACITY, RATE_LIMIT_REFILL_RATE},
};
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
    pub fn new() -> Self {
        RateLimiterManager {
            pubk_hash_limiters: Mutex::new(HashMap::new()),
            rate_limit_capacity: RATE_LIMIT_CAPACITY,
            rate_limit_refill_rate: RATE_LIMIT_REFILL_RATE,
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
