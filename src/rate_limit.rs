//! A small in-memory failure limiter with a fixed window.

use std::{
    collections::{HashMap, VecDeque},
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};

#[derive(Clone)]
pub struct RateLimiter {
    failures: Arc<Mutex<HashMap<String, VecDeque<Instant>>>>,
    limit: usize,
    window: Duration,
    capacity: usize,
}

impl RateLimiter {
    /// Allows `limit` failures per key within `window`, tracking at most `capacity` keys.
    pub fn new(limit: usize, window: Duration, capacity: usize) -> Self {
        Self {
            failures: Arc::new(Mutex::new(HashMap::new())),
            limit,
            window,
            capacity,
        }
    }

    /// Whether `key` may make another attempt.
    pub fn check(&self, key: &str) -> bool {
        self.check_at(key, Instant::now())
    }

    pub fn record_failure(&self, key: &str) {
        self.record_failure_at(key, Instant::now());
    }

    pub fn clear(&self, key: &str) {
        self.lock().remove(key);
    }

    fn check_at(&self, key: &str, now: Instant) -> bool {
        let mut failures = self.lock();
        let Some(attempts) = failures.get_mut(key) else {
            return true;
        };
        prune(attempts, now, self.window);
        if attempts.is_empty() {
            failures.remove(key);
            return true;
        }
        attempts.len() < self.limit
    }

    fn record_failure_at(&self, key: &str, now: Instant) {
        let mut failures = self.lock();
        if failures.len() >= self.capacity && !failures.contains_key(key) {
            // Sweep expired keys first; only evict a live key when the map is still full.
            failures.retain(|_, attempts| {
                prune(attempts, now, self.window);
                !attempts.is_empty()
            });
            if failures.len() >= self.capacity
                && let Some(oldest) = failures
                    .iter()
                    .min_by_key(|(_, attempts)| attempts.front().copied())
                    .map(|(key, _)| key.clone())
            {
                failures.remove(&oldest);
            }
        }
        let attempts = failures.entry(key.to_owned()).or_default();
        prune(attempts, now, self.window);
        if attempts.len() < self.limit {
            attempts.push_back(now);
        }
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, HashMap<String, VecDeque<Instant>>> {
        self.failures
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }
}

fn prune(attempts: &mut VecDeque<Instant>, now: Instant, window: Duration) {
    while attempts
        .front()
        .is_some_and(|time| now.duration_since(*time) >= window)
    {
        attempts.pop_front();
    }
}

#[cfg(test)]
mod tests {
    use std::time::{Duration, Instant};

    use super::RateLimiter;

    #[test]
    fn limits_after_the_configured_number_of_failures() {
        let limiter = RateLimiter::new(3, Duration::from_secs(60), 16);
        let now = Instant::now();
        for _ in 0..3 {
            assert!(limiter.check_at("a", now));
            limiter.record_failure_at("a", now);
        }
        assert!(!limiter.check_at("a", now));
        assert!(limiter.check_at("b", now));
    }

    #[test]
    fn forgets_failures_after_the_window() {
        let limiter = RateLimiter::new(1, Duration::from_secs(60), 16);
        let now = Instant::now();
        limiter.record_failure_at("a", now);
        assert!(!limiter.check_at("a", now + Duration::from_secs(59)));
        assert!(limiter.check_at("a", now + Duration::from_secs(60)));
    }

    #[test]
    fn clear_resets_one_key() {
        let limiter = RateLimiter::new(1, Duration::from_secs(60), 16);
        limiter.record_failure("a");
        limiter.record_failure("b");
        limiter.clear("a");
        assert!(limiter.check("a"));
        assert!(!limiter.check("b"));
    }

    #[test]
    fn evicts_the_oldest_key_at_capacity() {
        let limiter = RateLimiter::new(1, Duration::from_secs(60), 2);
        let now = Instant::now();
        limiter.record_failure_at("old", now);
        limiter.record_failure_at("newer", now + Duration::from_secs(1));
        limiter.record_failure_at("newest", now + Duration::from_secs(2));
        assert!(limiter.check_at("old", now + Duration::from_secs(2)));
        assert!(!limiter.check_at("newer", now + Duration::from_secs(2)));
        assert!(!limiter.check_at("newest", now + Duration::from_secs(2)));
    }
}
