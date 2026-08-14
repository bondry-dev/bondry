use std::{
    collections::{HashMap, VecDeque},
    hash::Hash,
    sync::Mutex,
    time::{Duration, Instant},
};

const WINDOW: Duration = Duration::from_secs(60);

pub(crate) struct SlidingWindow<K> {
    state: Mutex<RateLimitState<K>>,
}

impl<K> SlidingWindow<K>
where
    K: Clone + Eq + Hash,
{
    pub(crate) fn new() -> Self {
        Self {
            state: Mutex::new(RateLimitState::default()),
        }
    }

    pub(crate) fn check(&self, key: &K, limit: u32, now: Instant) -> RateLimitDecision {
        let mut state = lock(&self.state);
        state.clean_periodically(now);
        let Some(window) = state.windows.get_mut(key) else {
            return RateLimitDecision::Allowed;
        };
        clean_window(window, now);
        if window.len() >= limit as usize {
            return retry_decision(window, now);
        }
        RateLimitDecision::Allowed
    }

    pub(crate) fn consume(&self, key: K, limit: u32, now: Instant) -> RateLimitDecision {
        let mut state = lock(&self.state);
        state.clean_periodically(now);
        let window = state.windows.entry(key).or_default();
        clean_window(window, now);
        if window.len() >= limit as usize {
            return retry_decision(window, now);
        }
        window.push_back(now);
        RateLimitDecision::Allowed
    }
}

struct RateLimitState<K> {
    windows: HashMap<K, VecDeque<Instant>>,
    operations: u8,
}

impl<K> Default for RateLimitState<K> {
    fn default() -> Self {
        Self {
            windows: HashMap::new(),
            operations: 0,
        }
    }
}

impl<K> RateLimitState<K>
where
    K: Eq + Hash,
{
    fn clean_periodically(&mut self, now: Instant) {
        self.operations = self.operations.wrapping_add(1);
        if self.operations != 0 {
            return;
        }
        self.windows.retain(|_, window| {
            clean_window(window, now);
            !window.is_empty()
        });
    }
}

fn clean_window(window: &mut VecDeque<Instant>, now: Instant) {
    let cutoff = now.checked_sub(WINDOW).unwrap_or(now);
    while window.front().is_some_and(|recorded| *recorded <= cutoff) {
        window.pop_front();
    }
}

fn retry_decision(window: &VecDeque<Instant>, now: Instant) -> RateLimitDecision {
    let retry_after = window.front().map_or(1, |recorded| {
        let elapsed = now.saturating_duration_since(*recorded);
        WINDOW.saturating_sub(elapsed).as_secs().max(1)
    });
    RateLimitDecision::Limited { retry_after }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum RateLimitDecision {
    Allowed,
    Limited { retry_after: u64 },
}

fn lock<T>(mutex: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    match mutex.lock() {
        Ok(guard) => guard,
        Err(poisoned) => poisoned.into_inner(),
    }
}

#[cfg(test)]
mod tests {
    use super::{RateLimitDecision, SlidingWindow};
    use std::time::{Duration, Instant};

    #[test]
    fn uses_independent_sliding_windows() {
        let limiter = SlidingWindow::new();
        let start = Instant::now();
        assert_eq!(limiter.consume("a", 2, start), RateLimitDecision::Allowed);
        assert_eq!(
            limiter.consume("a", 2, start + Duration::from_secs(10)),
            RateLimitDecision::Allowed
        );
        assert_eq!(
            limiter.consume("a", 2, start + Duration::from_secs(20)),
            RateLimitDecision::Limited { retry_after: 40 }
        );
        assert_eq!(
            limiter.consume("b", 2, start + Duration::from_secs(20)),
            RateLimitDecision::Allowed
        );
        assert_eq!(
            limiter.consume("a", 2, start + Duration::from_secs(61)),
            RateLimitDecision::Allowed
        );
    }

    #[test]
    fn checking_does_not_consume_capacity() {
        let limiter = SlidingWindow::new();
        let now = Instant::now();
        assert_eq!(limiter.check(&"a", 1, now), RateLimitDecision::Allowed);
        assert_eq!(limiter.check(&"a", 1, now), RateLimitDecision::Allowed);
        assert_eq!(limiter.consume("a", 1, now), RateLimitDecision::Allowed);
        assert_eq!(
            limiter.check(&"a", 1, now),
            RateLimitDecision::Limited { retry_after: 60 }
        );
    }
}
