use std::{
    collections::{HashMap, VecDeque},
    sync::Mutex,
};

use bondry_core::PrincipalId;
use thiserror::Error;

const WINDOW_MILLISECONDS: u64 = 60_000;
const MAX_REQUESTS_PER_MINUTE: u32 = 60_000;

/// Shared authenticated request limiter for fixed webhook principals.
pub struct AuthenticatedRequestLimiter {
    requests_per_minute: u32,
    state: Mutex<LimiterState>,
}

#[derive(Default)]
struct LimiterState {
    last_monotonic_milliseconds: u64,
    principals: HashMap<PrincipalId, VecDeque<u64>>,
}

impl AuthenticatedRequestLimiter {
    /// Creates a limiter within the existing local-server principal-rate range.
    pub fn new(requests_per_minute: u32) -> Result<Self, AuthenticatedRequestLimitError> {
        if requests_per_minute == 0 || requests_per_minute > MAX_REQUESTS_PER_MINUTE {
            return Err(AuthenticatedRequestLimitError);
        }
        Ok(Self {
            requests_per_minute,
            state: Mutex::new(LimiterState::default()),
        })
    }

    pub(crate) fn admit(
        &self,
        principal: &PrincipalId,
        now_monotonic_milliseconds: u64,
    ) -> AuthenticatedAdmission {
        let mut state = lock(&self.state);
        let now_monotonic_milliseconds =
            now_monotonic_milliseconds.max(state.last_monotonic_milliseconds);
        state.last_monotonic_milliseconds = now_monotonic_milliseconds;
        let cutoff = now_monotonic_milliseconds.saturating_sub(WINDOW_MILLISECONDS);
        let requests = state.principals.entry(principal.clone()).or_default();
        while requests
            .front()
            .is_some_and(|timestamp| *timestamp <= cutoff)
        {
            requests.pop_front();
        }
        if requests.len() >= self.requests_per_minute as usize {
            let retry_after = requests.front().map_or(60, |oldest| {
                oldest
                    .saturating_add(WINDOW_MILLISECONDS)
                    .saturating_sub(now_monotonic_milliseconds)
                    .div_ceil(1_000)
                    .max(1)
            });
            return AuthenticatedAdmission::Limited { retry_after };
        }
        requests.push_back(now_monotonic_milliseconds);
        AuthenticatedAdmission::Allowed
    }
}

impl Default for AuthenticatedRequestLimiter {
    fn default() -> Self {
        Self {
            requests_per_minute: 120,
            state: Mutex::new(LimiterState::default()),
        }
    }
}

pub(crate) enum AuthenticatedAdmission {
    Allowed,
    Limited { retry_after: u64 },
}

fn lock<T>(mutex: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    match mutex.lock() {
        Ok(guard) => guard,
        Err(poisoned) => poisoned.into_inner(),
    }
}

/// An authenticated per-principal rate outside one through 60,000 per minute.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
#[error("authenticated request rate is outside the accepted range")]
pub struct AuthenticatedRequestLimitError;

#[cfg(test)]
mod tests {
    use bondry_core::PrincipalId;

    use super::{AuthenticatedAdmission, AuthenticatedRequestLimiter};

    #[test]
    fn shares_limits_by_principal_and_clamps_clock_regression()
    -> Result<(), Box<dyn std::error::Error>> {
        let limiter = AuthenticatedRequestLimiter::new(1)?;
        let alpha = PrincipalId::new("alpha")?;
        let beta = PrincipalId::new("beta")?;

        assert!(matches!(
            limiter.admit(&alpha, 100),
            AuthenticatedAdmission::Allowed
        ));
        assert!(matches!(
            limiter.admit(&alpha, 100),
            AuthenticatedAdmission::Limited { .. }
        ));
        assert!(matches!(
            limiter.admit(&beta, 100),
            AuthenticatedAdmission::Allowed
        ));
        assert!(matches!(
            limiter.admit(&alpha, 99),
            AuthenticatedAdmission::Limited { .. }
        ));
        Ok(())
    }
}
