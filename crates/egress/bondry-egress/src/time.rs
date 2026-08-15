use std::time::Duration;

/// A mockable monotonic instant relative to one runtime origin.
#[derive(Clone, Copy, Debug, Default, Eq, Ord, PartialEq, PartialOrd)]
pub struct EgressInstant(Duration);

impl EgressInstant {
    /// The runtime origin.
    pub const ZERO: Self = Self(Duration::ZERO);

    /// Creates an instant at an elapsed duration from the runtime origin.
    #[must_use]
    pub const fn at(elapsed: Duration) -> Self {
        Self(elapsed)
    }

    /// Returns elapsed monotonic time from the runtime origin.
    #[must_use]
    pub const fn elapsed(self) -> Duration {
        self.0
    }

    /// Adds a bounded duration, saturating at the representable maximum.
    #[must_use]
    pub fn saturating_add(self, duration: Duration) -> Self {
        Self(self.0.saturating_add(duration))
    }
}

/// Explicit monotonic and wall-clock time supplied to one transition.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TransitionTime {
    monotonic: EgressInstant,
    unix_ms: u64,
}

impl TransitionTime {
    /// Creates a transition timestamp without reading either clock.
    #[must_use]
    pub const fn new(monotonic: EgressInstant, unix_ms: u64) -> Self {
        Self { monotonic, unix_ms }
    }

    /// Returns the monotonic scheduling instant.
    #[must_use]
    pub const fn monotonic(self) -> EgressInstant {
        self.monotonic
    }

    /// Returns wall-clock Unix milliseconds for persistence and signing.
    #[must_use]
    pub const fn unix_ms(self) -> u64 {
        self.unix_ms
    }
}
