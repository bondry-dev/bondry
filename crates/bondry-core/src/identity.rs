use crate::PrincipalId;

/// Classifies the authenticated identity represented by a principal.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum PrincipalKind {
    /// An authenticated human user.
    User,
    /// An authenticated client application or integration.
    Application,
    /// A trusted operating-system or host-application service.
    System,
}

/// An authenticated identity passed from an adapter to the Bondry core.
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct Principal {
    id: PrincipalId,
    kind: PrincipalKind,
}

impl Principal {
    /// Creates an authenticated principal.
    #[must_use]
    pub const fn new(id: PrincipalId, kind: PrincipalKind) -> Self {
        Self { id, kind }
    }

    /// Returns the principal's stable identifier.
    #[must_use]
    pub const fn id(&self) -> &PrincipalId {
        &self.id
    }

    /// Returns the principal classification.
    #[must_use]
    pub const fn kind(&self) -> PrincipalKind {
        self.kind
    }
}
