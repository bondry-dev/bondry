use serde_json::Value;

use crate::{AdapterId, CapabilityId, InvocationId, Principal};

/// A protocol-neutral request to execute a capability.
#[derive(Clone, Debug)]
pub struct Invocation {
    pub(crate) id: InvocationId,
    pub(crate) adapter: AdapterId,
    pub(crate) principal: Principal,
    pub(crate) capability: CapabilityId,
    pub(crate) input: Value,
}

impl Invocation {
    /// Creates an invocation from authenticated adapter input.
    #[must_use]
    pub const fn new(
        id: InvocationId,
        adapter: AdapterId,
        principal: Principal,
        capability: CapabilityId,
        input: Value,
    ) -> Self {
        Self {
            id,
            adapter,
            principal,
            capability,
            input,
        }
    }

    /// Returns the unique invocation identifier.
    #[must_use]
    pub const fn id(&self) -> &InvocationId {
        &self.id
    }

    /// Returns the adapter identifier.
    #[must_use]
    pub const fn adapter(&self) -> &AdapterId {
        &self.adapter
    }

    /// Returns the authenticated principal.
    #[must_use]
    pub const fn principal(&self) -> &Principal {
        &self.principal
    }

    /// Returns the requested capability identifier.
    #[must_use]
    pub const fn capability(&self) -> &CapabilityId {
        &self.capability
    }

    /// Returns the protocol-neutral input.
    #[must_use]
    pub const fn input(&self) -> &Value {
        &self.input
    }
}

/// Trusted invocation metadata available to a capability handler.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct InvocationContext {
    id: InvocationId,
    adapter: AdapterId,
    principal: Principal,
    capability: CapabilityId,
}

impl InvocationContext {
    pub(crate) fn from_invocation(invocation: &Invocation) -> Self {
        Self {
            id: invocation.id.clone(),
            adapter: invocation.adapter.clone(),
            principal: invocation.principal.clone(),
            capability: invocation.capability.clone(),
        }
    }

    /// Returns the unique invocation identifier.
    #[must_use]
    pub const fn id(&self) -> &InvocationId {
        &self.id
    }

    /// Returns the adapter identifier.
    #[must_use]
    pub const fn adapter(&self) -> &AdapterId {
        &self.adapter
    }

    /// Returns the authenticated principal.
    #[must_use]
    pub const fn principal(&self) -> &Principal {
        &self.principal
    }

    /// Returns the requested capability identifier.
    #[must_use]
    pub const fn capability(&self) -> &CapabilityId {
        &self.capability
    }
}
