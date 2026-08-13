use std::collections::{HashMap, hash_map::Entry};

use thiserror::Error;

use crate::{CapabilityDescriptor, CapabilityHandler, CapabilityId};

struct RegisteredCapability {
    descriptor: CapabilityDescriptor,
    handler: Box<dyn CapabilityHandler>,
}

/// A collection of uniquely identified application capabilities.
#[derive(Default)]
pub struct CapabilityRegistry {
    capabilities: HashMap<CapabilityId, RegisteredCapability>,
}

impl CapabilityRegistry {
    /// Creates an empty registry.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Registers a capability and rejects duplicate identifiers.
    pub fn register<H>(
        &mut self,
        descriptor: CapabilityDescriptor,
        handler: H,
    ) -> Result<(), RegistrationError>
    where
        H: CapabilityHandler + 'static,
    {
        match self.capabilities.entry(descriptor.id().clone()) {
            Entry::Occupied(entry) => Err(RegistrationError::Duplicate(entry.key().clone())),
            Entry::Vacant(entry) => {
                entry.insert(RegisteredCapability {
                    descriptor,
                    handler: Box::new(handler),
                });
                Ok(())
            }
        }
    }

    /// Returns the number of registered capabilities.
    #[must_use]
    pub fn len(&self) -> usize {
        self.capabilities.len()
    }

    /// Returns whether the registry is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.capabilities.is_empty()
    }

    /// Returns capability descriptors in stable identifier order.
    #[must_use]
    pub fn descriptors(&self) -> Vec<&CapabilityDescriptor> {
        let mut descriptors: Vec<_> = self
            .capabilities
            .values()
            .map(|capability| &capability.descriptor)
            .collect();
        descriptors.sort_unstable_by_key(|descriptor| descriptor.id());
        descriptors
    }

    pub(crate) fn resolve(
        &self,
        id: &CapabilityId,
    ) -> Option<(&CapabilityDescriptor, &dyn CapabilityHandler)> {
        self.capabilities.get(id).map(|capability| {
            (
                &capability.descriptor,
                capability.handler.as_ref() as &dyn CapabilityHandler,
            )
        })
    }
}

/// An error produced while registering a capability.
#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum RegistrationError {
    /// A capability with the same identifier is already registered.
    #[error("capability {0} is already registered")]
    Duplicate(CapabilityId),
}
