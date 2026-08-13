use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use bondry_core::InvocationId;
use thiserror::Error;

const RANDOM_BYTES: usize = 16;

/// Generates unique invocation identifiers for protocol adapters.
pub trait InvocationIdGenerator: Send + Sync {
    /// Generates one validated identifier.
    fn generate(&self) -> Result<InvocationId, InvocationIdGenerationError>;
}

/// Generates invocation identifiers with operating-system entropy.
#[derive(Clone, Copy, Debug, Default)]
pub struct SystemInvocationIdGenerator;

impl InvocationIdGenerator for SystemInvocationIdGenerator {
    fn generate(&self) -> Result<InvocationId, InvocationIdGenerationError> {
        let mut random = [0_u8; RANDOM_BYTES];
        getrandom::fill(&mut random).map_err(|_| InvocationIdGenerationError)?;
        InvocationId::new(format!("request_{}", URL_SAFE_NO_PAD.encode(random)))
            .map_err(|_| InvocationIdGenerationError)
    }
}

/// Secure invocation identifier generation failed.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
#[error("secure invocation identifier generation is unavailable")]
pub struct InvocationIdGenerationError;

#[cfg(test)]
mod tests {
    use super::{InvocationIdGenerator, SystemInvocationIdGenerator};

    #[test]
    fn generates_independent_portable_identifiers() -> Result<(), Box<dyn std::error::Error>> {
        let generator = SystemInvocationIdGenerator;
        let first = generator.generate()?;
        let second = generator.generate()?;

        assert_ne!(first, second);
        assert!(first.as_str().starts_with("request_"));
        Ok(())
    }
}
