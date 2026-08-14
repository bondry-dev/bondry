# Host-owned secrets

Bondry configuration stores `SecretRef` values, never secret bytes. A Rust
host implements `SecretProvider` and resolves each reference when ingress or
egress needs it. Bondry does not ship a plaintext-file provider or a
recoverable secret store.

```rust
use std::{collections::HashMap, sync::RwLock};

use bondry_secrets::{
    ResolvedSecret, SecretProvider, SecretProviderError, SecretRef, SecretValue,
};

struct HostSecrets {
    values: RwLock<HashMap<String, Vec<u8>>>,
}

impl SecretProvider for HostSecrets {
    fn resolve(
        &self,
        reference: &SecretRef,
    ) -> Result<ResolvedSecret, SecretProviderError> {
        let values = self
            .values
            .read()
            .map_err(|_| SecretProviderError::Unavailable)?;
        let bytes = values
            .get(reference.as_str())
            .ok_or(SecretProviderError::NotFound)?
            .clone();
        let value = SecretValue::new(bytes)
            .map_err(|_| SecretProviderError::InvalidMaterial)?;
        Ok(ResolvedSecret::current(value))
    }
}
```

Production hosts should replace the in-memory map with their platform secret
service. `SecretValue` accepts 1–1024 bytes, redacts debug output, and clears
its allocation when dropped. During rotation, return
`ResolvedSecret::rotating(new, old)` until the sender overlap has elapsed;
new signatures always use the current value while verification accepts both.

Apple hosts use `KeychainSecretProvider` from `BondryApple`. Its `store`,
`rotate`, `resolve`, and `retirePrevious` operations keep the current and
previous values in one Data Protection Keychain item.
