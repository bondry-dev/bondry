use bondry_core::{
    AdapterId, CapabilityGrant, CapabilityId, GrantStore, GrantStoreError, PrincipalId,
};
use rusqlite::params;

use crate::SqlCipherStore;

impl GrantStore for SqlCipherStore {
    fn add_grant(&self, grant: CapabilityGrant) -> Result<bool, GrantStoreError> {
        self.connection()
            .map_err(|_| GrantStoreError::Unavailable)?
            .execute(
                "INSERT OR IGNORE INTO grants (principal_id, adapter_id, capability_id)
                 VALUES (?1, ?2, ?3)",
                params![
                    grant.principal().as_str(),
                    grant.adapter().as_str(),
                    grant.capability().as_str(),
                ],
            )
            .map(|changed| changed == 1)
            .map_err(|_| GrantStoreError::Unavailable)
    }

    fn remove_grant(&self, grant: &CapabilityGrant) -> Result<bool, GrantStoreError> {
        self.connection()
            .map_err(|_| GrantStoreError::Unavailable)?
            .execute(
                "DELETE FROM grants
                 WHERE principal_id = ?1 AND adapter_id = ?2 AND capability_id = ?3",
                params![
                    grant.principal().as_str(),
                    grant.adapter().as_str(),
                    grant.capability().as_str(),
                ],
            )
            .map(|changed| changed == 1)
            .map_err(|_| GrantStoreError::Unavailable)
    }

    fn contains_grant(&self, grant: &CapabilityGrant) -> Result<bool, GrantStoreError> {
        self.connection()
            .map_err(|_| GrantStoreError::Unavailable)?
            .query_row(
                "SELECT EXISTS(
                     SELECT 1 FROM grants
                     WHERE principal_id = ?1 AND adapter_id = ?2 AND capability_id = ?3
                 )",
                params![
                    grant.principal().as_str(),
                    grant.adapter().as_str(),
                    grant.capability().as_str(),
                ],
                |row| row.get::<_, bool>(0),
            )
            .map_err(|_| GrantStoreError::Unavailable)
    }

    fn grants_for_principal(
        &self,
        principal: &PrincipalId,
    ) -> Result<Vec<CapabilityGrant>, GrantStoreError> {
        let connection = self
            .connection()
            .map_err(|_| GrantStoreError::Unavailable)?;
        let mut statement = connection
            .prepare(
                "SELECT adapter_id, capability_id
                 FROM grants
                 WHERE principal_id = ?1
                 ORDER BY adapter_id ASC, capability_id ASC",
            )
            .map_err(|_| GrantStoreError::Unavailable)?;
        let rows = statement
            .query_map([principal.as_str()], |row| {
                Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
            })
            .map_err(|_| GrantStoreError::Unavailable)?;
        let mut grants = Vec::new();
        for row in rows {
            let (adapter, capability) = row.map_err(|_| GrantStoreError::Unavailable)?;
            grants.push(CapabilityGrant::new(
                principal.clone(),
                AdapterId::new(adapter).map_err(|_| GrantStoreError::Unavailable)?,
                CapabilityId::new(capability).map_err(|_| GrantStoreError::Unavailable)?,
            ));
        }
        Ok(grants)
    }
}
