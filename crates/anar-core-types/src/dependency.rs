use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::{SemanticDigest, StableId, domain_hash};

pub const DEPENDENCY_DOMAIN: &str = "ANAR-AUTHORITY-DEPENDENCY-BUNDLE-1";

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum AuthorityDependencyType {
    PolicyBinding,
    EntitlementBinding,
    Delegation,
    GuardianRelationship,
    ElevationGrant,
    ExternalStateAssertion,
    ExternalTrustFact,
    ExternalRevocationWatermark,
}

impl AuthorityDependencyType {
    pub const fn wire_code(self) -> u8 {
        match self {
            Self::PolicyBinding => 1,
            Self::EntitlementBinding => 2,
            Self::Delegation => 3,
            Self::GuardianRelationship => 4,
            Self::ElevationGrant => 5,
            Self::ExternalStateAssertion => 6,
            Self::ExternalTrustFact => 7,
            Self::ExternalRevocationWatermark => 8,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum AuthorityStatus {
    Active,
    Suspended,
    Revoked,
    Expired,
}

impl AuthorityStatus {
    pub const fn wire_code(self) -> u8 {
        match self {
            Self::Active => 1,
            Self::Suspended => 2,
            Self::Revoked => 3,
            Self::Expired => 4,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuthorityDependencyRef {
    pub dependency_type: AuthorityDependencyType,
    pub dependency_id: StableId,
    pub organization_id: Option<StableId>,
    pub expected_generation: Option<i64>,
    pub expected_digest: Option<SemanticDigest>,
    pub expected_status: Option<AuthorityStatus>,
}

impl AuthorityDependencyRef {
    fn key(&self) -> (AuthorityDependencyType, Option<StableId>, StableId) {
        (
            self.dependency_type,
            self.organization_id,
            self.dependency_id,
        )
    }

    fn encode(&self, output: &mut Vec<u8>) {
        output.push(self.dependency_type.wire_code());
        output.extend_from_slice(self.dependency_id.as_bytes());
        encode_optional_bytes(output, self.organization_id.map(|value| *value.as_bytes()));
        match self.expected_generation {
            Some(value) if value >= 0 => {
                output.push(1);
                output.extend_from_slice(&value.to_be_bytes());
            }
            Some(_) => {
                unreachable!("negative generations are rejected before encoding")
            }
            None => output.push(0),
        }
        encode_optional_bytes(output, self.expected_digest.map(|value| *value.as_bytes()));
        match self.expected_status {
            Some(status) => {
                output.push(1);
                output.push(status.wire_code());
            }
            None => output.push(0),
        }
    }
}

fn encode_optional_bytes<const N: usize>(output: &mut Vec<u8>, value: Option<[u8; N]>) {
    match value {
        Some(bytes) => {
            output.push(1);
            output.extend_from_slice(&bytes);
        }
        None => output.push(0),
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DependencyBundle {
    dependencies: Vec<AuthorityDependencyRef>,
    canonical_bytes: Vec<u8>,
    digest: SemanticDigest,
}

impl DependencyBundle {
    pub fn canonicalize(
        dependencies: impl IntoIterator<Item = AuthorityDependencyRef>,
    ) -> Result<Self, DependencyError> {
        let mut unique = BTreeMap::new();
        for dependency in dependencies {
            if dependency
                .expected_generation
                .is_some_and(|value| value < 0)
            {
                return Err(DependencyError::NegativeGeneration);
            }
            match unique.entry(dependency.key()) {
                std::collections::btree_map::Entry::Vacant(entry) => {
                    entry.insert(dependency);
                }
                std::collections::btree_map::Entry::Occupied(entry) => {
                    if entry.get() != &dependency {
                        return Err(DependencyError::ConflictingDuplicate);
                    }
                }
            }
        }
        let dependencies: Vec<_> = unique.into_values().collect();
        let mut canonical_bytes = Vec::new();
        canonical_bytes.extend_from_slice(&(dependencies.len() as u32).to_be_bytes());
        for dependency in &dependencies {
            let mut record = Vec::new();
            dependency.encode(&mut record);
            canonical_bytes.extend_from_slice(&(record.len() as u32).to_be_bytes());
            canonical_bytes.extend_from_slice(&record);
        }
        let digest = domain_hash(DEPENDENCY_DOMAIN, &[&canonical_bytes]);
        Ok(Self {
            dependencies,
            canonical_bytes,
            digest,
        })
    }

    pub fn dependencies(&self) -> &[AuthorityDependencyRef] {
        &self.dependencies
    }

    pub fn canonical_bytes(&self) -> &[u8] {
        &self.canonical_bytes
    }

    pub const fn digest(&self) -> SemanticDigest {
        self.digest
    }
}

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum DependencyError {
    #[error("authority dependency generations cannot be negative")]
    NegativeGeneration,
    #[error("duplicate authority dependency keys contain conflicting expected state")]
    ConflictingDuplicate,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn id(last: u8) -> StableId {
        let mut bytes = [0_u8; 16];
        bytes[15] = last;
        StableId::from_bytes(bytes)
    }

    fn dependency(kind: AuthorityDependencyType, last: u8) -> AuthorityDependencyRef {
        AuthorityDependencyRef {
            dependency_type: kind,
            dependency_id: id(last),
            organization_id: Some(id(200)),
            expected_generation: Some(3),
            expected_digest: None,
            expected_status: Some(AuthorityStatus::Active),
        }
    }

    #[test]
    fn empty_bundle_has_stable_domain_separated_hash() {
        let first = DependencyBundle::canonicalize([]).unwrap();
        let second = DependencyBundle::canonicalize([]).unwrap();
        assert_eq!(first.digest(), second.digest());
        assert_eq!(first.canonical_bytes(), 0_u32.to_be_bytes());
    }

    #[test]
    fn dependency_order_and_exact_duplicates_do_not_change_hash() {
        let first = dependency(AuthorityDependencyType::Delegation, 2);
        let second = dependency(AuthorityDependencyType::PolicyBinding, 1);
        let left = DependencyBundle::canonicalize([first.clone(), second.clone()]).unwrap();
        let right = DependencyBundle::canonicalize([second, first.clone(), first]).unwrap();
        assert_eq!(left.digest(), right.digest());
        assert_eq!(left.canonical_bytes(), right.canonical_bytes());
    }

    #[test]
    fn conflicting_duplicate_fails_closed() {
        let first = dependency(AuthorityDependencyType::Delegation, 2);
        let mut changed = first.clone();
        changed.expected_generation = Some(4);
        assert_eq!(
            DependencyBundle::canonicalize([first, changed]),
            Err(DependencyError::ConflictingDuplicate)
        );
    }
}
