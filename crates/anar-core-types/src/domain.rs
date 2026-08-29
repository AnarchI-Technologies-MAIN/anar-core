use serde::{Deserialize, Serialize};

use crate::{RegisteredId, SemanticDigest, StableId};

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum PrincipalKind {
    Human,
    Agent,
    Service,
    Workload,
    Device,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum MembershipClass {
    Standard,
    Guest,
    Service,
    ExternalCollaborator,
    Child,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum BindingStatus {
    Active,
    Suspended,
    Revoked,
    Expired,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ValidityWindow {
    pub valid_from_epoch_ms: i64,
    pub valid_until_epoch_ms: Option<i64>,
}

impl ValidityWindow {
    pub fn is_structurally_valid(self) -> bool {
        self.valid_until_epoch_ms
            .is_none_or(|until| self.valid_from_epoch_ms < until)
    }

    pub fn contains(self, at_epoch_ms: i64) -> bool {
        self.is_structurally_valid()
            && self.valid_from_epoch_ms <= at_epoch_ms
            && self
                .valid_until_epoch_ms
                .is_none_or(|until| at_epoch_ms < until)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EntitlementBindingSnapshot {
    pub entitlement_binding_id: StableId,
    pub organization_id: StableId,
    pub membership_id: Option<StableId>,
    pub principal_id: Option<StableId>,
    pub package_ref: RegisteredId,
    pub entitlement_ref: RegisteredId,
    pub source_system: RegisteredId,
    pub source_digest: SemanticDigest,
    pub status: BindingStatus,
    pub validity: ValidityWindow,
    pub generation: i64,
}

impl EntitlementBindingSnapshot {
    pub fn is_current_for(
        &self,
        organization_id: StableId,
        principal_id: StableId,
        membership_id: StableId,
        at_epoch_ms: i64,
    ) -> bool {
        self.organization_id == organization_id
            && self.principal_id.is_none_or(|value| value == principal_id)
            && self
                .membership_id
                .is_none_or(|value| value == membership_id)
            && self.status == BindingStatus::Active
            && self.generation >= 0
            && self.validity.contains(at_epoch_ms)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExternalStateAssertionSnapshot {
    pub assertion_id: StableId,
    pub organization_id: StableId,
    pub assertion_type: RegisteredId,
    pub object_ref: RegisteredId,
    pub object_digest: SemanticDigest,
    pub issuer_principal_id: StableId,
    pub issuer_class: RegisteredId,
    pub payload_digest: SemanticDigest,
    pub provenance_digest: SemanticDigest,
    pub issued_at_epoch_ms: i64,
    pub valid_until_epoch_ms: Option<i64>,
    pub revoked_at_epoch_ms: Option<i64>,
}

impl ExternalStateAssertionSnapshot {
    pub fn is_current_at(&self, at_epoch_ms: i64) -> bool {
        self.issued_at_epoch_ms <= at_epoch_ms
            && self
                .valid_until_epoch_ms
                .is_none_or(|until| at_epoch_ms < until)
            && self
                .revoked_at_epoch_ms
                .is_none_or(|revoked| at_epoch_ms < revoked)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExternalTrustFactSnapshot {
    pub fact_id: StableId,
    pub organization_id: Option<StableId>,
    pub subject_type: RegisteredId,
    pub subject_ref: RegisteredId,
    pub fact_type: RegisteredId,
    pub fact_value: RegisteredId,
    pub source_system: RegisteredId,
    pub source_digest: SemanticDigest,
    pub observed_at_epoch_ms: i64,
    pub valid_until_epoch_ms: Option<i64>,
}

impl ExternalTrustFactSnapshot {
    pub fn is_current_at(&self, at_epoch_ms: i64) -> bool {
        self.observed_at_epoch_ms <= at_epoch_ms
            && self
                .valid_until_epoch_ms
                .is_none_or(|until| at_epoch_ms < until)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExternalRevocationFactSnapshot {
    pub revocation_fact_id: StableId,
    pub organization_id: Option<StableId>,
    pub target_type: RegisteredId,
    pub target_ref: RegisteredId,
    pub reason_code: RegisteredId,
    pub severity: RegisteredId,
    pub source_system: RegisteredId,
    pub source_digest: SemanticDigest,
    pub effective_at_epoch_ms: i64,
}

impl ExternalRevocationFactSnapshot {
    pub fn is_effective_at(&self, at_epoch_ms: i64) -> bool {
        self.effective_at_epoch_ms <= at_epoch_ms
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn id(last: u8) -> StableId {
        let mut bytes = [0_u8; 16];
        bytes[15] = last;
        StableId::from_bytes(bytes)
    }

    #[test]
    fn validity_windows_are_half_open_and_structurally_checked() {
        let window = ValidityWindow {
            valid_from_epoch_ms: 10,
            valid_until_epoch_ms: Some(20),
        };
        assert!(!window.contains(9));
        assert!(window.contains(10));
        assert!(window.contains(19));
        assert!(!window.contains(20));
        assert!(
            !ValidityWindow {
                valid_from_epoch_ms: 20,
                valid_until_epoch_ms: Some(20),
            }
            .is_structurally_valid()
        );
    }

    #[test]
    fn entitlement_must_match_internal_tenant_and_current_subject() {
        let binding = EntitlementBindingSnapshot {
            entitlement_binding_id: id(1),
            organization_id: id(2),
            membership_id: Some(id(4)),
            principal_id: Some(id(3)),
            package_ref: RegisteredId::new("package.recoveries").unwrap(),
            entitlement_ref: RegisteredId::new("recoveries.notice").unwrap(),
            source_system: RegisteredId::new("marketplace").unwrap(),
            source_digest: SemanticDigest::from_bytes([1; 32]),
            status: BindingStatus::Active,
            validity: ValidityWindow {
                valid_from_epoch_ms: 10,
                valid_until_epoch_ms: Some(20),
            },
            generation: 1,
        };
        assert!(binding.is_current_for(id(2), id(3), id(4), 15));
        assert!(!binding.is_current_for(id(9), id(3), id(4), 15));
        assert!(!binding.is_current_for(id(2), id(3), id(4), 20));
    }
}
