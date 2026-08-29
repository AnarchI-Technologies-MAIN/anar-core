use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};

use crate::{RegisteredId, SemanticDigest};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum SubsetRelation {
    Equal,
    Narrower,
    Wider,
    Incomparable,
}

impl SubsetRelation {
    fn from_flags(equal: bool, self_subset: bool, legacy_subset: bool) -> Self {
        if equal {
            Self::Equal
        } else if self_subset {
            Self::Narrower
        } else if legacy_subset {
            Self::Wider
        } else {
            Self::Incomparable
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum DecisionOutcome {
    Deny,
    RequireApproval,
    Allow,
    Error,
    Unknown,
    Unsupported,
}

impl DecisionOutcome {
    fn authority_rank(self) -> u8 {
        match self {
            Self::Deny | Self::Error | Self::Unknown | Self::Unsupported => 0,
            Self::RequireApproval => 1,
            Self::Allow => 2,
        }
    }

    pub fn relation_to(self, legacy: Self) -> SubsetRelation {
        match self.authority_rank().cmp(&legacy.authority_rank()) {
            std::cmp::Ordering::Equal => SubsetRelation::Equal,
            std::cmp::Ordering::Less => SubsetRelation::Narrower,
            std::cmp::Ordering::Greater => SubsetRelation::Wider,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "SCREAMING_SNAKE_CASE", deny_unknown_fields)]
pub enum ResourceScope {
    All,
    ExplicitSet { resources: BTreeSet<RegisteredId> },
    Hierarchy { segments: Vec<RegisteredId> },
}

impl ResourceScope {
    pub fn relation_to(&self, legacy: &Self) -> SubsetRelation {
        match (self, legacy) {
            (Self::All, Self::All) => SubsetRelation::Equal,
            (Self::All, _) => SubsetRelation::Wider,
            (_, Self::All) => SubsetRelation::Narrower,
            (
                Self::ExplicitSet { resources: current },
                Self::ExplicitSet {
                    resources: previous,
                },
            ) => SubsetRelation::from_flags(
                current == previous,
                current.is_subset(previous),
                previous.is_subset(current),
            ),
            (Self::Hierarchy { segments: current }, Self::Hierarchy { segments: previous }) => {
                SubsetRelation::from_flags(
                    current == previous,
                    current.starts_with(previous),
                    previous.starts_with(current),
                )
            }
            _ => SubsetRelation::Incomparable,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EffectScope {
    pub classes: BTreeSet<RegisteredId>,
}

impl EffectScope {
    pub fn relation_to(&self, legacy: &Self) -> SubsetRelation {
        SubsetRelation::from_flags(
            self.classes == legacy.classes,
            self.classes.is_subset(&legacy.classes),
            legacy.classes.is_subset(&self.classes),
        )
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TimeWindow {
    pub starts_at_epoch_ms: Option<i64>,
    pub ends_at_epoch_ms: Option<i64>,
}

impl TimeWindow {
    pub fn validate(&self) -> bool {
        match (self.starts_at_epoch_ms, self.ends_at_epoch_ms) {
            (Some(start), Some(end)) => start <= end,
            _ => true,
        }
    }

    pub fn relation_to(&self, legacy: &Self) -> SubsetRelation {
        if !self.validate() || !legacy.validate() {
            return SubsetRelation::Incomparable;
        }
        let self_subset = lower_is_narrower(self.starts_at_epoch_ms, legacy.starts_at_epoch_ms)
            && upper_is_narrower(self.ends_at_epoch_ms, legacy.ends_at_epoch_ms);
        let legacy_subset = lower_is_narrower(legacy.starts_at_epoch_ms, self.starts_at_epoch_ms)
            && upper_is_narrower(legacy.ends_at_epoch_ms, self.ends_at_epoch_ms);
        SubsetRelation::from_flags(self == legacy, self_subset, legacy_subset)
    }
}

fn lower_is_narrower(current: Option<i64>, previous: Option<i64>) -> bool {
    match (current, previous) {
        (_, None) => true,
        (Some(current), Some(previous)) => current >= previous,
        (None, Some(_)) => false,
    }
}

fn upper_is_narrower(current: Option<i64>, previous: Option<i64>) -> bool {
    match (current, previous) {
        (_, None) => true,
        (Some(current), Some(previous)) => current <= previous,
        (None, Some(_)) => false,
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct UsageBound(pub Option<u64>);

impl UsageBound {
    pub fn relation_to(self, legacy: Self) -> SubsetRelation {
        optional_max_relation(self.0, legacy.0)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DelegationBound {
    pub allowed: bool,
    pub max_depth: u16,
}

impl DelegationBound {
    pub fn relation_to(self, legacy: Self) -> SubsetRelation {
        match (self.allowed, legacy.allowed) {
            (false, false) => SubsetRelation::Equal,
            (false, true) => SubsetRelation::Narrower,
            (true, false) => SubsetRelation::Wider,
            (true, true) => match self.max_depth.cmp(&legacy.max_depth) {
                std::cmp::Ordering::Equal => SubsetRelation::Equal,
                std::cmp::Ordering::Less => SubsetRelation::Narrower,
                std::cmp::Ordering::Greater => SubsetRelation::Wider,
            },
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum FinancialBoundKind {
    MaximumDebit,
    MaximumCredit,
    MaximumAbsoluteTransfer,
    MinimumRequiredCredit,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FinancialBound {
    pub asset_id: RegisteredId,
    pub registry_version: u32,
    pub kind: FinancialBoundKind,
    pub minor_units: u128,
}

impl FinancialBound {
    pub fn relation_to(&self, legacy: &Self) -> SubsetRelation {
        if self.asset_id != legacy.asset_id
            || self.registry_version != legacy.registry_version
            || self.kind != legacy.kind
        {
            return SubsetRelation::Incomparable;
        }
        let ordering = match self.kind {
            FinancialBoundKind::MaximumDebit
            | FinancialBoundKind::MaximumCredit
            | FinancialBoundKind::MaximumAbsoluteTransfer => {
                self.minor_units.cmp(&legacy.minor_units)
            }
            FinancialBoundKind::MinimumRequiredCredit => legacy.minor_units.cmp(&self.minor_units),
        };
        match ordering {
            std::cmp::Ordering::Equal => SubsetRelation::Equal,
            std::cmp::Ordering::Less => SubsetRelation::Narrower,
            std::cmp::Ordering::Greater => SubsetRelation::Wider,
        }
    }
}

fn optional_financial_relation(
    current: &Option<FinancialBound>,
    previous: &Option<FinancialBound>,
) -> SubsetRelation {
    match (current, previous) {
        (None, None) => SubsetRelation::Equal,
        (Some(_), None) => SubsetRelation::Narrower,
        (None, Some(_)) => SubsetRelation::Wider,
        (Some(current), Some(previous)) => current.relation_to(previous),
    }
}

fn optional_max_relation<T: Ord + Copy>(current: Option<T>, previous: Option<T>) -> SubsetRelation {
    match (current, previous) {
        (None, None) => SubsetRelation::Equal,
        (Some(_), None) => SubsetRelation::Narrower,
        (None, Some(_)) => SubsetRelation::Wider,
        (Some(current), Some(previous)) => match current.cmp(&previous) {
            std::cmp::Ordering::Equal => SubsetRelation::Equal,
            std::cmp::Ordering::Less => SubsetRelation::Narrower,
            std::cmp::Ordering::Greater => SubsetRelation::Wider,
        },
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "SCREAMING_SNAKE_CASE", deny_unknown_fields)]
pub enum ApprovalRequirement {
    None,
    OneAuthorizedApprover,
    MultiParty { quorum: u16 },
    RegisteredPolicy { policy_hash: SemanticDigest },
}

impl ApprovalRequirement {
    pub fn relation_to(&self, legacy: &Self) -> SubsetRelation {
        use ApprovalRequirement as A;
        match (self, legacy) {
            (A::None, A::None) => SubsetRelation::Equal,
            (A::None, _) => SubsetRelation::Wider,
            (_, A::None) => SubsetRelation::Narrower,
            (A::OneAuthorizedApprover, A::OneAuthorizedApprover) => SubsetRelation::Equal,
            (A::OneAuthorizedApprover, A::MultiParty { .. }) => SubsetRelation::Wider,
            (A::MultiParty { .. }, A::OneAuthorizedApprover) => SubsetRelation::Narrower,
            (A::MultiParty { quorum: current }, A::MultiParty { quorum: previous }) => {
                match current.cmp(previous) {
                    std::cmp::Ordering::Equal => SubsetRelation::Equal,
                    std::cmp::Ordering::Greater => SubsetRelation::Narrower,
                    std::cmp::Ordering::Less => SubsetRelation::Wider,
                }
            }
            (
                A::RegisteredPolicy {
                    policy_hash: current,
                },
                A::RegisteredPolicy {
                    policy_hash: previous,
                },
            ) if current == previous => SubsetRelation::Equal,
            _ => SubsetRelation::Incomparable,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EvidenceRequirementSet {
    pub required_classes: BTreeSet<RegisteredId>,
}

impl EvidenceRequirementSet {
    pub fn relation_to(&self, legacy: &Self) -> SubsetRelation {
        SubsetRelation::from_flags(
            self.required_classes == legacy.required_classes,
            self.required_classes.is_superset(&legacy.required_classes),
            legacy.required_classes.is_superset(&self.required_classes),
        )
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum RiskTier {
    Low,
    Moderate,
    High,
    Critical,
}

impl RiskTier {
    pub fn relation_to(self, legacy: Self) -> SubsetRelation {
        match self.cmp(&legacy) {
            std::cmp::Ordering::Equal => SubsetRelation::Equal,
            std::cmp::Ordering::Less => SubsetRelation::Narrower,
            std::cmp::Ordering::Greater => SubsetRelation::Wider,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OfflineRestriction {
    pub offline_read_allowed: bool,
    pub deferred_effect_allowed: bool,
}

impl OfflineRestriction {
    pub fn relation_to(self, legacy: Self) -> SubsetRelation {
        let self_subset = (!self.offline_read_allowed || legacy.offline_read_allowed)
            && (!self.deferred_effect_allowed || legacy.deferred_effect_allowed);
        let legacy_subset = (!legacy.offline_read_allowed || self.offline_read_allowed)
            && (!legacy.deferred_effect_allowed || self.deferred_effect_allowed);
        SubsetRelation::from_flags(self == legacy, self_subset, legacy_subset)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuthorityEnvelope {
    pub outcome: DecisionOutcome,
    pub resource_scope: ResourceScope,
    pub effect_scope: EffectScope,
    pub time_window: TimeWindow,
    pub usage_bound: UsageBound,
    pub delegation_bound: DelegationBound,
    pub financial_bound: Option<FinancialBound>,
    pub approval_requirement: ApprovalRequirement,
    pub evidence_requirements: EvidenceRequirementSet,
    pub risk_tier_ceiling: RiskTier,
    pub offline_restriction: OfflineRestriction,
}

impl AuthorityEnvelope {
    pub fn compare_for_shadow_cutover(&self, legacy: &Self) -> ShadowComparison {
        let dimensions = BTreeMap::from([
            (
                "approval_requirement".to_owned(),
                self.approval_requirement
                    .relation_to(&legacy.approval_requirement),
            ),
            (
                "delegation_bound".to_owned(),
                self.delegation_bound.relation_to(legacy.delegation_bound),
            ),
            (
                "effect_scope".to_owned(),
                self.effect_scope.relation_to(&legacy.effect_scope),
            ),
            (
                "evidence_requirements".to_owned(),
                self.evidence_requirements
                    .relation_to(&legacy.evidence_requirements),
            ),
            (
                "financial_bound".to_owned(),
                optional_financial_relation(&self.financial_bound, &legacy.financial_bound),
            ),
            (
                "offline_restriction".to_owned(),
                self.offline_restriction
                    .relation_to(legacy.offline_restriction),
            ),
            (
                "outcome".to_owned(),
                self.outcome.relation_to(legacy.outcome),
            ),
            (
                "resource_scope".to_owned(),
                self.resource_scope.relation_to(&legacy.resource_scope),
            ),
            (
                "risk_tier_ceiling".to_owned(),
                self.risk_tier_ceiling.relation_to(legacy.risk_tier_ceiling),
            ),
            (
                "time_window".to_owned(),
                self.time_window.relation_to(&legacy.time_window),
            ),
            (
                "usage_bound".to_owned(),
                self.usage_bound.relation_to(legacy.usage_bound),
            ),
        ]);
        ShadowComparison { dimensions }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ShadowComparison {
    pub dimensions: BTreeMap<String, SubsetRelation>,
}

impl ShadowComparison {
    pub fn cutover_safe(&self) -> bool {
        self.dimensions
            .values()
            .all(|relation| matches!(relation, SubsetRelation::Equal | SubsetRelation::Narrower))
    }

    pub fn blocking_dimensions(&self) -> Vec<&str> {
        self.dimensions
            .iter()
            .filter_map(|(name, relation)| {
                matches!(
                    relation,
                    SubsetRelation::Wider | SubsetRelation::Incomparable
                )
                .then_some(name.as_str())
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn registered(value: &str) -> RegisteredId {
        RegisteredId::new(value).unwrap()
    }

    fn base() -> AuthorityEnvelope {
        AuthorityEnvelope {
            outcome: DecisionOutcome::Allow,
            resource_scope: ResourceScope::ExplicitSet {
                resources: BTreeSet::from([registered("project:a")]),
            },
            effect_scope: EffectScope {
                classes: BTreeSet::from([registered("external.communication")]),
            },
            time_window: TimeWindow {
                starts_at_epoch_ms: Some(100),
                ends_at_epoch_ms: Some(200),
            },
            usage_bound: UsageBound(Some(2)),
            delegation_bound: DelegationBound {
                allowed: true,
                max_depth: 2,
            },
            financial_bound: Some(FinancialBound {
                asset_id: registered("iso4217:usd"),
                registry_version: 1,
                kind: FinancialBoundKind::MaximumCredit,
                minor_units: 50_000,
            }),
            approval_requirement: ApprovalRequirement::OneAuthorizedApprover,
            evidence_requirements: EvidenceRequirementSet {
                required_classes: BTreeSet::from([registered("adjudication.approval")]),
            },
            risk_tier_ceiling: RiskTier::High,
            offline_restriction: OfflineRestriction {
                offline_read_allowed: false,
                deferred_effect_allowed: false,
            },
        }
    }

    #[test]
    fn same_count_different_resource_is_incomparable() {
        let legacy = base();
        let mut current = legacy.clone();
        current.resource_scope = ResourceScope::ExplicitSet {
            resources: BTreeSet::from([registered("project:b")]),
        };
        let comparison = current.compare_for_shadow_cutover(&legacy);
        assert_eq!(
            comparison.dimensions["resource_scope"],
            SubsetRelation::Incomparable
        );
        assert!(!comparison.cutover_safe());
    }

    #[test]
    fn maximum_credit_uses_maximum_semantics() {
        let legacy = base();
        let mut current = legacy.clone();
        current.financial_bound.as_mut().unwrap().minor_units = 40_000;
        assert_eq!(
            current.compare_for_shadow_cutover(&legacy).dimensions["financial_bound"],
            SubsetRelation::Narrower
        );
    }

    #[test]
    fn removed_financial_bound_is_widening() {
        let legacy = base();
        let mut current = legacy.clone();
        current.financial_bound = None;
        assert_eq!(
            current.compare_for_shadow_cutover(&legacy).dimensions["financial_bound"],
            SubsetRelation::Wider
        );
    }

    #[test]
    fn requirement_state_not_observed_satisfaction_is_compared() {
        let legacy = base();
        let mut current = legacy.clone();
        current
            .evidence_requirements
            .required_classes
            .insert(registered("counterparty.receipt"));
        assert_eq!(
            current.compare_for_shadow_cutover(&legacy).dimensions["evidence_requirements"],
            SubsetRelation::Narrower
        );
    }

    #[test]
    fn invalid_time_window_blocks_cutover() {
        let legacy = base();
        let mut current = legacy.clone();
        current.time_window = TimeWindow {
            starts_at_epoch_ms: Some(300),
            ends_at_epoch_ms: Some(200),
        };
        assert_eq!(
            current.compare_for_shadow_cutover(&legacy).dimensions["time_window"],
            SubsetRelation::Incomparable
        );
    }
}
