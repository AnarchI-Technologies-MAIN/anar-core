use anar_core_types::{
    AuthorityDependencyRef, AuthorityEnvelope, AuthorityStatus, DecisionOutcome, DependencyBundle,
    RegisteredId, SemanticDigest, ShadowComparison, StableId, SubsetRelation, domain_hash,
};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GenerationVector {
    pub principal_generation: i64,
    pub membership_generation: i64,
    pub organization_generation: i64,
    pub policy_generation: i64,
    pub entitlement_generation: i64,
    pub credential_revision: i64,
    pub principal_global_revocation_epoch: i64,
    pub organization_revocation_epoch: i64,
}

impl GenerationVector {
    pub fn is_non_negative(&self) -> bool {
        [
            self.principal_generation,
            self.membership_generation,
            self.organization_generation,
            self.policy_generation,
            self.entitlement_generation,
            self.credential_revision,
            self.principal_global_revocation_epoch,
            self.organization_revocation_epoch,
        ]
        .into_iter()
        .all(|value| value >= 0)
    }

    pub(crate) fn encode(&self, output: &mut Vec<u8>) {
        for value in [
            self.principal_generation,
            self.membership_generation,
            self.organization_generation,
            self.policy_generation,
            self.entitlement_generation,
            self.credential_revision,
            self.principal_global_revocation_epoch,
            self.organization_revocation_epoch,
        ] {
            output.extend_from_slice(&value.to_be_bytes());
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuthorityContextSnapshot {
    pub authority_context_id: StableId,
    pub principal_id: StableId,
    pub organization_id: StableId,
    pub membership_id: StableId,
    pub authenticator_id: StableId,
    pub status: AuthorityStatus,
    pub issued_at_epoch_ms: i64,
    pub expires_at_epoch_ms: i64,
    pub revoked_at_epoch_ms: Option<i64>,
    pub bound_generations: GenerationVector,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CoreAuthorityState {
    pub principal_status: AuthorityStatus,
    pub organization_status: AuthorityStatus,
    pub membership_status: AuthorityStatus,
    pub authenticator_status: AuthorityStatus,
    pub authenticator_valid_from_epoch_ms: i64,
    pub authenticator_valid_until_epoch_ms: Option<i64>,
    pub live_generations: GenerationVector,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BindingSnapshot {
    pub organization_id: StableId,
    pub capability_id: RegisteredId,
    pub capability_version: u32,
    pub policy_hash: SemanticDigest,
    pub envelope: AuthorityEnvelope,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EvaluationInput {
    pub request_id: StableId,
    pub request_semantic_hash: SemanticDigest,
    pub authority_context: AuthorityContextSnapshot,
    pub current_state: CoreAuthorityState,
    pub binding: BindingSnapshot,
    pub requested_envelope: AuthorityEnvelope,
    pub dependencies: Vec<AuthorityDependencyRef>,
    pub evaluated_at_epoch_ms: i64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ReasonCode {
    CurrentAuthorityProven,
    AuthorityContextExpired,
    AuthorityContextRevoked,
    AuthorityContextInactive,
    PrincipalInactive,
    OrganizationInactive,
    MembershipInactive,
    AuthenticatorInactive,
    AuthenticatorExpired,
    StaleAuthorityGeneration,
    OrganizationMismatch,
    CapabilityMismatch,
    UnsupportedCapabilityVersion,
    RequestedAuthorityExceedsBinding,
    PolicyRequiresApproval,
    PolicyDenied,
    UnsupportedAuthoritySemantics,
    InvalidGenerationState,
    InvalidTimeWindow,
    DependencyVectorInvalid,
    PolicyDigestMismatch,
    InsufficientEntitlement,
    InsufficientEvidence,
    TrustOrRevocationDenied,
}

impl ReasonCode {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::CurrentAuthorityProven => "CURRENT_AUTHORITY_PROVEN",
            Self::AuthorityContextExpired => "AUTHORITY_CONTEXT_EXPIRED",
            Self::AuthorityContextRevoked => "AUTHORITY_CONTEXT_REVOKED",
            Self::AuthorityContextInactive => "AUTHORITY_CONTEXT_INACTIVE",
            Self::PrincipalInactive => "PRINCIPAL_INACTIVE",
            Self::OrganizationInactive => "ORGANIZATION_INACTIVE",
            Self::MembershipInactive => "MEMBERSHIP_INACTIVE",
            Self::AuthenticatorInactive => "AUTHENTICATOR_INACTIVE",
            Self::AuthenticatorExpired => "AUTHENTICATOR_EXPIRED",
            Self::StaleAuthorityGeneration => "STALE_AUTHORITY_GENERATION",
            Self::OrganizationMismatch => "ORGANIZATION_MISMATCH",
            Self::CapabilityMismatch => "CAPABILITY_MISMATCH",
            Self::UnsupportedCapabilityVersion => "UNSUPPORTED_CAPABILITY_VERSION",
            Self::RequestedAuthorityExceedsBinding => "REQUESTED_AUTHORITY_EXCEEDS_BINDING",
            Self::PolicyRequiresApproval => "POLICY_REQUIRES_APPROVAL",
            Self::PolicyDenied => "POLICY_DENIED",
            Self::UnsupportedAuthoritySemantics => "UNSUPPORTED_AUTHORITY_SEMANTICS",
            Self::InvalidGenerationState => "INVALID_GENERATION_STATE",
            Self::InvalidTimeWindow => "INVALID_TIME_WINDOW",
            Self::DependencyVectorInvalid => "DEPENDENCY_VECTOR_INVALID",
            Self::PolicyDigestMismatch => "POLICY_DIGEST_MISMATCH",
            Self::InsufficientEntitlement => "INSUFFICIENT_ENTITLEMENT",
            Self::InsufficientEvidence => "INSUFFICIENT_EVIDENCE",
            Self::TrustOrRevocationDenied => "TRUST_OR_REVOCATION_DENIED",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CandidateDecision {
    pub request_id: StableId,
    pub principal_id: StableId,
    pub organization_id: StableId,
    pub membership_id: StableId,
    pub authenticator_id: StableId,
    pub capability_id: RegisteredId,
    pub capability_version: u32,
    pub outcome: DecisionOutcome,
    pub reason_codes: Vec<ReasonCode>,
    pub effective_envelope: Option<AuthorityEnvelope>,
    pub request_semantic_hash: SemanticDigest,
    pub evaluation_snapshot_hash: SemanticDigest,
    pub policy_bundle_hash: SemanticDigest,
    pub dependency_bundle: DependencyBundle,
    pub evaluated_generations: GenerationVector,
    pub evaluated_at_epoch_ms: i64,
}

pub fn evaluate(input: EvaluationInput) -> CandidateDecision {
    let dependency_bundle = match DependencyBundle::canonicalize(input.dependencies.clone()) {
        Ok(bundle) => bundle,
        Err(_) => {
            return denied(
                &input,
                ReasonCode::DependencyVectorInvalid,
                empty_dependencies(),
            );
        }
    };
    if !input.authority_context.bound_generations.is_non_negative()
        || !input.current_state.live_generations.is_non_negative()
    {
        return denied(
            &input,
            ReasonCode::InvalidGenerationState,
            dependency_bundle,
        );
    }
    if input.authority_context.status != AuthorityStatus::Active {
        return denied(
            &input,
            ReasonCode::AuthorityContextInactive,
            dependency_bundle,
        );
    }
    if input.authority_context.revoked_at_epoch_ms.is_some() {
        return denied(
            &input,
            ReasonCode::AuthorityContextRevoked,
            dependency_bundle,
        );
    }
    if input.authority_context.expires_at_epoch_ms <= input.evaluated_at_epoch_ms {
        return denied(
            &input,
            ReasonCode::AuthorityContextExpired,
            dependency_bundle,
        );
    }
    for (status, reason) in [
        (
            input.current_state.principal_status,
            ReasonCode::PrincipalInactive,
        ),
        (
            input.current_state.organization_status,
            ReasonCode::OrganizationInactive,
        ),
        (
            input.current_state.membership_status,
            ReasonCode::MembershipInactive,
        ),
        (
            input.current_state.authenticator_status,
            ReasonCode::AuthenticatorInactive,
        ),
    ] {
        if status != AuthorityStatus::Active {
            return denied(&input, reason, dependency_bundle);
        }
    }
    if input.current_state.authenticator_valid_from_epoch_ms > input.evaluated_at_epoch_ms
        || input
            .current_state
            .authenticator_valid_until_epoch_ms
            .is_some_and(|expires| expires <= input.evaluated_at_epoch_ms)
    {
        return denied(&input, ReasonCode::AuthenticatorExpired, dependency_bundle);
    }
    if input.authority_context.bound_generations != input.current_state.live_generations {
        return denied(
            &input,
            ReasonCode::StaleAuthorityGeneration,
            dependency_bundle,
        );
    }
    if input.authority_context.organization_id != input.binding.organization_id {
        return denied(&input, ReasonCode::OrganizationMismatch, dependency_bundle);
    }
    if input.binding.capability_id.as_str().is_empty() {
        return denied(&input, ReasonCode::CapabilityMismatch, dependency_bundle);
    }
    if input.binding.capability_version == 0 {
        return denied(
            &input,
            ReasonCode::UnsupportedCapabilityVersion,
            dependency_bundle,
        );
    }
    if !input.requested_envelope.time_window.validate() {
        return denied(&input, ReasonCode::InvalidTimeWindow, dependency_bundle);
    }
    let comparison = input
        .requested_envelope
        .compare_for_shadow_cutover(&input.binding.envelope);
    if !request_is_within_binding(&comparison) {
        return denied(
            &input,
            ReasonCode::RequestedAuthorityExceedsBinding,
            dependency_bundle,
        );
    }
    match input.binding.envelope.outcome {
        DecisionOutcome::Allow => candidate(
            &input,
            DecisionOutcome::Allow,
            ReasonCode::CurrentAuthorityProven,
            Some(input.requested_envelope.clone()),
            dependency_bundle,
        ),
        DecisionOutcome::RequireApproval => candidate(
            &input,
            DecisionOutcome::RequireApproval,
            ReasonCode::PolicyRequiresApproval,
            None,
            dependency_bundle,
        ),
        DecisionOutcome::Deny => denied(&input, ReasonCode::PolicyDenied, dependency_bundle),
        DecisionOutcome::Error | DecisionOutcome::Unknown | DecisionOutcome::Unsupported => denied(
            &input,
            ReasonCode::UnsupportedAuthoritySemantics,
            dependency_bundle,
        ),
    }
}

fn request_is_within_binding(comparison: &ShadowComparison) -> bool {
    comparison
        .dimensions
        .iter()
        .filter(|(dimension, _)| dimension.as_str() != "outcome")
        .all(|(_, relation)| matches!(relation, SubsetRelation::Equal | SubsetRelation::Narrower))
}

fn candidate(
    input: &EvaluationInput,
    outcome: DecisionOutcome,
    reason: ReasonCode,
    effective_envelope: Option<AuthorityEnvelope>,
    dependency_bundle: DependencyBundle,
) -> CandidateDecision {
    CandidateDecision {
        request_id: input.request_id,
        principal_id: input.authority_context.principal_id,
        organization_id: input.authority_context.organization_id,
        membership_id: input.authority_context.membership_id,
        authenticator_id: input.authority_context.authenticator_id,
        capability_id: input.binding.capability_id.clone(),
        capability_version: input.binding.capability_version,
        outcome,
        reason_codes: vec![reason],
        effective_envelope,
        request_semantic_hash: input.request_semantic_hash,
        evaluation_snapshot_hash: evaluation_snapshot_hash(input),
        policy_bundle_hash: input.binding.policy_hash,
        dependency_bundle,
        evaluated_generations: input.current_state.live_generations.clone(),
        evaluated_at_epoch_ms: input.evaluated_at_epoch_ms,
    }
}

pub(crate) fn denied(
    input: &EvaluationInput,
    reason: ReasonCode,
    dependency_bundle: DependencyBundle,
) -> CandidateDecision {
    candidate(
        input,
        DecisionOutcome::Deny,
        reason,
        None,
        dependency_bundle,
    )
}

fn empty_dependencies() -> DependencyBundle {
    DependencyBundle::canonicalize([]).expect("empty dependency bundle is always valid")
}

fn evaluation_snapshot_hash(input: &EvaluationInput) -> SemanticDigest {
    let mut encoded = Vec::new();
    for identifier in [
        input.authority_context.authority_context_id,
        input.authority_context.principal_id,
        input.authority_context.organization_id,
        input.authority_context.membership_id,
        input.authority_context.authenticator_id,
    ] {
        encoded.extend_from_slice(identifier.as_bytes());
    }
    input.current_state.live_generations.encode(&mut encoded);
    encoded.extend_from_slice(&input.evaluated_at_epoch_ms.to_be_bytes());
    domain_hash("ANAR-EVALUATION-SNAPSHOT-1", &[&encoded])
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;

    use anar_core_types::{
        ApprovalRequirement, DelegationBound, EffectScope, EvidenceRequirementSet,
        OfflineRestriction, ResourceScope, RiskTier, TimeWindow, UsageBound,
    };

    use super::*;

    fn id(last: u8) -> StableId {
        let mut bytes = [0_u8; 16];
        bytes[15] = last;
        StableId::from_bytes(bytes)
    }

    fn registered(value: &str) -> RegisteredId {
        RegisteredId::new(value).unwrap()
    }

    fn envelope() -> AuthorityEnvelope {
        AuthorityEnvelope {
            outcome: DecisionOutcome::Allow,
            resource_scope: ResourceScope::ExplicitSet {
                resources: BTreeSet::from([registered("recovery:opp_123")]),
            },
            effect_scope: EffectScope {
                classes: BTreeSet::from([registered("external.communication")]),
            },
            time_window: TimeWindow {
                starts_at_epoch_ms: Some(100),
                ends_at_epoch_ms: Some(300),
            },
            usage_bound: UsageBound(Some(1)),
            delegation_bound: DelegationBound {
                allowed: false,
                max_depth: 0,
            },
            financial_bound: None,
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

    fn input() -> EvaluationInput {
        let generations = GenerationVector {
            principal_generation: 1,
            membership_generation: 2,
            organization_generation: 3,
            policy_generation: 4,
            entitlement_generation: 5,
            credential_revision: 6,
            principal_global_revocation_epoch: 7,
            organization_revocation_epoch: 8,
        };
        EvaluationInput {
            request_id: id(1),
            request_semantic_hash: SemanticDigest::ZERO,
            authority_context: AuthorityContextSnapshot {
                authority_context_id: id(2),
                principal_id: id(3),
                organization_id: id(4),
                membership_id: id(5),
                authenticator_id: id(6),
                status: AuthorityStatus::Active,
                issued_at_epoch_ms: 100,
                expires_at_epoch_ms: 300,
                revoked_at_epoch_ms: None,
                bound_generations: generations.clone(),
            },
            current_state: CoreAuthorityState {
                principal_status: AuthorityStatus::Active,
                organization_status: AuthorityStatus::Active,
                membership_status: AuthorityStatus::Active,
                authenticator_status: AuthorityStatus::Active,
                authenticator_valid_from_epoch_ms: 50,
                authenticator_valid_until_epoch_ms: Some(300),
                live_generations: generations,
            },
            binding: BindingSnapshot {
                organization_id: id(4),
                capability_id: registered("recoveries.notice.send"),
                capability_version: 1,
                policy_hash: SemanticDigest::ZERO,
                envelope: envelope(),
            },
            requested_envelope: envelope(),
            dependencies: Vec::new(),
            evaluated_at_epoch_ms: 200,
        }
    }

    #[test]
    fn current_exact_authority_produces_allow_candidate() {
        let decision = evaluate(input());
        assert_eq!(decision.outcome, DecisionOutcome::Allow);
        assert_eq!(decision.reason_codes, [ReasonCode::CurrentAuthorityProven]);
        assert!(decision.effective_envelope.is_some());
    }

    #[test]
    fn generation_drift_fails_closed() {
        let mut value = input();
        value.current_state.live_generations.membership_generation += 1;
        let decision = evaluate(value);
        assert_eq!(decision.outcome, DecisionOutcome::Deny);
        assert_eq!(
            decision.reason_codes,
            [ReasonCode::StaleAuthorityGeneration]
        );
        assert!(decision.effective_envelope.is_none());
    }

    #[test]
    fn unknown_policy_state_never_becomes_allow() {
        let mut value = input();
        value.binding.envelope.outcome = DecisionOutcome::Unknown;
        let decision = evaluate(value);
        assert_eq!(decision.outcome, DecisionOutcome::Deny);
        assert_eq!(
            decision.reason_codes,
            [ReasonCode::UnsupportedAuthoritySemantics]
        );
    }

    #[test]
    fn resource_widening_is_denied() {
        let mut value = input();
        value.requested_envelope.resource_scope = ResourceScope::ExplicitSet {
            resources: BTreeSet::from([
                registered("recovery:opp_123"),
                registered("recovery:opp_999"),
            ]),
        };
        let decision = evaluate(value);
        assert_eq!(decision.outcome, DecisionOutcome::Deny);
        assert_eq!(
            decision.reason_codes,
            [ReasonCode::RequestedAuthorityExceedsBinding]
        );
    }
}
