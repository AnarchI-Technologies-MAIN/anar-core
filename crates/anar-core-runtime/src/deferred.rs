use anar_core_engine::DecisionReceipt;
use anar_core_types::{DecisionOutcome, RegisteredId, RiskTier, SemanticDigest, StableId};
use thiserror::Error;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OfflineCaptureKind {
    Draft,
    PendingIntent,
    Evidence,
    PayloadDigest,
    LocalProvenance,
    NonAuthoritativeUiState,
    FinalizedFinancialEffect,
    Publication,
    CredentialChange,
    PrivilegedSystemEffect,
    IrreversibleExternalAction,
    ChildSensitiveHighImpactAction,
}

pub fn offline_capture_allowed(kind: OfflineCaptureKind) -> bool {
    matches!(
        kind,
        OfflineCaptureKind::Draft
            | OfflineCaptureKind::PendingIntent
            | OfflineCaptureKind::Evidence
            | OfflineCaptureKind::PayloadDigest
            | OfflineCaptureKind::LocalProvenance
            | OfflineCaptureKind::NonAuthoritativeUiState
    )
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeferredIntent {
    pub intent_id: StableId,
    pub principal_id: StableId,
    pub organization_id: StableId,
    pub capability_id: RegisteredId,
    pub capability_version: u32,
    pub action_payload_hash: SemanticDigest,
    pub effect_class: RegisteredId,
    pub risk_tier: RiskTier,
    pub queued_at_epoch_ms: i64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EffectTimeAuthorization {
    pub receipt: DecisionReceipt,
    pub action_payload_hash: SemanticDigest,
    pub online_revalidated: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthorizedDeferredExecution {
    pub intent_id: StableId,
    pub decision_receipt_id: StableId,
    pub action_payload_hash: SemanticDigest,
    pub authorized_at_epoch_ms: i64,
}

pub fn authorize_deferred_execution(
    intent: &DeferredIntent,
    authorization: &EffectTimeAuthorization,
    at_epoch_ms: i64,
) -> Result<AuthorizedDeferredExecution, DeferredError> {
    let receipt = &authorization.receipt;
    receipt
        .verify()
        .map_err(|_| DeferredError::InvalidReceipt)?;
    if receipt.outcome != DecisionOutcome::Allow {
        return Err(DeferredError::NotAllowed);
    }
    if receipt.issued_at_epoch_ms > at_epoch_ms || receipt.valid_until_epoch_ms <= at_epoch_ms {
        return Err(DeferredError::StaleAuthority);
    }
    if receipt.principal_id != intent.principal_id
        || receipt.organization_id != intent.organization_id
        || receipt.capability_id != intent.capability_id
        || receipt.capability_version != intent.capability_version
    {
        return Err(DeferredError::AuthorityBindingMismatch);
    }
    if authorization.action_payload_hash != intent.action_payload_hash {
        return Err(DeferredError::PayloadMutation);
    }
    if matches!(intent.risk_tier, RiskTier::High | RiskTier::Critical)
        && !authorization.online_revalidated
    {
        return Err(DeferredError::OnlineRevalidationRequired);
    }
    Ok(AuthorizedDeferredExecution {
        intent_id: intent.intent_id,
        decision_receipt_id: receipt.receipt_id,
        action_payload_hash: intent.action_payload_hash,
        authorized_at_epoch_ms: at_epoch_ms,
    })
}

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum DeferredError {
    #[error("effect-time decision receipt does not verify")]
    InvalidReceipt,
    #[error("effect-time decision is not ALLOW")]
    NotAllowed,
    #[error("effect-time authority is not current")]
    StaleAuthority,
    #[error("effect-time authority does not bind the queued subject or capability")]
    AuthorityBindingMismatch,
    #[error("queued payload changed after authority evaluation")]
    PayloadMutation,
    #[error("high or critical effect requires current online revalidation")]
    OnlineRevalidationRequired,
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;

    use anar_core_engine::{
        AuthorityContextSnapshot, BindingSnapshot, CoreAuthorityState, EvaluationInput,
        FinalizationState, GenerationVector, ReceiptMaterial, evaluate,
    };
    use anar_core_types::{
        ApprovalRequirement, AuthorityEnvelope, AuthorityStatus, DelegationBound, EffectScope,
        EvidenceRequirementSet, OfflineRestriction, ResourceScope, TimeWindow, UsageBound,
    };

    use super::*;

    fn id(last: u8) -> StableId {
        let mut bytes = [0_u8; 16];
        bytes[15] = last;
        StableId::from_bytes(bytes)
    }

    fn rid(value: &str) -> RegisteredId {
        RegisteredId::new(value).unwrap()
    }

    fn receipt() -> DecisionReceipt {
        let generations = GenerationVector {
            principal_generation: 1,
            membership_generation: 1,
            organization_generation: 1,
            policy_generation: 1,
            entitlement_generation: 1,
            credential_revision: 1,
            principal_global_revocation_epoch: 1,
            organization_revocation_epoch: 1,
        };
        let envelope = AuthorityEnvelope {
            outcome: DecisionOutcome::Allow,
            resource_scope: ResourceScope::ExplicitSet {
                resources: BTreeSet::from([rid("recovery:falcon")]),
            },
            effect_scope: EffectScope {
                classes: BTreeSet::from([rid("external.communication")]),
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
                required_classes: BTreeSet::from([rid("opportunity.approved")]),
            },
            risk_tier_ceiling: RiskTier::High,
            offline_restriction: OfflineRestriction {
                offline_read_allowed: true,
                deferred_effect_allowed: true,
            },
        };
        let candidate = evaluate(EvaluationInput {
            request_id: id(1),
            request_semantic_hash: SemanticDigest::from_bytes([1; 32]),
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
                live_generations: generations.clone(),
            },
            binding: BindingSnapshot {
                organization_id: id(4),
                capability_id: rid("recoveries.notice.send"),
                capability_version: 1,
                policy_hash: SemanticDigest::from_bytes([2; 32]),
                envelope: envelope.clone(),
            },
            requested_envelope: envelope,
            dependencies: vec![],
            evaluated_at_epoch_ms: 150,
        });
        DecisionReceipt::issue(
            &candidate,
            &FinalizationState {
                principal_id: id(3),
                organization_id: id(4),
                membership_id: id(5),
                authenticator_id: id(6),
                principal_global_sequence: 1,
                organization_decision_sequence: 1,
                principal_global_revocation_epoch: 1,
                organization_revocation_epoch: 1,
                live_generations: generations,
            },
            ReceiptMaterial {
                receipt_id: id(7),
                decision_id: id(8),
                authority_context_hash: SemanticDigest::from_bytes([3; 32]),
                cal_semantic_hash: SemanticDigest::from_bytes([4; 32]),
                evidence_bundle_hash: SemanticDigest::from_bytes([5; 32]),
                effective_capability_hash: Some(SemanticDigest::from_bytes([6; 32])),
                spec_sha256: SemanticDigest::from_bytes([7; 32]),
                issued_at_epoch_ms: 150,
                valid_until_epoch_ms: 250,
            },
        )
        .unwrap()
    }

    fn intent() -> DeferredIntent {
        DeferredIntent {
            intent_id: id(9),
            principal_id: id(3),
            organization_id: id(4),
            capability_id: rid("recoveries.notice.send"),
            capability_version: 1,
            action_payload_hash: SemanticDigest::from_bytes([9; 32]),
            effect_class: rid("external.communication"),
            risk_tier: RiskTier::High,
            queued_at_epoch_ms: 120,
        }
    }

    #[test]
    fn queue_admission_is_not_execution_authority() {
        let authorization = EffectTimeAuthorization {
            receipt: receipt(),
            action_payload_hash: SemanticDigest::from_bytes([9; 32]),
            online_revalidated: false,
        };
        assert_eq!(
            authorize_deferred_execution(&intent(), &authorization, 200),
            Err(DeferredError::OnlineRevalidationRequired)
        );
    }

    #[test]
    fn changed_payload_and_expired_receipt_fail_closed() {
        let authorization = EffectTimeAuthorization {
            receipt: receipt(),
            action_payload_hash: SemanticDigest::from_bytes([10; 32]),
            online_revalidated: true,
        };
        assert_eq!(
            authorize_deferred_execution(&intent(), &authorization, 200),
            Err(DeferredError::PayloadMutation)
        );
        let current_payload = EffectTimeAuthorization {
            receipt: receipt(),
            action_payload_hash: SemanticDigest::from_bytes([9; 32]),
            online_revalidated: true,
        };
        assert_eq!(
            authorize_deferred_execution(&intent(), &current_payload, 250),
            Err(DeferredError::StaleAuthority)
        );
    }

    #[test]
    fn offline_capture_never_includes_consequential_finalization() {
        assert!(offline_capture_allowed(OfflineCaptureKind::PendingIntent));
        assert!(offline_capture_allowed(OfflineCaptureKind::PayloadDigest));
        assert!(!offline_capture_allowed(
            OfflineCaptureKind::FinalizedFinancialEffect
        ));
        assert!(!offline_capture_allowed(
            OfflineCaptureKind::IrreversibleExternalAction
        ));
    }
}
