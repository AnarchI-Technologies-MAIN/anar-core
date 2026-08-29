use anar_core_types::{DecisionOutcome, RegisteredId, SemanticDigest, StableId, domain_hash};
use thiserror::Error;

use crate::{CandidateDecision, GenerationVector, ReasonCode};

const RECEIPT_DOMAIN: &str = "ANAR-DECISION-RECEIPT-1";
const RECEIPT_HASH_DOMAIN: &str = "ANAR-DECISION-RECEIPT-HASH-1";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FinalizationState {
    pub principal_id: StableId,
    pub organization_id: StableId,
    pub membership_id: StableId,
    pub authenticator_id: StableId,
    pub principal_global_sequence: i64,
    pub organization_decision_sequence: i64,
    pub principal_global_revocation_epoch: i64,
    pub organization_revocation_epoch: i64,
    pub live_generations: GenerationVector,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReceiptMaterial {
    pub receipt_id: StableId,
    pub decision_id: StableId,
    pub authority_context_hash: SemanticDigest,
    pub cal_semantic_hash: SemanticDigest,
    pub evidence_bundle_hash: SemanticDigest,
    pub effective_capability_hash: Option<SemanticDigest>,
    pub spec_sha256: SemanticDigest,
    pub issued_at_epoch_ms: i64,
    pub valid_until_epoch_ms: i64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DecisionReceipt {
    pub receipt_id: StableId,
    pub decision_id: StableId,
    pub request_id: StableId,
    pub principal_id: StableId,
    pub organization_id: StableId,
    pub membership_id: StableId,
    pub authenticator_id: StableId,
    pub capability_id: RegisteredId,
    pub capability_version: u32,
    pub outcome: DecisionOutcome,
    pub reason_codes: Vec<ReasonCode>,
    pub authority_context_hash: SemanticDigest,
    pub request_semantic_hash: SemanticDigest,
    pub cal_semantic_hash: SemanticDigest,
    pub evaluation_snapshot_hash: SemanticDigest,
    pub effective_capability_hash: Option<SemanticDigest>,
    pub policy_bundle_hash: SemanticDigest,
    pub evidence_bundle_hash: SemanticDigest,
    pub dependency_bundle_hash: SemanticDigest,
    pub spec_sha256: SemanticDigest,
    pub principal_global_sequence: i64,
    pub organization_decision_sequence: i64,
    pub principal_global_revocation_epoch: i64,
    pub organization_revocation_epoch: i64,
    pub live_generations: GenerationVector,
    pub issued_at_epoch_ms: i64,
    pub valid_until_epoch_ms: i64,
    pub canonical_bytes: Vec<u8>,
    pub receipt_hash: SemanticDigest,
}

impl DecisionReceipt {
    pub fn issue(
        candidate: &CandidateDecision,
        finalization: &FinalizationState,
        material: ReceiptMaterial,
    ) -> Result<Self, ReceiptError> {
        if candidate.principal_id != finalization.principal_id
            || candidate.organization_id != finalization.organization_id
            || candidate.membership_id != finalization.membership_id
            || candidate.authenticator_id != finalization.authenticator_id
        {
            return Err(ReceiptError::FinalizationBindingMismatch);
        }
        if candidate.evaluated_generations != finalization.live_generations {
            return Err(ReceiptError::StaleFinalizationState);
        }
        if [
            finalization.principal_global_sequence,
            finalization.organization_decision_sequence,
            finalization.principal_global_revocation_epoch,
            finalization.organization_revocation_epoch,
        ]
        .into_iter()
        .any(|value| value < 0)
            || !finalization.live_generations.is_non_negative()
        {
            return Err(ReceiptError::InvalidSequenceState);
        }
        if material.valid_until_epoch_ms <= material.issued_at_epoch_ms {
            return Err(ReceiptError::InvalidValidityWindow);
        }
        if candidate.outcome == DecisionOutcome::Allow
            && material.effective_capability_hash.is_none()
        {
            return Err(ReceiptError::MissingEffectiveCapabilityHash);
        }
        if candidate.outcome != DecisionOutcome::Allow
            && material.effective_capability_hash.is_some()
        {
            return Err(ReceiptError::UnexpectedEffectiveCapabilityHash);
        }

        let mut receipt = Self {
            receipt_id: material.receipt_id,
            decision_id: material.decision_id,
            request_id: candidate.request_id,
            principal_id: candidate.principal_id,
            organization_id: candidate.organization_id,
            membership_id: candidate.membership_id,
            authenticator_id: candidate.authenticator_id,
            capability_id: candidate.capability_id.clone(),
            capability_version: candidate.capability_version,
            outcome: candidate.outcome,
            reason_codes: candidate.reason_codes.clone(),
            authority_context_hash: material.authority_context_hash,
            request_semantic_hash: candidate.request_semantic_hash,
            cal_semantic_hash: material.cal_semantic_hash,
            evaluation_snapshot_hash: candidate.evaluation_snapshot_hash,
            effective_capability_hash: material.effective_capability_hash,
            policy_bundle_hash: candidate.policy_bundle_hash,
            evidence_bundle_hash: material.evidence_bundle_hash,
            dependency_bundle_hash: candidate.dependency_bundle.digest(),
            spec_sha256: material.spec_sha256,
            principal_global_sequence: finalization.principal_global_sequence,
            organization_decision_sequence: finalization.organization_decision_sequence,
            principal_global_revocation_epoch: finalization.principal_global_revocation_epoch,
            organization_revocation_epoch: finalization.organization_revocation_epoch,
            live_generations: finalization.live_generations.clone(),
            issued_at_epoch_ms: material.issued_at_epoch_ms,
            valid_until_epoch_ms: material.valid_until_epoch_ms,
            canonical_bytes: Vec::new(),
            receipt_hash: SemanticDigest::ZERO,
        };
        receipt.canonical_bytes = receipt.encode();
        receipt.receipt_hash = domain_hash(RECEIPT_HASH_DOMAIN, &[&receipt.canonical_bytes]);
        Ok(receipt)
    }

    pub fn verify(&self) -> Result<(), ReceiptError> {
        let encoded = self.encode();
        if encoded != self.canonical_bytes
            || domain_hash(RECEIPT_HASH_DOMAIN, &[&encoded]) != self.receipt_hash
        {
            return Err(ReceiptError::ReceiptHashMismatch);
        }
        Ok(())
    }

    fn encode(&self) -> Vec<u8> {
        let mut output = Vec::new();
        encode_bytes(&mut output, RECEIPT_DOMAIN.as_bytes());
        output.extend_from_slice(self.receipt_id.as_bytes());
        output.extend_from_slice(self.decision_id.as_bytes());
        output.extend_from_slice(self.request_id.as_bytes());
        output.extend_from_slice(self.principal_id.as_bytes());
        output.extend_from_slice(self.organization_id.as_bytes());
        output.extend_from_slice(self.membership_id.as_bytes());
        output.extend_from_slice(self.authenticator_id.as_bytes());
        encode_bytes(&mut output, self.capability_id.as_str().as_bytes());
        output.extend_from_slice(&self.capability_version.to_be_bytes());
        output.push(outcome_code(self.outcome));
        output.extend_from_slice(&(self.reason_codes.len() as u32).to_be_bytes());
        for reason in &self.reason_codes {
            encode_bytes(&mut output, reason.as_str().as_bytes());
        }
        for digest in [
            self.authority_context_hash,
            self.request_semantic_hash,
            self.cal_semantic_hash,
            self.evaluation_snapshot_hash,
        ] {
            output.extend_from_slice(digest.as_bytes());
        }
        match self.effective_capability_hash {
            Some(digest) => {
                output.push(1);
                output.extend_from_slice(digest.as_bytes());
            }
            None => output.push(0),
        }
        for digest in [
            self.policy_bundle_hash,
            self.evidence_bundle_hash,
            self.dependency_bundle_hash,
            self.spec_sha256,
        ] {
            output.extend_from_slice(digest.as_bytes());
        }
        for value in [
            self.principal_global_sequence,
            self.organization_decision_sequence,
            self.principal_global_revocation_epoch,
            self.organization_revocation_epoch,
        ] {
            output.extend_from_slice(&value.to_be_bytes());
        }
        self.live_generations.encode(&mut output);
        output.extend_from_slice(&self.issued_at_epoch_ms.to_be_bytes());
        output.extend_from_slice(&self.valid_until_epoch_ms.to_be_bytes());
        output
    }
}

fn encode_bytes(output: &mut Vec<u8>, value: &[u8]) {
    output.extend_from_slice(&(value.len() as u32).to_be_bytes());
    output.extend_from_slice(value);
}

const fn outcome_code(outcome: DecisionOutcome) -> u8 {
    match outcome {
        DecisionOutcome::Deny => 1,
        DecisionOutcome::RequireApproval => 2,
        DecisionOutcome::Allow => 3,
        DecisionOutcome::Error => 4,
        DecisionOutcome::Unknown => 5,
        DecisionOutcome::Unsupported => 6,
    }
}

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum ReceiptError {
    #[error("finalization state does not bind the evaluated principal/context")]
    FinalizationBindingMismatch,
    #[error("finalization generations differ from the evaluated snapshot")]
    StaleFinalizationState,
    #[error("finalization sequence or generation state is invalid")]
    InvalidSequenceState,
    #[error("receipt validity window is invalid")]
    InvalidValidityWindow,
    #[error("ALLOW receipt requires an exact effective capability hash")]
    MissingEffectiveCapabilityHash,
    #[error("non-ALLOW receipt cannot claim an effective capability hash")]
    UnexpectedEffectiveCapabilityHash,
    #[error("receipt canonical bytes or hash do not verify")]
    ReceiptHashMismatch,
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;

    use anar_core_types::{
        ApprovalRequirement, AuthorityEnvelope, AuthorityStatus, DelegationBound, EffectScope,
        EvidenceRequirementSet, OfflineRestriction, ResourceScope, RiskTier, TimeWindow,
        UsageBound,
    };

    use crate::{
        AuthorityContextSnapshot, BindingSnapshot, CoreAuthorityState, EvaluationInput, evaluate,
    };

    use super::*;

    fn id(last: u8) -> StableId {
        let mut bytes = [0_u8; 16];
        bytes[15] = last;
        StableId::from_bytes(bytes)
    }

    fn candidate() -> CandidateDecision {
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
        let registered = |value| RegisteredId::new(value).unwrap();
        let envelope = AuthorityEnvelope {
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
        };
        evaluate(EvaluationInput {
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
                authenticator_valid_from_epoch_ms: 100,
                authenticator_valid_until_epoch_ms: Some(300),
                live_generations: generations,
            },
            binding: BindingSnapshot {
                organization_id: id(4),
                capability_id: registered("recoveries.notice.send"),
                capability_version: 1,
                policy_hash: SemanticDigest::ZERO,
                envelope: envelope.clone(),
            },
            requested_envelope: envelope,
            dependencies: Vec::new(),
            evaluated_at_epoch_ms: 200,
        })
    }

    fn finalization(candidate: &CandidateDecision) -> FinalizationState {
        FinalizationState {
            principal_id: candidate.principal_id,
            organization_id: candidate.organization_id,
            membership_id: candidate.membership_id,
            authenticator_id: candidate.authenticator_id,
            principal_global_sequence: 10,
            organization_decision_sequence: 20,
            principal_global_revocation_epoch: 1,
            organization_revocation_epoch: 1,
            live_generations: candidate.evaluated_generations.clone(),
        }
    }

    fn material() -> ReceiptMaterial {
        ReceiptMaterial {
            receipt_id: id(20),
            decision_id: id(21),
            authority_context_hash: SemanticDigest::ZERO,
            cal_semantic_hash: SemanticDigest::ZERO,
            evidence_bundle_hash: SemanticDigest::ZERO,
            effective_capability_hash: Some(SemanticDigest::ZERO),
            spec_sha256: SemanticDigest::ZERO,
            issued_at_epoch_ms: 200,
            valid_until_epoch_ms: 250,
        }
    }

    #[test]
    fn receipt_is_byte_identical_for_identical_final_state() {
        let candidate = candidate();
        let first =
            DecisionReceipt::issue(&candidate, &finalization(&candidate), material()).unwrap();
        let second =
            DecisionReceipt::issue(&candidate, &finalization(&candidate), material()).unwrap();
        assert_eq!(first.canonical_bytes, second.canonical_bytes);
        assert_eq!(first.receipt_hash, second.receipt_hash);
        first.verify().unwrap();
    }

    #[test]
    fn sequence_assignment_changes_receipt() {
        let candidate = candidate();
        let first =
            DecisionReceipt::issue(&candidate, &finalization(&candidate), material()).unwrap();
        let mut changed = finalization(&candidate);
        changed.organization_decision_sequence += 1;
        let second = DecisionReceipt::issue(&candidate, &changed, material()).unwrap();
        assert_ne!(first.receipt_hash, second.receipt_hash);
    }

    #[test]
    fn wrong_membership_or_stale_generation_fails_closed() {
        let candidate = candidate();
        let mut wrong = finalization(&candidate);
        wrong.membership_id = id(99);
        assert_eq!(
            DecisionReceipt::issue(&candidate, &wrong, material()),
            Err(ReceiptError::FinalizationBindingMismatch)
        );

        let mut stale = finalization(&candidate);
        stale.live_generations.policy_generation += 1;
        assert_eq!(
            DecisionReceipt::issue(&candidate, &stale, material()),
            Err(ReceiptError::StaleFinalizationState)
        );
    }
}
