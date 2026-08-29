use std::collections::BTreeMap;
use std::sync::Mutex;

use anar_core_engine::{CandidateDecision, DecisionReceipt, FinalizationState, ReceiptMaterial};
use anar_core_types::{
    AuthorityDependencyRef, AuthorityDependencyType, AuthorityStatus, DecisionOutcome,
    RegisteredId, SemanticDigest, StableId,
};
use thiserror::Error;

pub const MAX_SEQUENCE: i64 = 9_223_372_036_854_775_806;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CurrentDependencyState {
    pub generation: Option<i64>,
    pub digest: Option<SemanticDigest>,
    pub status: Option<AuthorityStatus>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RuntimeState {
    pub principal_id: StableId,
    pub organization_id: StableId,
    pub membership_id: StableId,
    pub authenticator_id: StableId,
    pub principal_global_sequence: i64,
    pub organization_decision_sequence: i64,
    pub principal_global_revocation_epoch: i64,
    pub organization_revocation_epoch: i64,
    pub live_generations: anar_core_engine::GenerationVector,
    pub membership_status: AuthorityStatus,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InternalMutationGrant {
    pub mutation_grant_id: StableId,
    pub decision_receipt_id: StableId,
    pub actor_principal_id: StableId,
    pub organization_id: StableId,
    pub capability_id: RegisteredId,
    pub target_type: RegisteredId,
    pub target_ref: StableId,
    pub target_digest: SemanticDigest,
    pub purpose_code: RegisteredId,
    pub effect_scope_hash: SemanticDigest,
    pub issued_at_epoch_ms: i64,
    pub expires_at_epoch_ms: i64,
    pub consumed_at_epoch_ms: Option<i64>,
    pub revoked_at_epoch_ms: Option<i64>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MutationEvent {
    pub event_id: StableId,
    pub mutation_grant_id: StableId,
    pub decision_receipt_id: StableId,
    pub actor_principal_id: StableId,
    pub target_type: RegisteredId,
    pub target_ref: StableId,
    pub capability_id: RegisteredId,
    pub purpose_code: RegisteredId,
    pub pre_generation: i64,
    pub post_generation: i64,
    pub pre_revocation_epoch: i64,
    pub post_revocation_epoch: i64,
    pub recorded_at_epoch_ms: i64,
}

type DependencyKey = (AuthorityDependencyType, Option<StableId>, StableId);

struct RuntimeInner {
    state: RuntimeState,
    dependencies: BTreeMap<DependencyKey, CurrentDependencyState>,
    receipts_by_id: BTreeMap<StableId, DecisionReceipt>,
    grants: BTreeMap<StableId, InternalMutationGrant>,
    mutation_events: Vec<MutationEvent>,
}

pub struct AuthorityRuntime {
    inner: Mutex<RuntimeInner>,
}

impl AuthorityRuntime {
    pub fn new(state: RuntimeState) -> Result<Self, RuntimeError> {
        if !state.live_generations.is_non_negative()
            || [
                state.principal_global_sequence,
                state.organization_decision_sequence,
                state.principal_global_revocation_epoch,
                state.organization_revocation_epoch,
            ]
            .into_iter()
            .any(|value| !(0..=MAX_SEQUENCE).contains(&value))
        {
            return Err(RuntimeError::InvalidInitialState);
        }
        Ok(Self {
            inner: Mutex::new(RuntimeInner {
                state,
                dependencies: BTreeMap::new(),
                receipts_by_id: BTreeMap::new(),
                grants: BTreeMap::new(),
                mutation_events: Vec::new(),
            }),
        })
    }

    pub fn set_dependency_state(
        &self,
        dependency: &AuthorityDependencyRef,
        state: CurrentDependencyState,
    ) -> Result<(), RuntimeError> {
        let mut inner = self.lock()?;
        inner.dependencies.insert(dependency_key(dependency), state);
        Ok(())
    }

    pub fn finalize(
        &self,
        candidate: &CandidateDecision,
        material: ReceiptMaterial,
    ) -> Result<DecisionReceipt, RuntimeError> {
        let mut inner = self.lock()?;
        if let Some(existing) = inner.receipts_by_id.get(&material.receipt_id) {
            if receipt_matches_retry(existing, candidate, &material) {
                return Ok(existing.clone());
            }
            return Err(RuntimeError::IdempotencyConflict);
        }
        require_core_state(&inner.state, candidate)?;
        for dependency in candidate.dependency_bundle.dependencies() {
            let current = inner
                .dependencies
                .get(&dependency_key(dependency))
                .ok_or(RuntimeError::DependencyUnavailable)?;
            verify_dependency(dependency, current)?;
        }
        inner.state.principal_global_sequence =
            checked_next(inner.state.principal_global_sequence)?;
        inner.state.organization_decision_sequence =
            checked_next(inner.state.organization_decision_sequence)?;
        let finalization = FinalizationState {
            principal_id: inner.state.principal_id,
            organization_id: inner.state.organization_id,
            membership_id: inner.state.membership_id,
            authenticator_id: inner.state.authenticator_id,
            principal_global_sequence: inner.state.principal_global_sequence,
            organization_decision_sequence: inner.state.organization_decision_sequence,
            principal_global_revocation_epoch: inner.state.principal_global_revocation_epoch,
            organization_revocation_epoch: inner.state.organization_revocation_epoch,
            live_generations: inner.state.live_generations.clone(),
        };
        let receipt = DecisionReceipt::issue(candidate, &finalization, material)
            .map_err(RuntimeError::Receipt)?;
        receipt.verify().map_err(RuntimeError::Receipt)?;
        inner
            .receipts_by_id
            .insert(receipt.receipt_id, receipt.clone());
        Ok(receipt)
    }

    pub fn install_mutation_grant(&self, grant: InternalMutationGrant) -> Result<(), RuntimeError> {
        if grant.expires_at_epoch_ms <= grant.issued_at_epoch_ms {
            return Err(RuntimeError::InvalidGrant);
        }
        let mut inner = self.lock()?;
        if inner
            .grants
            .insert(grant.mutation_grant_id, grant)
            .is_some()
        {
            return Err(RuntimeError::IdempotencyConflict);
        }
        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
    pub fn execute_membership_revocation(
        &self,
        mutation_grant_id: StableId,
        event_id: StableId,
        actor_principal_id: StableId,
        organization_id: StableId,
        target_membership_id: StableId,
        target_digest: SemanticDigest,
        purpose_code: &RegisteredId,
        effect_scope_hash: SemanticDigest,
        now_epoch_ms: i64,
    ) -> Result<MutationEvent, RuntimeError> {
        let mut inner = self.lock()?;

        // The in-memory proof model holds one mutex. The PostgreSQL path uses the
        // spec-mandated two-phase discovery and class-first lock order.
        let grant = inner
            .grants
            .get(&mutation_grant_id)
            .ok_or(RuntimeError::GrantUnavailable)?
            .clone();
        validate_grant(
            &grant,
            actor_principal_id,
            organization_id,
            target_membership_id,
            target_digest,
            purpose_code,
            effect_scope_hash,
            now_epoch_ms,
        )?;
        let receipt = inner
            .receipts_by_id
            .get(&grant.decision_receipt_id)
            .ok_or(RuntimeError::DecisionReceiptUnavailable)?;
        if receipt.principal_id != actor_principal_id
            || receipt.organization_id != organization_id
            || receipt.capability_id != grant.capability_id
            || receipt.outcome != DecisionOutcome::Allow
            || receipt.valid_until_epoch_ms <= now_epoch_ms
            || receipt.live_generations != inner.state.live_generations
        {
            return Err(RuntimeError::EffectTimeAuthorityStale);
        }
        if inner.state.membership_id != target_membership_id
            || inner.state.organization_id != organization_id
            || inner.state.membership_status != AuthorityStatus::Active
        {
            return Err(RuntimeError::MutationTargetMismatch);
        }

        let pre_generation = inner.state.live_generations.membership_generation;
        let pre_epoch = inner.state.organization_revocation_epoch;
        let post_generation = checked_next(pre_generation)?;
        let post_epoch = checked_next(pre_epoch)?;

        inner.state.live_generations.membership_generation = post_generation;
        inner.state.live_generations.organization_revocation_epoch = post_epoch;
        inner.state.organization_revocation_epoch = post_epoch;
        inner.state.membership_status = AuthorityStatus::Revoked;

        let stored_grant = inner
            .grants
            .get_mut(&mutation_grant_id)
            .ok_or(RuntimeError::GrantUnavailable)?;
        if stored_grant.consumed_at_epoch_ms.is_some()
            || stored_grant.revoked_at_epoch_ms.is_some()
            || stored_grant.expires_at_epoch_ms <= now_epoch_ms
        {
            return Err(RuntimeError::GrantUnavailable);
        }
        stored_grant.consumed_at_epoch_ms = Some(now_epoch_ms);

        let event = MutationEvent {
            event_id,
            mutation_grant_id,
            decision_receipt_id: grant.decision_receipt_id,
            actor_principal_id,
            target_type: grant.target_type,
            target_ref: target_membership_id,
            capability_id: grant.capability_id,
            purpose_code: purpose_code.clone(),
            pre_generation,
            post_generation,
            pre_revocation_epoch: pre_epoch,
            post_revocation_epoch: post_epoch,
            recorded_at_epoch_ms: now_epoch_ms,
        };
        inner.mutation_events.push(event.clone());
        Ok(event)
    }

    pub fn snapshot(&self) -> Result<RuntimeState, RuntimeError> {
        Ok(self.lock()?.state.clone())
    }

    pub fn mutation_events(&self) -> Result<Vec<MutationEvent>, RuntimeError> {
        Ok(self.lock()?.mutation_events.clone())
    }

    fn lock(&self) -> Result<std::sync::MutexGuard<'_, RuntimeInner>, RuntimeError> {
        self.inner.lock().map_err(|_| RuntimeError::LockPoisoned)
    }
}

fn dependency_key(dependency: &AuthorityDependencyRef) -> DependencyKey {
    (
        dependency.dependency_type,
        dependency.organization_id,
        dependency.dependency_id,
    )
}

fn verify_dependency(
    expected: &AuthorityDependencyRef,
    current: &CurrentDependencyState,
) -> Result<(), RuntimeError> {
    if expected.expected_generation != current.generation
        || expected.expected_digest != current.digest
        || expected.expected_status != current.status
    {
        return Err(RuntimeError::DependencyStale);
    }
    Ok(())
}

fn require_core_state(
    current: &RuntimeState,
    candidate: &CandidateDecision,
) -> Result<(), RuntimeError> {
    if current.principal_id != candidate.principal_id
        || current.organization_id != candidate.organization_id
        || current.membership_id != candidate.membership_id
        || current.authenticator_id != candidate.authenticator_id
    {
        return Err(RuntimeError::CoreBindingMismatch);
    }
    if current.live_generations != candidate.evaluated_generations
        || current.membership_status != AuthorityStatus::Active
    {
        return Err(RuntimeError::StaleAuthorityRetryRequired);
    }
    Ok(())
}

fn receipt_matches_retry(
    existing: &DecisionReceipt,
    candidate: &CandidateDecision,
    material: &ReceiptMaterial,
) -> bool {
    existing.request_id == candidate.request_id
        && existing.request_semantic_hash == candidate.request_semantic_hash
        && existing.evaluation_snapshot_hash == candidate.evaluation_snapshot_hash
        && existing.policy_bundle_hash == candidate.policy_bundle_hash
        && existing.dependency_bundle_hash == candidate.dependency_bundle.digest()
        && existing.receipt_id == material.receipt_id
        && existing.decision_id == material.decision_id
        && existing.authority_context_hash == material.authority_context_hash
        && existing.cal_semantic_hash == material.cal_semantic_hash
        && existing.evidence_bundle_hash == material.evidence_bundle_hash
        && existing.effective_capability_hash == material.effective_capability_hash
        && existing.spec_sha256 == material.spec_sha256
        && existing.issued_at_epoch_ms == material.issued_at_epoch_ms
        && existing.valid_until_epoch_ms == material.valid_until_epoch_ms
}

fn checked_next(value: i64) -> Result<i64, RuntimeError> {
    if value >= MAX_SEQUENCE {
        return Err(RuntimeError::SequenceExhausted);
    }
    value.checked_add(1).ok_or(RuntimeError::SequenceExhausted)
}

#[allow(clippy::too_many_arguments)]
fn validate_grant(
    grant: &InternalMutationGrant,
    actor_principal_id: StableId,
    organization_id: StableId,
    target_membership_id: StableId,
    target_digest: SemanticDigest,
    purpose_code: &RegisteredId,
    effect_scope_hash: SemanticDigest,
    now_epoch_ms: i64,
) -> Result<(), RuntimeError> {
    if grant.actor_principal_id != actor_principal_id
        || grant.organization_id != organization_id
        || grant.target_ref != target_membership_id
        || grant.target_digest != target_digest
        || &grant.purpose_code != purpose_code
        || grant.effect_scope_hash != effect_scope_hash
        || grant.target_type.as_str() != "membership"
        || grant.capability_id.as_str() != "identity.membership.revoke"
    {
        return Err(RuntimeError::MutationTargetMismatch);
    }
    if grant.consumed_at_epoch_ms.is_some()
        || grant.revoked_at_epoch_ms.is_some()
        || grant.expires_at_epoch_ms <= now_epoch_ms
        || grant.issued_at_epoch_ms > now_epoch_ms
    {
        return Err(RuntimeError::GrantUnavailable);
    }
    Ok(())
}

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum RuntimeError {
    #[error("runtime state is invalid")]
    InvalidInitialState,
    #[error("runtime lock was poisoned")]
    LockPoisoned,
    #[error("sequence domain is exhausted")]
    SequenceExhausted,
    #[error("candidate core identifiers do not match current authority")]
    CoreBindingMismatch,
    #[error("authority changed after evaluation; retry required")]
    StaleAuthorityRetryRequired,
    #[error("an evaluated dependency is unavailable")]
    DependencyUnavailable,
    #[error("an evaluated dependency changed after evaluation")]
    DependencyStale,
    #[error("receipt finalization failed: {0}")]
    Receipt(anar_core_engine::ReceiptError),
    #[error("idempotency key was reused with different semantic input")]
    IdempotencyConflict,
    #[error("internal mutation grant is invalid")]
    InvalidGrant,
    #[error("internal mutation grant is unavailable")]
    GrantUnavailable,
    #[error("the decision receipt required for mutation is unavailable")]
    DecisionReceiptUnavailable,
    #[error("effect-time administrative authority is stale or mismatched")]
    EffectTimeAuthorityStale,
    #[error("mutation target, purpose, actor, or effect scope does not match the grant")]
    MutationTargetMismatch,
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;
    use std::sync::Arc;

    use anar_core_engine::{
        AuthorityContextSnapshot, BindingSnapshot, CoreAuthorityState, EvaluationInput,
        GenerationVector, ReceiptMaterial, evaluate,
    };
    use anar_core_types::{
        ApprovalRequirement, AuthorityDependencyType, AuthorityEnvelope, DelegationBound,
        DependencyBundle, EffectScope, EvidenceRequirementSet, OfflineRestriction, ResourceScope,
        RiskTier, TimeWindow, UsageBound,
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

    fn generations() -> GenerationVector {
        GenerationVector {
            principal_generation: 1,
            membership_generation: 1,
            organization_generation: 1,
            policy_generation: 1,
            entitlement_generation: 1,
            credential_revision: 1,
            principal_global_revocation_epoch: 1,
            organization_revocation_epoch: 1,
        }
    }

    fn envelope() -> AuthorityEnvelope {
        AuthorityEnvelope {
            outcome: DecisionOutcome::Allow,
            resource_scope: ResourceScope::ExplicitSet {
                resources: BTreeSet::from([registered("membership:target")]),
            },
            effect_scope: EffectScope {
                classes: BTreeSet::from([registered("authority.revocation")]),
            },
            time_window: TimeWindow {
                starts_at_epoch_ms: Some(100),
                ends_at_epoch_ms: Some(500),
            },
            usage_bound: UsageBound(Some(1)),
            delegation_bound: DelegationBound {
                allowed: false,
                max_depth: 0,
            },
            financial_bound: None,
            approval_requirement: ApprovalRequirement::OneAuthorizedApprover,
            evidence_requirements: EvidenceRequirementSet {
                required_classes: BTreeSet::new(),
            },
            risk_tier_ceiling: RiskTier::Critical,
            offline_restriction: OfflineRestriction {
                offline_read_allowed: false,
                deferred_effect_allowed: false,
            },
        }
    }

    fn candidate(capability: &str, dependencies: Vec<AuthorityDependencyRef>) -> CandidateDecision {
        let vector = generations();
        evaluate(EvaluationInput {
            request_id: id(10),
            request_semantic_hash: SemanticDigest::ZERO,
            authority_context: AuthorityContextSnapshot {
                authority_context_id: id(11),
                principal_id: id(1),
                organization_id: id(2),
                membership_id: id(3),
                authenticator_id: id(4),
                status: AuthorityStatus::Active,
                issued_at_epoch_ms: 100,
                expires_at_epoch_ms: 500,
                revoked_at_epoch_ms: None,
                bound_generations: vector.clone(),
            },
            current_state: CoreAuthorityState {
                principal_status: AuthorityStatus::Active,
                organization_status: AuthorityStatus::Active,
                membership_status: AuthorityStatus::Active,
                authenticator_status: AuthorityStatus::Active,
                authenticator_valid_from_epoch_ms: 100,
                authenticator_valid_until_epoch_ms: Some(500),
                live_generations: vector,
            },
            binding: BindingSnapshot {
                organization_id: id(2),
                capability_id: registered(capability),
                capability_version: 1,
                policy_hash: SemanticDigest::ZERO,
                envelope: envelope(),
            },
            requested_envelope: envelope(),
            dependencies,
            evaluated_at_epoch_ms: 200,
        })
    }

    fn runtime(sequence: i64) -> AuthorityRuntime {
        AuthorityRuntime::new(RuntimeState {
            principal_id: id(1),
            organization_id: id(2),
            membership_id: id(3),
            authenticator_id: id(4),
            principal_global_sequence: sequence,
            organization_decision_sequence: sequence,
            principal_global_revocation_epoch: 1,
            organization_revocation_epoch: 1,
            live_generations: generations(),
            membership_status: AuthorityStatus::Active,
        })
        .unwrap()
    }

    fn material(receipt_id: u8, decision_id: u8) -> ReceiptMaterial {
        ReceiptMaterial {
            receipt_id: id(receipt_id),
            decision_id: id(decision_id),
            authority_context_hash: SemanticDigest::ZERO,
            cal_semantic_hash: SemanticDigest::ZERO,
            evidence_bundle_hash: SemanticDigest::ZERO,
            effective_capability_hash: Some(SemanticDigest::ZERO),
            spec_sha256: SemanticDigest::ZERO,
            issued_at_epoch_ms: 200,
            valid_until_epoch_ms: 400,
        }
    }

    #[test]
    fn exact_retry_returns_identical_receipt_without_advancing_again() {
        let runtime = runtime(0);
        let candidate = candidate("recoveries.notice.send", Vec::new());
        let first = runtime.finalize(&candidate, material(20, 21)).unwrap();
        let second = runtime.finalize(&candidate, material(20, 21)).unwrap();
        assert_eq!(first, second);
        assert_eq!(
            runtime.snapshot().unwrap().organization_decision_sequence,
            1
        );
        assert_eq!(
            runtime.finalize(&candidate, material(20, 22)),
            Err(RuntimeError::IdempotencyConflict)
        );
    }

    #[test]
    fn every_dependency_is_revalidated_before_sequence_assignment() {
        let dependency = AuthorityDependencyRef {
            dependency_type: AuthorityDependencyType::Delegation,
            dependency_id: id(30),
            organization_id: Some(id(2)),
            expected_generation: Some(1),
            expected_digest: Some(SemanticDigest::ZERO),
            expected_status: Some(AuthorityStatus::Active),
        };
        let runtime = runtime(0);
        runtime
            .set_dependency_state(
                &dependency,
                CurrentDependencyState {
                    generation: Some(2),
                    digest: Some(SemanticDigest::ZERO),
                    status: Some(AuthorityStatus::Active),
                },
            )
            .unwrap();
        let candidate = candidate("recoveries.notice.send", vec![dependency]);
        assert_eq!(
            runtime.finalize(&candidate, material(20, 21)),
            Err(RuntimeError::DependencyStale)
        );
        assert_eq!(
            runtime.snapshot().unwrap().organization_decision_sequence,
            0
        );
    }

    #[test]
    fn sequence_exhaustion_fails_closed() {
        let runtime = runtime(MAX_SEQUENCE);
        let candidate = candidate("recoveries.notice.send", Vec::new());
        assert_eq!(
            runtime.finalize(&candidate, material(20, 21)),
            Err(RuntimeError::SequenceExhausted)
        );
    }

    #[test]
    fn one_shot_mutation_has_one_concurrent_winner_and_appends_event() {
        let runtime = Arc::new(runtime(0));
        let admin = candidate("identity.membership.revoke", Vec::new());
        let receipt = runtime.finalize(&admin, material(20, 21)).unwrap();
        let purpose = registered("administrative.revocation");
        let effect_scope_hash = SemanticDigest::ZERO;
        runtime
            .install_mutation_grant(InternalMutationGrant {
                mutation_grant_id: id(40),
                decision_receipt_id: receipt.receipt_id,
                actor_principal_id: id(1),
                organization_id: id(2),
                capability_id: registered("identity.membership.revoke"),
                target_type: registered("membership"),
                target_ref: id(3),
                target_digest: SemanticDigest::ZERO,
                purpose_code: purpose.clone(),
                effect_scope_hash,
                issued_at_epoch_ms: 200,
                expires_at_epoch_ms: 300,
                consumed_at_epoch_ms: None,
                revoked_at_epoch_ms: None,
            })
            .unwrap();

        let mut workers = Vec::new();
        for event in [41_u8, 42_u8] {
            let runtime = Arc::clone(&runtime);
            let purpose = purpose.clone();
            workers.push(std::thread::spawn(move || {
                runtime.execute_membership_revocation(
                    id(40),
                    id(event),
                    id(1),
                    id(2),
                    id(3),
                    SemanticDigest::ZERO,
                    &purpose,
                    effect_scope_hash,
                    250,
                )
            }));
        }
        let results: Vec<_> = workers
            .into_iter()
            .map(|worker| worker.join().unwrap())
            .collect();
        assert_eq!(results.iter().filter(|result| result.is_ok()).count(), 1);
        assert_eq!(runtime.mutation_events().unwrap().len(), 1);
        let state = runtime.snapshot().unwrap();
        assert_eq!(state.membership_status, AuthorityStatus::Revoked);
        assert_eq!(state.live_generations.membership_generation, 2);
        assert_eq!(state.organization_revocation_epoch, 2);
    }

    #[test]
    fn dependency_bundle_type_is_not_a_runtime_authority_source() {
        let empty = DependencyBundle::canonicalize([]).unwrap();
        assert!(empty.dependencies().is_empty());
    }
}
