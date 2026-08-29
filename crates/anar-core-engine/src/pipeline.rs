use std::collections::BTreeSet;

use anar_core_types::{
    AuthorityDependencyRef, AuthorityDependencyType, AuthorityStatus, DependencyBundle,
    EntitlementBindingSnapshot, ExternalRevocationFactSnapshot, ExternalStateAssertionSnapshot,
    ExternalTrustFactSnapshot, MembershipClass, PrincipalKind, RegisteredId, StableId,
};

use crate::{
    CandidateDecision, CompiledPolicy, EvaluationInput, EvidenceIssuerAllowlist,
    EvidenceRequirement, PolicyFacts, ReasonCode, TrustQuery, evaluate,
    resolve_trust_and_revocation, verify_required_evidence,
};

pub struct AuthorityPipelineInput<'a> {
    pub evaluation: EvaluationInput,
    pub principal_kind: PrincipalKind,
    pub membership_class: MembershipClass,
    pub purpose: RegisteredId,
    pub policy: &'a CompiledPolicy,
    pub required_entitlements: BTreeSet<RegisteredId>,
    pub entitlement_bindings: &'a [EntitlementBindingSnapshot],
    pub evidence_requirements: &'a [EvidenceRequirement],
    pub assertions: &'a [ExternalStateAssertionSnapshot],
    pub evidence_issuer_allowlist: &'a EvidenceIssuerAllowlist,
    pub trust_query: &'a TrustQuery,
    pub trust_facts: &'a [ExternalTrustFactSnapshot],
    pub revocations: &'a [ExternalRevocationFactSnapshot],
    pub revocation_snapshot_complete: bool,
    pub revocation_watermark_dependency_id: StableId,
}

pub fn evaluate_authority_pipeline(mut input: AuthorityPipelineInput<'_>) -> CandidateDecision {
    if input.evaluation.binding.policy_hash != input.policy.semantic_hash() {
        return deny_pipeline(&input.evaluation, ReasonCode::PolicyDigestMismatch);
    }
    if !input.revocation_snapshot_complete {
        return deny_pipeline(&input.evaluation, ReasonCode::TrustOrRevocationDenied);
    }

    let context = &input.evaluation.authority_context;
    let evaluated_at = input.evaluation.evaluated_at_epoch_ms;
    let mut active_entitlements = BTreeSet::new();
    for entitlement_ref in &input.required_entitlements {
        let binding = input
            .entitlement_bindings
            .iter()
            .filter(|binding| {
                binding.entitlement_ref == *entitlement_ref
                    && binding.is_current_for(
                        context.organization_id,
                        context.principal_id,
                        context.membership_id,
                        evaluated_at,
                    )
            })
            .min_by_key(|binding| binding.entitlement_binding_id);
        let Some(binding) = binding else {
            return deny_pipeline(&input.evaluation, ReasonCode::InsufficientEntitlement);
        };
        active_entitlements.insert(entitlement_ref.clone());
        input.evaluation.dependencies.push(AuthorityDependencyRef {
            dependency_type: AuthorityDependencyType::EntitlementBinding,
            dependency_id: binding.entitlement_binding_id,
            organization_id: Some(binding.organization_id),
            expected_generation: Some(binding.generation),
            expected_digest: Some(binding.source_digest),
            expected_status: Some(AuthorityStatus::Active),
        });
    }

    let evidence = match verify_required_evidence(
        context.organization_id,
        input.evidence_requirements,
        input.assertions,
        input.evidence_issuer_allowlist,
        evaluated_at,
    ) {
        Ok(value) => value,
        Err(_) => return deny_pipeline(&input.evaluation, ReasonCode::InsufficientEvidence),
    };
    for assertion_id in &evidence.assertion_ids {
        let Some(assertion) = input
            .assertions
            .iter()
            .find(|assertion| assertion.assertion_id == *assertion_id)
        else {
            return deny_pipeline(&input.evaluation, ReasonCode::InsufficientEvidence);
        };
        input.evaluation.dependencies.push(AuthorityDependencyRef {
            dependency_type: AuthorityDependencyType::ExternalStateAssertion,
            dependency_id: assertion.assertion_id,
            organization_id: Some(assertion.organization_id),
            expected_generation: None,
            expected_digest: Some(assertion.payload_digest),
            expected_status: Some(AuthorityStatus::Active),
        });
    }

    let trust =
        match resolve_trust_and_revocation(input.trust_query, input.trust_facts, input.revocations)
        {
            Ok(value) => value,
            Err(_) => return deny_pipeline(&input.evaluation, ReasonCode::TrustOrRevocationDenied),
        };
    for fact_id in &trust.fact_ids {
        let Some(fact) = input
            .trust_facts
            .iter()
            .find(|fact| fact.fact_id == *fact_id)
        else {
            return deny_pipeline(&input.evaluation, ReasonCode::TrustOrRevocationDenied);
        };
        input.evaluation.dependencies.push(AuthorityDependencyRef {
            dependency_type: AuthorityDependencyType::ExternalTrustFact,
            dependency_id: fact.fact_id,
            organization_id: fact.organization_id,
            expected_generation: None,
            expected_digest: Some(fact.source_digest),
            expected_status: Some(AuthorityStatus::Active),
        });
    }
    input.evaluation.dependencies.push(AuthorityDependencyRef {
        dependency_type: AuthorityDependencyType::ExternalRevocationWatermark,
        dependency_id: input.revocation_watermark_dependency_id,
        organization_id: Some(context.organization_id),
        expected_generation: None,
        expected_digest: Some(trust.revocation_watermark),
        expected_status: Some(AuthorityStatus::Active),
    });

    let policy = input.policy.evaluate(&PolicyFacts {
        principal_kind: input.principal_kind,
        membership_class: input.membership_class,
        purpose: input.purpose,
        active_entitlements,
        verified_evidence_types: evidence.assertion_types,
        current_trust_facts: trust.facts,
        effective_revocation_targets: BTreeSet::new(),
        revocation_snapshot_complete: true,
        evaluated_at_epoch_ms: evaluated_at,
    });
    input.evaluation.binding.envelope.outcome = policy.outcome;
    evaluate(input.evaluation)
}

fn deny_pipeline(input: &EvaluationInput, reason: ReasonCode) -> CandidateDecision {
    let dependency_bundle = match DependencyBundle::canonicalize(input.dependencies.clone()) {
        Ok(bundle) => bundle,
        Err(_) => DependencyBundle::canonicalize([]).expect("empty dependency bundle is valid"),
    };
    crate::evaluation::denied(input, reason, dependency_bundle)
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;

    use anar_core_types::{
        ApprovalRequirement, AuthorityEnvelope, BindingStatus, DecisionOutcome, DelegationBound,
        EffectScope, EvidenceRequirementSet, FinancialBound, FinancialBoundKind,
        OfflineRestriction, ResourceScope, RiskTier, SemanticDigest, TimeWindow, UsageBound,
        ValidityWindow,
    };

    use crate::{
        AuthorityContextSnapshot, BindingSnapshot, CoreAuthorityState, GenerationVector,
        PolicyEffect, PolicyPredicate, PolicyProgram, PolicyRule,
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

    fn envelope() -> AuthorityEnvelope {
        AuthorityEnvelope {
            outcome: DecisionOutcome::Deny,
            resource_scope: ResourceScope::ExplicitSet {
                resources: BTreeSet::from([rid("opportunity:falcon.delta1")]),
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
            financial_bound: Some(FinancialBound {
                asset_id: rid("iso4217.usd"),
                registry_version: 1,
                kind: FinancialBoundKind::MaximumCredit,
                minor_units: 10_000,
            }),
            approval_requirement: ApprovalRequirement::OneAuthorizedApprover,
            evidence_requirements: EvidenceRequirementSet {
                required_classes: BTreeSet::from([rid("opportunity.approved")]),
            },
            risk_tier_ceiling: RiskTier::High,
            offline_restriction: OfflineRestriction {
                offline_read_allowed: false,
                deferred_effect_allowed: true,
            },
        }
    }

    fn evaluation(policy_hash: SemanticDigest) -> EvaluationInput {
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
        EvaluationInput {
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
                live_generations: generations,
            },
            binding: BindingSnapshot {
                organization_id: id(4),
                capability_id: rid("recoveries.notice.send"),
                capability_version: 1,
                policy_hash,
                envelope: envelope(),
            },
            requested_envelope: {
                let mut value = envelope();
                value.outcome = DecisionOutcome::Allow;
                value
            },
            dependencies: Vec::new(),
            evaluated_at_epoch_ms: 150,
        }
    }

    fn policy() -> CompiledPolicy {
        CompiledPolicy::compile(PolicyProgram {
            policy_id: rid("recoveries.falcon.notice"),
            version: 1,
            rules: vec![PolicyRule {
                rule_id: rid("allow.approved.entitled"),
                predicate: PolicyPredicate::All {
                    predicates: vec![
                        PolicyPredicate::HasEntitlement {
                            entitlement_ref: rid("recoveries.active"),
                        },
                        PolicyPredicate::HasEvidence {
                            assertion_type: rid("opportunity.approved"),
                        },
                        PolicyPredicate::NoEffectiveRevocation {
                            target_ref: rid("opportunity.falcon.delta1"),
                        },
                    ],
                },
                effect: PolicyEffect::Allow,
            }],
            default_effect: PolicyEffect::Deny,
        })
        .unwrap()
    }

    fn entitlement() -> EntitlementBindingSnapshot {
        EntitlementBindingSnapshot {
            entitlement_binding_id: id(10),
            organization_id: id(4),
            membership_id: Some(id(5)),
            principal_id: Some(id(3)),
            package_ref: rid("package.recoveries"),
            entitlement_ref: rid("recoveries.active"),
            source_system: rid("marketplace"),
            source_digest: SemanticDigest::from_bytes([10; 32]),
            status: BindingStatus::Active,
            validity: ValidityWindow {
                valid_from_epoch_ms: 100,
                valid_until_epoch_ms: Some(300),
            },
            generation: 1,
        }
    }

    fn assertion(issuer: &str) -> ExternalStateAssertionSnapshot {
        ExternalStateAssertionSnapshot {
            assertion_id: id(11),
            organization_id: id(4),
            assertion_type: rid("opportunity.approved"),
            object_ref: rid("opportunity.falcon.delta1"),
            object_digest: SemanticDigest::from_bytes([11; 32]),
            issuer_principal_id: id(12),
            issuer_class: rid(issuer),
            payload_digest: SemanticDigest::from_bytes([12; 32]),
            provenance_digest: SemanticDigest::from_bytes([13; 32]),
            issued_at_epoch_ms: 120,
            valid_until_epoch_ms: Some(250),
            revoked_at_epoch_ms: None,
        }
    }

    fn trust_fact() -> ExternalTrustFactSnapshot {
        ExternalTrustFactSnapshot {
            fact_id: id(13),
            organization_id: Some(id(4)),
            subject_type: rid("opportunity"),
            subject_ref: rid("opportunity.falcon.delta1"),
            fact_type: rid("review.status"),
            fact_value: rid("passed"),
            source_system: rid("recoveries"),
            source_digest: SemanticDigest::from_bytes([14; 32]),
            observed_at_epoch_ms: 140,
            valid_until_epoch_ms: Some(250),
        }
    }

    #[test]
    fn allow_requires_every_prerequisite_and_builds_finalization_dependencies() {
        let policy = policy();
        let entitlement = entitlement();
        let assertion = assertion("recoveries.adjudicator");
        let trust = trust_fact();
        let requirement = EvidenceRequirement {
            assertion_type: rid("opportunity.approved"),
            object_ref: rid("opportunity.falcon.delta1"),
            object_digest: SemanticDigest::from_bytes([11; 32]),
        };
        let mut allowlist = EvidenceIssuerAllowlist::default();
        allowlist.allow(rid("opportunity.approved"), rid("recoveries.adjudicator"));
        let query = TrustQuery {
            organization_id: id(4),
            subject_type: rid("opportunity"),
            subject_ref: rid("opportunity.falcon.delta1"),
            required_fact_types: BTreeSet::from([rid("review.status")]),
            freshness_not_before_epoch_ms: 100,
            evaluated_at_epoch_ms: 150,
        };
        let candidate = evaluate_authority_pipeline(AuthorityPipelineInput {
            evaluation: evaluation(policy.semantic_hash()),
            principal_kind: PrincipalKind::Agent,
            membership_class: MembershipClass::Service,
            purpose: rid("recoveries.notice"),
            policy: &policy,
            required_entitlements: BTreeSet::from([rid("recoveries.active")]),
            entitlement_bindings: &[entitlement],
            evidence_requirements: &[requirement],
            assertions: &[assertion],
            evidence_issuer_allowlist: &allowlist,
            trust_query: &query,
            trust_facts: &[trust],
            revocations: &[],
            revocation_snapshot_complete: true,
            revocation_watermark_dependency_id: id(14),
        });
        assert_eq!(candidate.outcome, DecisionOutcome::Allow);
        assert_eq!(candidate.dependency_bundle.dependencies().len(), 4);
    }

    #[test]
    fn untrusted_evidence_and_incomplete_revocation_snapshot_deny_before_policy() {
        let policy = policy();
        let entitlement = entitlement();
        let untrusted = assertion("client.web");
        let trust = trust_fact();
        let requirement = EvidenceRequirement {
            assertion_type: rid("opportunity.approved"),
            object_ref: rid("opportunity.falcon.delta1"),
            object_digest: SemanticDigest::from_bytes([11; 32]),
        };
        let mut allowlist = EvidenceIssuerAllowlist::default();
        allowlist.allow(rid("opportunity.approved"), rid("recoveries.adjudicator"));
        let query = TrustQuery {
            organization_id: id(4),
            subject_type: rid("opportunity"),
            subject_ref: rid("opportunity.falcon.delta1"),
            required_fact_types: BTreeSet::from([rid("review.status")]),
            freshness_not_before_epoch_ms: 100,
            evaluated_at_epoch_ms: 150,
        };
        let denied = evaluate_authority_pipeline(AuthorityPipelineInput {
            evaluation: evaluation(policy.semantic_hash()),
            principal_kind: PrincipalKind::Agent,
            membership_class: MembershipClass::Service,
            purpose: rid("recoveries.notice"),
            policy: &policy,
            required_entitlements: BTreeSet::from([rid("recoveries.active")]),
            entitlement_bindings: std::slice::from_ref(&entitlement),
            evidence_requirements: std::slice::from_ref(&requirement),
            assertions: &[untrusted],
            evidence_issuer_allowlist: &allowlist,
            trust_query: &query,
            trust_facts: std::slice::from_ref(&trust),
            revocations: &[],
            revocation_snapshot_complete: true,
            revocation_watermark_dependency_id: id(14),
        });
        assert_eq!(denied.reason_codes, vec![ReasonCode::InsufficientEvidence]);

        let incomplete = evaluate_authority_pipeline(AuthorityPipelineInput {
            evaluation: evaluation(policy.semantic_hash()),
            principal_kind: PrincipalKind::Agent,
            membership_class: MembershipClass::Service,
            purpose: rid("recoveries.notice"),
            policy: &policy,
            required_entitlements: BTreeSet::from([rid("recoveries.active")]),
            entitlement_bindings: &[entitlement],
            evidence_requirements: &[requirement],
            assertions: &[assertion("recoveries.adjudicator")],
            evidence_issuer_allowlist: &allowlist,
            trust_query: &query,
            trust_facts: &[trust],
            revocations: &[],
            revocation_snapshot_complete: false,
            revocation_watermark_dependency_id: id(14),
        });
        assert_eq!(
            incomplete.reason_codes,
            vec![ReasonCode::TrustOrRevocationDenied]
        );
    }
}
