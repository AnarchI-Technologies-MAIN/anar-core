use std::collections::BTreeSet;

use anar_core_types::{
    DecisionOutcome, MembershipClass, PrincipalKind, RegisteredId, SemanticDigest, domain_hash,
};
use serde::{Deserialize, Serialize};
use thiserror::Error;

const POLICY_DOMAIN: &str = "ANAR-DETERMINISTIC-POLICY-IR-1";
const MAX_RULES: usize = 128;
const MAX_PREDICATE_NODES: usize = 1_024;
const MAX_PREDICATE_DEPTH: usize = 32;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum PolicyEffect {
    Deny,
    RequireApproval,
    Allow,
}

impl PolicyEffect {
    fn outcome(&self) -> DecisionOutcome {
        match self {
            Self::Deny => DecisionOutcome::Deny,
            Self::RequireApproval => DecisionOutcome::RequireApproval,
            Self::Allow => DecisionOutcome::Allow,
        }
    }

    const fn wire_code(&self) -> u8 {
        match self {
            Self::Deny => 1,
            Self::RequireApproval => 2,
            Self::Allow => 3,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "op", rename_all = "SCREAMING_SNAKE_CASE", deny_unknown_fields)]
pub enum PolicyPredicate {
    True,
    All {
        predicates: Vec<PolicyPredicate>,
    },
    Any {
        predicates: Vec<PolicyPredicate>,
    },
    Not {
        predicate: Box<PolicyPredicate>,
    },
    PrincipalKindIs {
        value: PrincipalKind,
    },
    MembershipClassIs {
        value: MembershipClass,
    },
    PurposeIs {
        value: RegisteredId,
    },
    HasEntitlement {
        entitlement_ref: RegisteredId,
    },
    HasEvidence {
        assertion_type: RegisteredId,
    },
    HasTrustFact {
        fact_type: RegisteredId,
        fact_value: RegisteredId,
    },
    NoEffectiveRevocation {
        target_ref: RegisteredId,
    },
    AtOrAfter {
        epoch_ms: i64,
    },
    Before {
        epoch_ms: i64,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PolicyRule {
    pub rule_id: RegisteredId,
    pub predicate: PolicyPredicate,
    pub effect: PolicyEffect,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PolicyProgram {
    pub policy_id: RegisteredId,
    pub version: u32,
    pub rules: Vec<PolicyRule>,
    pub default_effect: PolicyEffect,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CompiledPolicy {
    program: PolicyProgram,
    semantic_hash: SemanticDigest,
}

impl CompiledPolicy {
    pub fn compile(program: PolicyProgram) -> Result<Self, PolicyError> {
        if program.version == 0 || program.rules.is_empty() || program.rules.len() > MAX_RULES {
            return Err(PolicyError::InvalidProgram);
        }
        if program.default_effect != PolicyEffect::Deny {
            return Err(PolicyError::DefaultMustDeny);
        }
        let mut rule_ids = BTreeSet::new();
        let mut node_count = 0_usize;
        for rule in &program.rules {
            if !rule_ids.insert(rule.rule_id.clone()) {
                return Err(PolicyError::DuplicateRuleId);
            }
            validate_predicate(&rule.predicate, 1, &mut node_count)?;
        }
        let bytes = encode_program(&program);
        Ok(Self {
            program,
            semantic_hash: domain_hash(POLICY_DOMAIN, &[&bytes]),
        })
    }

    pub const fn semantic_hash(&self) -> SemanticDigest {
        self.semantic_hash
    }

    pub fn evaluate(&self, facts: &PolicyFacts) -> PolicyEvaluation {
        for rule in &self.program.rules {
            if predicate_matches(&rule.predicate, facts) {
                return PolicyEvaluation {
                    outcome: rule.effect.outcome(),
                    matched_rule_id: Some(rule.rule_id.clone()),
                    policy_semantic_hash: self.semantic_hash,
                };
            }
        }
        PolicyEvaluation {
            outcome: self.program.default_effect.outcome(),
            matched_rule_id: None,
            policy_semantic_hash: self.semantic_hash,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PolicyFacts {
    pub principal_kind: PrincipalKind,
    pub membership_class: MembershipClass,
    pub purpose: RegisteredId,
    pub active_entitlements: BTreeSet<RegisteredId>,
    pub verified_evidence_types: BTreeSet<RegisteredId>,
    pub current_trust_facts: BTreeSet<(RegisteredId, RegisteredId)>,
    pub effective_revocation_targets: BTreeSet<RegisteredId>,
    pub revocation_snapshot_complete: bool,
    pub evaluated_at_epoch_ms: i64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PolicyEvaluation {
    pub outcome: DecisionOutcome,
    pub matched_rule_id: Option<RegisteredId>,
    pub policy_semantic_hash: SemanticDigest,
}

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum PolicyError {
    #[error("policy IR is structurally invalid or exceeds rule limits")]
    InvalidProgram,
    #[error("policy IR default effect must be DENY")]
    DefaultMustDeny,
    #[error("policy IR contains a duplicate rule id")]
    DuplicateRuleId,
    #[error("policy predicate exceeds bounded depth or node count")]
    PredicateBudgetExceeded,
}

fn validate_predicate(
    predicate: &PolicyPredicate,
    depth: usize,
    nodes: &mut usize,
) -> Result<(), PolicyError> {
    *nodes = nodes
        .checked_add(1)
        .ok_or(PolicyError::PredicateBudgetExceeded)?;
    if depth > MAX_PREDICATE_DEPTH || *nodes > MAX_PREDICATE_NODES {
        return Err(PolicyError::PredicateBudgetExceeded);
    }
    match predicate {
        PolicyPredicate::All { predicates } | PolicyPredicate::Any { predicates } => {
            if predicates.is_empty() || predicates.len() > MAX_RULES {
                return Err(PolicyError::InvalidProgram);
            }
            for child in predicates {
                validate_predicate(child, depth + 1, nodes)?;
            }
        }
        PolicyPredicate::Not { predicate } => validate_predicate(predicate, depth + 1, nodes)?,
        _ => {}
    }
    Ok(())
}

fn predicate_matches(predicate: &PolicyPredicate, facts: &PolicyFacts) -> bool {
    match predicate {
        PolicyPredicate::True => true,
        PolicyPredicate::All { predicates } => predicates
            .iter()
            .all(|value| predicate_matches(value, facts)),
        PolicyPredicate::Any { predicates } => predicates
            .iter()
            .any(|value| predicate_matches(value, facts)),
        PolicyPredicate::Not { predicate } => !predicate_matches(predicate, facts),
        PolicyPredicate::PrincipalKindIs { value } => facts.principal_kind == *value,
        PolicyPredicate::MembershipClassIs { value } => facts.membership_class == *value,
        PolicyPredicate::PurposeIs { value } => facts.purpose == *value,
        PolicyPredicate::HasEntitlement { entitlement_ref } => {
            facts.active_entitlements.contains(entitlement_ref)
        }
        PolicyPredicate::HasEvidence { assertion_type } => {
            facts.verified_evidence_types.contains(assertion_type)
        }
        PolicyPredicate::HasTrustFact {
            fact_type,
            fact_value,
        } => facts
            .current_trust_facts
            .contains(&(fact_type.clone(), fact_value.clone())),
        PolicyPredicate::NoEffectiveRevocation { target_ref } => {
            facts.revocation_snapshot_complete
                && !facts.effective_revocation_targets.contains(target_ref)
        }
        PolicyPredicate::AtOrAfter { epoch_ms } => facts.evaluated_at_epoch_ms >= *epoch_ms,
        PolicyPredicate::Before { epoch_ms } => facts.evaluated_at_epoch_ms < *epoch_ms,
    }
}

fn encode_program(program: &PolicyProgram) -> Vec<u8> {
    let mut output = Vec::new();
    encode_text(&mut output, program.policy_id.as_str());
    output.extend_from_slice(&program.version.to_be_bytes());
    output.extend_from_slice(&(program.rules.len() as u32).to_be_bytes());
    for rule in &program.rules {
        encode_text(&mut output, rule.rule_id.as_str());
        encode_predicate(&mut output, &rule.predicate);
        output.push(rule.effect.wire_code());
    }
    output.push(program.default_effect.wire_code());
    output
}

fn encode_predicate(output: &mut Vec<u8>, predicate: &PolicyPredicate) {
    match predicate {
        PolicyPredicate::True => output.push(1),
        PolicyPredicate::All { predicates } => {
            output.push(2);
            encode_children(output, predicates);
        }
        PolicyPredicate::Any { predicates } => {
            output.push(3);
            encode_children(output, predicates);
        }
        PolicyPredicate::Not { predicate } => {
            output.push(4);
            encode_predicate(output, predicate);
        }
        PolicyPredicate::PrincipalKindIs { value } => {
            output.push(5);
            output.push(*value as u8);
        }
        PolicyPredicate::MembershipClassIs { value } => {
            output.push(6);
            output.push(*value as u8);
        }
        PolicyPredicate::PurposeIs { value } => {
            output.push(7);
            encode_text(output, value.as_str());
        }
        PolicyPredicate::HasEntitlement { entitlement_ref } => {
            output.push(8);
            encode_text(output, entitlement_ref.as_str());
        }
        PolicyPredicate::HasEvidence { assertion_type } => {
            output.push(9);
            encode_text(output, assertion_type.as_str());
        }
        PolicyPredicate::HasTrustFact {
            fact_type,
            fact_value,
        } => {
            output.push(10);
            encode_text(output, fact_type.as_str());
            encode_text(output, fact_value.as_str());
        }
        PolicyPredicate::NoEffectiveRevocation { target_ref } => {
            output.push(11);
            encode_text(output, target_ref.as_str());
        }
        PolicyPredicate::AtOrAfter { epoch_ms } => {
            output.push(12);
            output.extend_from_slice(&epoch_ms.to_be_bytes());
        }
        PolicyPredicate::Before { epoch_ms } => {
            output.push(13);
            output.extend_from_slice(&epoch_ms.to_be_bytes());
        }
    }
}

fn encode_children(output: &mut Vec<u8>, predicates: &[PolicyPredicate]) {
    output.extend_from_slice(&(predicates.len() as u32).to_be_bytes());
    for predicate in predicates {
        let mut child = Vec::new();
        encode_predicate(&mut child, predicate);
        output.extend_from_slice(&(child.len() as u32).to_be_bytes());
        output.extend_from_slice(&child);
    }
}

fn encode_text(output: &mut Vec<u8>, text: &str) {
    output.extend_from_slice(&(text.len() as u32).to_be_bytes());
    output.extend_from_slice(text.as_bytes());
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rid(value: &str) -> RegisteredId {
        RegisteredId::new(value).unwrap()
    }

    fn facts() -> PolicyFacts {
        PolicyFacts {
            principal_kind: PrincipalKind::Agent,
            membership_class: MembershipClass::Service,
            purpose: rid("recoveries.notice"),
            active_entitlements: BTreeSet::from([rid("recoveries.active")]),
            verified_evidence_types: BTreeSet::from([rid("opportunity.approved")]),
            current_trust_facts: BTreeSet::new(),
            effective_revocation_targets: BTreeSet::new(),
            revocation_snapshot_complete: true,
            evaluated_at_epoch_ms: 100,
        }
    }

    #[test]
    fn evidence_and_entitlement_require_an_explicit_allow_policy() {
        let program = PolicyProgram {
            policy_id: rid("recoveries.notice.policy"),
            version: 1,
            rules: vec![PolicyRule {
                rule_id: rid("deny.unrelated"),
                predicate: PolicyPredicate::PurposeIs {
                    value: rid("different.purpose"),
                },
                effect: PolicyEffect::Allow,
            }],
            default_effect: PolicyEffect::Deny,
        };
        assert_eq!(
            CompiledPolicy::compile(program)
                .unwrap()
                .evaluate(&facts())
                .outcome,
            DecisionOutcome::Deny
        );
    }

    #[test]
    fn typed_conjunction_is_deterministic_and_unknown_revocation_fails_closed() {
        let program = PolicyProgram {
            policy_id: rid("recoveries.notice.policy"),
            version: 1,
            rules: vec![PolicyRule {
                rule_id: rid("allow.current.approved.notice"),
                predicate: PolicyPredicate::All {
                    predicates: vec![
                        PolicyPredicate::PurposeIs {
                            value: rid("recoveries.notice"),
                        },
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
        };
        let first = CompiledPolicy::compile(program.clone()).unwrap();
        let second = CompiledPolicy::compile(program).unwrap();
        assert_eq!(first.semantic_hash(), second.semantic_hash());
        assert_eq!(first.evaluate(&facts()).outcome, DecisionOutcome::Allow);
        let mut unknown = facts();
        unknown.revocation_snapshot_complete = false;
        assert_eq!(first.evaluate(&unknown).outcome, DecisionOutcome::Deny);
    }

    #[test]
    fn allow_by_default_and_unbounded_predicates_are_rejected() {
        let allow_default = PolicyProgram {
            policy_id: rid("bad.policy"),
            version: 1,
            rules: vec![PolicyRule {
                rule_id: rid("deny"),
                predicate: PolicyPredicate::True,
                effect: PolicyEffect::Deny,
            }],
            default_effect: PolicyEffect::Allow,
        };
        assert_eq!(
            CompiledPolicy::compile(allow_default),
            Err(PolicyError::DefaultMustDeny)
        );

        let mut predicate = PolicyPredicate::True;
        for _ in 0..=MAX_PREDICATE_DEPTH {
            predicate = PolicyPredicate::Not {
                predicate: Box::new(predicate),
            };
        }
        let too_deep = PolicyProgram {
            policy_id: rid("deep.policy"),
            version: 1,
            rules: vec![PolicyRule {
                rule_id: rid("deep"),
                predicate,
                effect: PolicyEffect::Deny,
            }],
            default_effect: PolicyEffect::Deny,
        };
        assert_eq!(
            CompiledPolicy::compile(too_deep),
            Err(PolicyError::PredicateBudgetExceeded)
        );
    }
}
