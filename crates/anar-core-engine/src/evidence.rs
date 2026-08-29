use std::collections::{BTreeMap, BTreeSet};

use anar_core_types::{
    ExternalRevocationFactSnapshot, ExternalStateAssertionSnapshot, ExternalTrustFactSnapshot,
    RegisteredId, SemanticDigest, StableId, domain_hash,
};
use thiserror::Error;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EvidenceRequirement {
    pub assertion_type: RegisteredId,
    pub object_ref: RegisteredId,
    pub object_digest: SemanticDigest,
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct EvidenceIssuerAllowlist {
    allowed: BTreeMap<RegisteredId, BTreeSet<RegisteredId>>,
}

impl EvidenceIssuerAllowlist {
    pub fn allow(&mut self, assertion_type: RegisteredId, issuer_class: RegisteredId) -> bool {
        self.allowed
            .entry(assertion_type)
            .or_default()
            .insert(issuer_class)
    }

    fn permits(&self, assertion_type: &RegisteredId, issuer_class: &RegisteredId) -> bool {
        self.allowed
            .get(assertion_type)
            .is_some_and(|classes| classes.contains(issuer_class))
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedEvidence {
    pub assertion_ids: BTreeSet<StableId>,
    pub assertion_types: BTreeSet<RegisteredId>,
    pub evidence_bundle_hash: SemanticDigest,
}

pub fn verify_required_evidence(
    organization_id: StableId,
    requirements: &[EvidenceRequirement],
    assertions: &[ExternalStateAssertionSnapshot],
    allowlist: &EvidenceIssuerAllowlist,
    at_epoch_ms: i64,
) -> Result<VerifiedEvidence, EvidenceError> {
    if requirements.is_empty() {
        return Ok(VerifiedEvidence {
            assertion_ids: BTreeSet::new(),
            assertion_types: BTreeSet::new(),
            evidence_bundle_hash: domain_hash(
                "ANAR-VERIFIED-EVIDENCE-BUNDLE-1",
                &[&0_u32.to_be_bytes()],
            ),
        });
    }
    let mut selected =
        BTreeMap::<(RegisteredId, RegisteredId), &ExternalStateAssertionSnapshot>::new();
    for requirement in requirements {
        let candidate = assertions
            .iter()
            .filter(|assertion| {
                assertion.organization_id == organization_id
                    && assertion.assertion_type == requirement.assertion_type
                    && assertion.object_ref == requirement.object_ref
                    && assertion.object_digest == requirement.object_digest
                    && assertion.is_current_at(at_epoch_ms)
                    && allowlist.permits(&assertion.assertion_type, &assertion.issuer_class)
            })
            .min_by_key(|assertion| assertion.assertion_id)
            .ok_or_else(|| EvidenceError::MissingOrUntrusted(requirement.assertion_type.clone()))?;
        let key = (
            requirement.assertion_type.clone(),
            requirement.object_ref.clone(),
        );
        if let Some(previous) = selected.insert(key, candidate)
            && previous.object_digest != candidate.object_digest
        {
            return Err(EvidenceError::ContradictoryEvidence);
        }
    }

    let mut bytes = Vec::new();
    bytes.extend_from_slice(&(selected.len() as u32).to_be_bytes());
    let mut assertion_ids = BTreeSet::new();
    let mut assertion_types = BTreeSet::new();
    for ((assertion_type, object_ref), assertion) in selected {
        assertion_ids.insert(assertion.assertion_id);
        assertion_types.insert(assertion_type.clone());
        bytes.extend_from_slice(assertion.assertion_id.as_bytes());
        encode_text(&mut bytes, assertion_type.as_str());
        encode_text(&mut bytes, object_ref.as_str());
        bytes.extend_from_slice(assertion.object_digest.as_bytes());
        bytes.extend_from_slice(assertion.payload_digest.as_bytes());
        bytes.extend_from_slice(assertion.provenance_digest.as_bytes());
    }
    Ok(VerifiedEvidence {
        assertion_ids,
        assertion_types,
        evidence_bundle_hash: domain_hash("ANAR-VERIFIED-EVIDENCE-BUNDLE-1", &[&bytes]),
    })
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TrustQuery {
    pub organization_id: StableId,
    pub subject_type: RegisteredId,
    pub subject_ref: RegisteredId,
    pub required_fact_types: BTreeSet<RegisteredId>,
    pub freshness_not_before_epoch_ms: i64,
    pub evaluated_at_epoch_ms: i64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedTrust {
    pub fact_ids: BTreeSet<StableId>,
    pub facts: BTreeSet<(RegisteredId, RegisteredId)>,
    pub revocation_watermark: SemanticDigest,
}

pub fn resolve_trust_and_revocation(
    query: &TrustQuery,
    facts: &[ExternalTrustFactSnapshot],
    revocations: &[ExternalRevocationFactSnapshot],
) -> Result<VerifiedTrust, TrustError> {
    let mut relevant_revocations: Vec<_> = revocations
        .iter()
        .filter(|revocation| {
            revocation
                .organization_id
                .is_none_or(|value| value == query.organization_id)
                && revocation.target_type == query.subject_type
                && revocation.target_ref == query.subject_ref
                && revocation.is_effective_at(query.evaluated_at_epoch_ms)
        })
        .collect();
    relevant_revocations.sort_by_key(|value| value.revocation_fact_id);
    if let Some(revocation) = relevant_revocations.first() {
        return Err(TrustError::EffectivelyRevoked {
            reason_code: revocation.reason_code.clone(),
        });
    }

    let mut selected = BTreeMap::<RegisteredId, &ExternalTrustFactSnapshot>::new();
    for required_type in &query.required_fact_types {
        let fact = facts
            .iter()
            .filter(|fact| {
                fact.organization_id
                    .is_none_or(|value| value == query.organization_id)
                    && fact.subject_type == query.subject_type
                    && fact.subject_ref == query.subject_ref
                    && fact.fact_type == *required_type
                    && fact.observed_at_epoch_ms >= query.freshness_not_before_epoch_ms
                    && fact.is_current_at(query.evaluated_at_epoch_ms)
            })
            .max_by_key(|fact| (fact.observed_at_epoch_ms, fact.fact_id))
            .ok_or_else(|| TrustError::MissingOrStaleFact(required_type.clone()))?;
        selected.insert(required_type.clone(), fact);
    }

    let mut bytes = Vec::new();
    bytes.extend_from_slice(&(selected.len() as u32).to_be_bytes());
    let mut fact_ids = BTreeSet::new();
    let mut verified_facts = BTreeSet::new();
    for (fact_type, fact) in selected {
        fact_ids.insert(fact.fact_id);
        verified_facts.insert((fact_type.clone(), fact.fact_value.clone()));
        bytes.extend_from_slice(fact.fact_id.as_bytes());
        encode_text(&mut bytes, fact_type.as_str());
        encode_text(&mut bytes, fact.fact_value.as_str());
        bytes.extend_from_slice(fact.source_digest.as_bytes());
        bytes.extend_from_slice(&fact.observed_at_epoch_ms.to_be_bytes());
    }
    Ok(VerifiedTrust {
        fact_ids,
        facts: verified_facts,
        revocation_watermark: domain_hash("ANAR-TRUST-REVOCATION-WATERMARK-1", &[&bytes]),
    })
}

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum EvidenceError {
    #[error(
        "required evidence is absent, expired, revoked, digest-mismatched, or from an unauthorized issuer: {0}"
    )]
    MissingOrUntrusted(RegisteredId),
    #[error("selected evidence contains contradictory object digests")]
    ContradictoryEvidence,
}

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum TrustError {
    #[error("an effective external revocation denies the subject: {reason_code}")]
    EffectivelyRevoked { reason_code: RegisteredId },
    #[error("required external trust fact is missing or stale: {0}")]
    MissingOrStaleFact(RegisteredId),
}

fn encode_text(output: &mut Vec<u8>, text: &str) {
    output.extend_from_slice(&(text.len() as u32).to_be_bytes());
    output.extend_from_slice(text.as_bytes());
}

#[cfg(test)]
mod tests {
    use super::*;

    fn id(last: u8) -> StableId {
        let mut bytes = [0_u8; 16];
        bytes[15] = last;
        StableId::from_bytes(bytes)
    }

    fn rid(value: &str) -> RegisteredId {
        RegisteredId::new(value).unwrap()
    }

    fn assertion(issuer_class: &str) -> ExternalStateAssertionSnapshot {
        ExternalStateAssertionSnapshot {
            assertion_id: id(1),
            organization_id: id(2),
            assertion_type: rid("opportunity.approved"),
            object_ref: rid("opportunity.falcon.delta1"),
            object_digest: SemanticDigest::from_bytes([3; 32]),
            issuer_principal_id: id(4),
            issuer_class: rid(issuer_class),
            payload_digest: SemanticDigest::from_bytes([5; 32]),
            provenance_digest: SemanticDigest::from_bytes([6; 32]),
            issued_at_epoch_ms: 10,
            valid_until_epoch_ms: Some(20),
            revoked_at_epoch_ms: None,
        }
    }

    #[test]
    fn formatted_evidence_from_an_unlisted_issuer_is_not_authoritative() {
        let requirement = EvidenceRequirement {
            assertion_type: rid("opportunity.approved"),
            object_ref: rid("opportunity.falcon.delta1"),
            object_digest: SemanticDigest::from_bytes([3; 32]),
        };
        let mut allowlist = EvidenceIssuerAllowlist::default();
        allowlist.allow(rid("opportunity.approved"), rid("recoveries.adjudicator"));
        assert!(matches!(
            verify_required_evidence(
                id(2),
                &[requirement],
                &[assertion("client.web")],
                &allowlist,
                15
            ),
            Err(EvidenceError::MissingOrUntrusted(_))
        ));
    }

    #[test]
    fn exact_current_allowlisted_evidence_produces_a_stable_bundle() {
        let requirement = EvidenceRequirement {
            assertion_type: rid("opportunity.approved"),
            object_ref: rid("opportunity.falcon.delta1"),
            object_digest: SemanticDigest::from_bytes([3; 32]),
        };
        let mut allowlist = EvidenceIssuerAllowlist::default();
        allowlist.allow(rid("opportunity.approved"), rid("recoveries.adjudicator"));
        let first = verify_required_evidence(
            id(2),
            std::slice::from_ref(&requirement),
            &[assertion("recoveries.adjudicator")],
            &allowlist,
            15,
        )
        .unwrap();
        let second = verify_required_evidence(
            id(2),
            &[requirement],
            &[assertion("recoveries.adjudicator")],
            &allowlist,
            15,
        )
        .unwrap();
        assert_eq!(first, second);
    }

    #[test]
    fn effective_revocation_wins_over_positive_trust() {
        let fact = ExternalTrustFactSnapshot {
            fact_id: id(10),
            organization_id: Some(id(2)),
            subject_type: rid("artifact"),
            subject_ref: rid("artifact.falcon"),
            fact_type: rid("review.status"),
            fact_value: rid("passed"),
            source_system: rid("registry"),
            source_digest: SemanticDigest::from_bytes([7; 32]),
            observed_at_epoch_ms: 12,
            valid_until_epoch_ms: Some(30),
        };
        let revocation = ExternalRevocationFactSnapshot {
            revocation_fact_id: id(11),
            organization_id: Some(id(2)),
            target_type: rid("artifact"),
            target_ref: rid("artifact.falcon"),
            reason_code: rid("review.revoked"),
            severity: rid("high"),
            source_system: rid("registry"),
            source_digest: SemanticDigest::from_bytes([8; 32]),
            effective_at_epoch_ms: 14,
        };
        let query = TrustQuery {
            organization_id: id(2),
            subject_type: rid("artifact"),
            subject_ref: rid("artifact.falcon"),
            required_fact_types: BTreeSet::from([rid("review.status")]),
            freshness_not_before_epoch_ms: 10,
            evaluated_at_epoch_ms: 15,
        };
        assert!(matches!(
            resolve_trust_and_revocation(&query, &[fact], &[revocation]),
            Err(TrustError::EffectivelyRevoked { .. })
        ));
    }
}
