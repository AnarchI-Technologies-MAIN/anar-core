use std::collections::BTreeMap;

use anar_core_types::{AuthorityEnvelope, RegisteredId, ShadowComparison, SubsetRelation};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ShadowDisposition {
    Equal,
    NarrowerOnly,
    Wider,
    Incomparable,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ShadowCaseResult {
    pub case_id: RegisteredId,
    pub comparison: ShadowComparison,
    pub disposition: ShadowDisposition,
}

pub fn compare_shadow_case(
    case_id: RegisteredId,
    current: &AuthorityEnvelope,
    predecessor: &AuthorityEnvelope,
) -> ShadowCaseResult {
    let comparison = current.compare_for_shadow_cutover(predecessor);
    let disposition = if comparison
        .dimensions
        .values()
        .any(|value| *value == SubsetRelation::Incomparable)
    {
        ShadowDisposition::Incomparable
    } else if comparison
        .dimensions
        .values()
        .any(|value| *value == SubsetRelation::Wider)
    {
        ShadowDisposition::Wider
    } else if comparison
        .dimensions
        .values()
        .all(|value| *value == SubsetRelation::Equal)
    {
        ShadowDisposition::Equal
    } else {
        ShadowDisposition::NarrowerOnly
    };
    ShadowCaseResult {
        case_id,
        comparison,
        disposition,
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ShadowBatchEvidence {
    pub case_count: usize,
    pub disposition_counts: BTreeMap<String, usize>,
    pub wider_by_dimension: BTreeMap<String, usize>,
    pub incomparable_by_dimension: BTreeMap<String, usize>,
    pub cutover_eligible: bool,
}

pub fn summarize_shadow_batch(cases: &[ShadowCaseResult]) -> ShadowBatchEvidence {
    let mut disposition_counts = BTreeMap::from([
        ("EQUAL".to_owned(), 0),
        ("INCOMPARABLE".to_owned(), 0),
        ("NARROWER_ONLY".to_owned(), 0),
        ("WIDER".to_owned(), 0),
    ]);
    let mut wider_by_dimension = BTreeMap::new();
    let mut incomparable_by_dimension = BTreeMap::new();
    for case in cases {
        let key = match case.disposition {
            ShadowDisposition::Equal => "EQUAL",
            ShadowDisposition::NarrowerOnly => "NARROWER_ONLY",
            ShadowDisposition::Wider => "WIDER",
            ShadowDisposition::Incomparable => "INCOMPARABLE",
        };
        *disposition_counts
            .get_mut(key)
            .expect("all dispositions registered") += 1;
        for (dimension, relation) in &case.comparison.dimensions {
            match relation {
                SubsetRelation::Wider => {
                    *wider_by_dimension.entry(dimension.clone()).or_insert(0) += 1;
                }
                SubsetRelation::Incomparable => {
                    *incomparable_by_dimension
                        .entry(dimension.clone())
                        .or_insert(0) += 1;
                }
                SubsetRelation::Equal | SubsetRelation::Narrower => {}
            }
        }
    }
    ShadowBatchEvidence {
        case_count: cases.len(),
        disposition_counts,
        wider_by_dimension,
        incomparable_by_dimension,
        cutover_eligible: !cases.is_empty()
            && cases.iter().all(|case| {
                matches!(
                    case.disposition,
                    ShadowDisposition::Equal | ShadowDisposition::NarrowerOnly
                )
            }),
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;

    use anar_core_types::{
        ApprovalRequirement, DecisionOutcome, DelegationBound, EffectScope, EvidenceRequirementSet,
        OfflineRestriction, ResourceScope, RiskTier, TimeWindow, UsageBound,
    };

    use super::*;

    fn rid(value: &str) -> RegisteredId {
        RegisteredId::new(value).unwrap()
    }

    fn envelope(resource: &str) -> AuthorityEnvelope {
        AuthorityEnvelope {
            outcome: DecisionOutcome::Allow,
            resource_scope: ResourceScope::ExplicitSet {
                resources: BTreeSet::from([rid(resource)]),
            },
            effect_scope: EffectScope {
                classes: BTreeSet::from([rid("external.communication")]),
            },
            time_window: TimeWindow {
                starts_at_epoch_ms: Some(100),
                ends_at_epoch_ms: Some(200),
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
                offline_read_allowed: false,
                deferred_effect_allowed: false,
            },
        }
    }

    #[test]
    fn same_count_different_resource_blocks_cutover_without_an_aggregate_score() {
        let case = compare_shadow_case(
            rid("falcon.case1"),
            &envelope("resource:b"),
            &envelope("resource:a"),
        );
        assert_eq!(case.disposition, ShadowDisposition::Incomparable);
        let evidence = summarize_shadow_batch(&[case]);
        assert!(!evidence.cutover_eligible);
        assert_eq!(evidence.incomparable_by_dimension["resource_scope"], 1);
    }

    #[test]
    fn empty_or_wider_batches_never_cut_over() {
        assert!(!summarize_shadow_batch(&[]).cutover_eligible);
        let mut wider = envelope("resource:a");
        wider.resource_scope = ResourceScope::All;
        let case = compare_shadow_case(rid("falcon.case2"), &wider, &envelope("resource:a"));
        assert_eq!(case.disposition, ShadowDisposition::Wider);
        assert!(!summarize_shadow_batch(&[case]).cutover_eligible);
    }
}
