use std::collections::{BTreeMap, BTreeSet};
use std::panic::{AssertUnwindSafe, catch_unwind, resume_unwind};

use anar_core_types::{RegisteredId, SemanticDigest, StableId, SubsetRelation};
use thiserror::Error;

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct DelegationNodeKey {
    pub principal_id: StableId,
    pub organization_id: StableId,
    pub capability_id: RegisteredId,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct DelegationFrameKey {
    pub node: DelegationNodeKey,
    pub policy_binding_id: StableId,
    pub resource_scope_hash: SemanticDigest,
    pub effect_scope_hash: SemanticDigest,
    pub constraint_hash: SemanticDigest,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DelegationEdge {
    pub delegation_id: StableId,
    pub source: DelegationNodeKey,
    pub target: DelegationNodeKey,
    pub frame: DelegationFrameKey,
    pub relation_to_parent: SubsetRelation,
    pub cross_organization_authorized: bool,
}

#[derive(Debug, Clone, Default)]
pub struct DelegationGraph {
    edges: BTreeMap<DelegationNodeKey, Vec<DelegationEdge>>,
}

impl DelegationGraph {
    pub fn add_edge(&mut self, edge: DelegationEdge) {
        self.edges
            .entry(edge.source.clone())
            .or_default()
            .push(edge);
    }

    pub fn validate_from(
        &self,
        start: DelegationNodeKey,
        max_depth: u16,
    ) -> Result<BTreeSet<DelegationNodeKey>, DelegationError> {
        let mut state = TraversalState::new(max_depth);
        state.active_nodes.insert(start.clone());
        let mut reached = BTreeSet::new();
        let result = self.visit(&start, &mut state, &mut reached);
        state.active_nodes.remove(&start);
        result?;
        if !state.is_clean() {
            return Err(DelegationError::TraversalStateCorrupted);
        }
        Ok(reached)
    }

    fn visit(
        &self,
        node: &DelegationNodeKey,
        state: &mut TraversalState,
        reached: &mut BTreeSet<DelegationNodeKey>,
    ) -> Result<(), DelegationError> {
        for edge in self.edges.get(node).into_iter().flatten() {
            if edge.source != *node {
                return Err(DelegationError::TraversalStateCorrupted);
            }
            if edge.source.organization_id != edge.target.organization_id
                && !edge.cross_organization_authorized
            {
                return Err(DelegationError::CrossOrganizationNotAuthorized);
            }
            if !matches!(
                edge.relation_to_parent,
                SubsetRelation::Equal | SubsetRelation::Narrower
            ) {
                return Err(DelegationError::ScopeAmplification);
            }
            state.with_frame(edge, |state| {
                reached.insert(edge.target.clone());
                self.visit(&edge.target, state, reached)
            })?;
        }
        Ok(())
    }
}

struct TraversalState {
    active_nodes: BTreeSet<DelegationNodeKey>,
    active_edges: BTreeSet<StableId>,
    active_frames: BTreeSet<DelegationFrameKey>,
    depth: u16,
    max_depth: u16,
}

impl TraversalState {
    fn new(max_depth: u16) -> Self {
        Self {
            active_nodes: BTreeSet::new(),
            active_edges: BTreeSet::new(),
            active_frames: BTreeSet::new(),
            depth: 0,
            max_depth,
        }
    }

    fn with_frame<T>(
        &mut self,
        edge: &DelegationEdge,
        operation: impl FnOnce(&mut Self) -> Result<T, DelegationError>,
    ) -> Result<T, DelegationError> {
        if self.depth >= self.max_depth {
            return Err(DelegationError::DepthExceeded);
        }
        if self.active_nodes.contains(&edge.target) {
            return Err(DelegationError::SemanticLoopDetected);
        }
        if self.active_edges.contains(&edge.delegation_id) {
            return Err(DelegationError::EdgeLoopDetected);
        }
        if self.active_frames.contains(&edge.frame) {
            return Err(DelegationError::FrameReentryDetected);
        }

        self.active_nodes.insert(edge.target.clone());
        self.active_edges.insert(edge.delegation_id);
        self.active_frames.insert(edge.frame.clone());
        self.depth = self
            .depth
            .checked_add(1)
            .ok_or(DelegationError::DepthExceeded)?;

        let result = catch_unwind(AssertUnwindSafe(|| operation(self)));

        self.depth = self
            .depth
            .checked_sub(1)
            .ok_or(DelegationError::TraversalStateCorrupted)?;
        let node_removed = self.active_nodes.remove(&edge.target);
        let edge_removed = self.active_edges.remove(&edge.delegation_id);
        let frame_removed = self.active_frames.remove(&edge.frame);
        if !(node_removed && edge_removed && frame_removed) {
            return Err(DelegationError::TraversalStateCorrupted);
        }

        match result {
            Ok(value) => value,
            Err(payload) => resume_unwind(payload),
        }
    }

    fn is_clean(&self) -> bool {
        self.depth == 0 && self.active_edges.is_empty() && self.active_frames.is_empty()
    }
}

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum DelegationError {
    #[error("delegation semantic loop detected")]
    SemanticLoopDetected,
    #[error("delegation edge loop detected")]
    EdgeLoopDetected,
    #[error("delegation frame re-entry detected")]
    FrameReentryDetected,
    #[error("delegation depth exceeded")]
    DepthExceeded,
    #[error("cross-organization delegation is not explicitly authorized")]
    CrossOrganizationNotAuthorized,
    #[error("delegation would amplify authority")]
    ScopeAmplification,
    #[error("delegation traversal state was corrupted")]
    TraversalStateCorrupted,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn id(last: u8) -> StableId {
        let mut value = [0_u8; 16];
        value[15] = last;
        StableId::from_bytes(value)
    }

    fn node(principal: u8, organization: u8) -> DelegationNodeKey {
        DelegationNodeKey {
            principal_id: id(principal),
            organization_id: id(organization),
            capability_id: RegisteredId::new("recoveries.notice.send").unwrap(),
        }
    }

    fn edge(last: u8, source: DelegationNodeKey, target: DelegationNodeKey) -> DelegationEdge {
        DelegationEdge {
            delegation_id: id(last),
            source,
            target: target.clone(),
            frame: DelegationFrameKey {
                node: target,
                policy_binding_id: id(100 + last),
                resource_scope_hash: SemanticDigest::ZERO,
                effect_scope_hash: SemanticDigest::ZERO,
                constraint_hash: SemanticDigest::ZERO,
            },
            relation_to_parent: SubsetRelation::Narrower,
            cross_organization_authorized: false,
        }
    }

    #[test]
    fn semantic_cycle_with_distinct_edges_and_frames_fails_closed() {
        let a = node(1, 10);
        let b = node(2, 10);
        let c = node(3, 10);
        let mut graph = DelegationGraph::default();
        graph.add_edge(edge(1, a.clone(), b.clone()));
        graph.add_edge(edge(2, b, c.clone()));
        graph.add_edge(edge(3, c, a.clone()));
        assert_eq!(
            graph.validate_from(a, 8),
            Err(DelegationError::SemanticLoopDetected)
        );
    }

    #[test]
    fn valid_diamond_convergence_is_branch_local() {
        let a = node(1, 10);
        let b = node(2, 10);
        let c = node(3, 10);
        let d = node(4, 10);
        let mut graph = DelegationGraph::default();
        graph.add_edge(edge(1, a.clone(), b.clone()));
        graph.add_edge(edge(2, a.clone(), c.clone()));
        graph.add_edge(edge(3, b, d.clone()));
        graph.add_edge(edge(4, c, d.clone()));
        let reached = graph.validate_from(a, 8).unwrap();
        assert!(reached.contains(&d));
        assert_eq!(reached.len(), 3);
    }

    #[test]
    fn cross_org_requires_exact_explicit_authorization() {
        let a = node(1, 10);
        let b = node(2, 11);
        let mut graph = DelegationGraph::default();
        graph.add_edge(edge(1, a.clone(), b));
        assert_eq!(
            graph.validate_from(a, 8),
            Err(DelegationError::CrossOrganizationNotAuthorized)
        );
    }

    #[test]
    fn early_return_and_panic_restore_branch_state() {
        let source = node(1, 10);
        let target = node(2, 10);
        let edge = edge(1, source.clone(), target);
        let mut state = TraversalState::new(8);
        state.active_nodes.insert(source.clone());
        let result: Result<(), _> =
            state.with_frame(&edge, |_| Err(DelegationError::ScopeAmplification));
        assert_eq!(result, Err(DelegationError::ScopeAmplification));
        assert!(state.is_clean());

        let unwind = catch_unwind(AssertUnwindSafe(|| {
            let _: Result<(), DelegationError> = state.with_frame(&edge, |_| panic!("fracture"));
        }));
        assert!(unwind.is_err());
        assert!(state.is_clean());
        assert!(state.active_nodes.contains(&source));
    }
}
