#![forbid(unsafe_code)]

pub mod canonical;
pub mod dependency;
pub mod domain;
pub mod ids;
pub mod lattice;
pub mod money;
pub mod parser;

pub use canonical::{SemanticDigest, domain_hash};
pub use dependency::{
    AuthorityDependencyRef, AuthorityDependencyType, AuthorityStatus, DependencyBundle,
};
pub use domain::{
    BindingStatus, EntitlementBindingSnapshot, ExternalRevocationFactSnapshot,
    ExternalStateAssertionSnapshot, ExternalTrustFactSnapshot, MembershipClass, PrincipalKind,
    ValidityWindow,
};
pub use ids::{RegisteredId, StableId};
pub use lattice::{
    ApprovalRequirement, AuthorityEnvelope, DecisionOutcome, DelegationBound, EffectScope,
    EvidenceRequirementSet, FinancialBound, FinancialBoundKind, OfflineRestriction, ResourceScope,
    RiskTier, ShadowComparison, SubsetRelation, TimeWindow, UsageBound,
};
pub use money::{AssetRegistry, AssetSpec, MoneyError, MoneyLimit};
pub use parser::{
    AuthorityInputError, CapabilityRef, ConstraintSet, EffectScopeRequest, EvidenceRef,
    InputLimitsProfile, NormalizedCapabilityRequest, ResourceScopeRequest, parse_authority_request,
    validate_bounded_json,
};
