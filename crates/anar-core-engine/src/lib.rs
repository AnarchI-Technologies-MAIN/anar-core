#![forbid(unsafe_code)]

pub mod delegation;
pub mod evaluation;
pub mod evidence;
pub mod pipeline;
pub mod policy;
pub mod receipt;
pub mod shadow;

pub use delegation::{
    DelegationEdge, DelegationError, DelegationFrameKey, DelegationGraph, DelegationNodeKey,
};
pub use evaluation::{
    AuthorityContextSnapshot, BindingSnapshot, CandidateDecision, CoreAuthorityState,
    EvaluationInput, GenerationVector, ReasonCode, evaluate,
};
pub use evidence::{
    EvidenceError, EvidenceIssuerAllowlist, EvidenceRequirement, TrustError, TrustQuery,
    VerifiedEvidence, VerifiedTrust, resolve_trust_and_revocation, verify_required_evidence,
};
pub use pipeline::{AuthorityPipelineInput, evaluate_authority_pipeline};
pub use policy::{
    CompiledPolicy, PolicyEffect, PolicyError, PolicyEvaluation, PolicyFacts, PolicyPredicate,
    PolicyProgram, PolicyRule,
};
pub use receipt::{DecisionReceipt, FinalizationState, ReceiptError, ReceiptMaterial};
pub use shadow::{
    ShadowBatchEvidence, ShadowCaseResult, ShadowDisposition, compare_shadow_case,
    summarize_shadow_batch,
};
