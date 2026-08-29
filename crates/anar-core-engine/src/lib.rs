#![forbid(unsafe_code)]

pub mod delegation;
pub mod evaluation;
pub mod receipt;

pub use delegation::{
    DelegationEdge, DelegationError, DelegationFrameKey, DelegationGraph, DelegationNodeKey,
};
pub use evaluation::{
    AuthorityContextSnapshot, BindingSnapshot, CandidateDecision, CoreAuthorityState,
    EvaluationInput, GenerationVector, ReasonCode, evaluate,
};
pub use receipt::{DecisionReceipt, FinalizationState, ReceiptError, ReceiptMaterial};
