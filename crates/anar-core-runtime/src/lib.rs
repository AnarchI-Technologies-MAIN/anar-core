#![forbid(unsafe_code)]

pub mod deferred;
pub mod finalizer;
pub mod telemetry;
pub mod vault;

pub use deferred::{
    AuthorizedDeferredExecution, DeferredError, DeferredIntent, EffectTimeAuthorization,
    OfflineCaptureKind, authorize_deferred_execution, offline_capture_allowed,
};
pub use finalizer::{
    AuthorityRuntime, CurrentDependencyState, InternalMutationGrant, MAX_SEQUENCE, MutationEvent,
    RuntimeError, RuntimeState,
};
pub use telemetry::{TelemetryDisposition, TelemetryPseudonymizer};
pub use vault::{
    ConnectionLease, HealthState, LeasedDbCredential, PoolGenerationMetadata, RiskAdmission,
    RotationFailure, RotationSupervisor, SecretBytes, VaultRuntimeError,
};
