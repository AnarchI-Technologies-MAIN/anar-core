#![forbid(unsafe_code)]

pub mod finalizer;
pub mod telemetry;
pub mod vault;

pub use finalizer::{
    AuthorityRuntime, CurrentDependencyState, InternalMutationGrant, MAX_SEQUENCE, MutationEvent,
    RuntimeError, RuntimeState,
};
pub use telemetry::{TelemetryDisposition, TelemetryPseudonymizer};
pub use vault::{
    ConnectionLease, HealthState, LeasedDbCredential, PoolGenerationMetadata, RiskAdmission,
    RotationFailure, RotationSupervisor, SecretBytes, VaultRuntimeError,
};
