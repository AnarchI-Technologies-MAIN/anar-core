use std::fmt;

use anar_core_types::RiskTier;
use thiserror::Error;

pub struct SecretBytes(Vec<u8>);

impl SecretBytes {
    pub fn new(value: Vec<u8>) -> Result<Self, VaultRuntimeError> {
        if value.is_empty() {
            return Err(VaultRuntimeError::InvalidCredential);
        }
        Ok(Self(value))
    }

    pub fn expose_to_pool_builder(&self) -> &[u8] {
        &self.0
    }
}

impl fmt::Debug for SecretBytes {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("SecretBytes([REDACTED])")
    }
}

impl Drop for SecretBytes {
    fn drop(&mut self) {
        self.0.fill(0);
    }
}

pub struct LeasedDbCredential {
    pub username: String,
    pub password: SecretBytes,
    pub lease_id: String,
    pub renewable: bool,
    pub acquired_at_epoch_ms: i64,
    pub rotate_after_epoch_ms: i64,
    pub hard_expiry_epoch_ms: i64,
}

impl LeasedDbCredential {
    pub fn validate(&self) -> Result<(), VaultRuntimeError> {
        if self.username.is_empty()
            || self.lease_id.is_empty()
            || self.password.expose_to_pool_builder().is_empty()
            || self.acquired_at_epoch_ms >= self.rotate_after_epoch_ms
            || self.rotate_after_epoch_ms >= self.hard_expiry_epoch_ms
        {
            return Err(VaultRuntimeError::InvalidCredential);
        }
        Ok(())
    }
}

impl fmt::Debug for LeasedDbCredential {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("LeasedDbCredential")
            .field("username", &"[REDACTED]")
            .field("password", &"[REDACTED]")
            .field("lease_id", &self.lease_id)
            .field("renewable", &self.renewable)
            .field("acquired_at_epoch_ms", &self.acquired_at_epoch_ms)
            .field("rotate_after_epoch_ms", &self.rotate_after_epoch_ms)
            .field("hard_expiry_epoch_ms", &self.hard_expiry_epoch_ms)
            .finish()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HealthState {
    Ready,
    Degraded,
    Draining,
    NotReady,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PoolGenerationState {
    Active,
    Draining,
    Closed,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PoolGenerationMetadata {
    pub generation_id: u64,
    pub lease_id: String,
    pub renewable: bool,
    pub activated_at_epoch_ms: i64,
    pub rotate_after_epoch_ms: i64,
    pub hard_expiry_epoch_ms: i64,
    pub state: PoolGenerationState,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RotationFailure {
    VaultFetch,
    PoolBuild,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RiskAdmission {
    Admitted,
    RejectedUnavailable,
    RejectedDeadline,
}

#[derive(Debug, PartialEq, Eq)]
pub struct ConnectionLease {
    pub generation_id: u64,
    pub lease_id: String,
    pub credential_hard_expiry_epoch_ms: i64,
    pub operation_deadline_epoch_ms: i64,
}

#[derive(Debug)]
pub struct RotationSupervisor {
    active: Option<PoolGenerationMetadata>,
    draining: Vec<PoolGenerationMetadata>,
    health: HealthState,
    next_generation: u64,
    safety_margin_ms: i64,
}

impl RotationSupervisor {
    pub fn new(safety_margin_ms: i64) -> Result<Self, VaultRuntimeError> {
        if safety_margin_ms <= 0 {
            return Err(VaultRuntimeError::InvalidSafetyMargin);
        }
        Ok(Self {
            active: None,
            draining: Vec::new(),
            health: HealthState::NotReady,
            next_generation: 1,
            safety_margin_ms,
        })
    }

    pub fn activate_initial(
        &mut self,
        credential: &LeasedDbCredential,
        now_epoch_ms: i64,
    ) -> Result<(), VaultRuntimeError> {
        if self.active.is_some() {
            return Err(VaultRuntimeError::GenerationAlreadyActive);
        }
        let generation = self.generation_from(credential, now_epoch_ms)?;
        self.active = Some(generation);
        self.health = HealthState::Ready;
        Ok(())
    }

    pub fn rotation_succeeded(
        &mut self,
        credential: &LeasedDbCredential,
        now_epoch_ms: i64,
    ) -> Result<(), VaultRuntimeError> {
        let next = self.generation_from(credential, now_epoch_ms)?;
        if let Some(mut old) = self.active.replace(next) {
            old.state = PoolGenerationState::Draining;
            self.draining.push(old);
        }
        self.health = HealthState::Ready;
        Ok(())
    }

    pub fn rotation_failed(&mut self, _failure: RotationFailure, now_epoch_ms: i64) -> HealthState {
        self.health = match self.active.as_ref() {
            None => HealthState::NotReady,
            Some(active) if now_epoch_ms >= active.hard_expiry_epoch_ms => HealthState::NotReady,
            Some(active)
                if now_epoch_ms
                    >= active
                        .hard_expiry_epoch_ms
                        .saturating_sub(self.safety_margin_ms) =>
            {
                HealthState::Draining
            }
            Some(_) => HealthState::Degraded,
        };
        self.health
    }

    pub fn next_retry_at(&self, now_epoch_ms: i64, backoff_ms: i64) -> Option<i64> {
        let active = self.active.as_ref()?;
        if backoff_ms <= 0 || now_epoch_ms >= active.hard_expiry_epoch_ms {
            return None;
        }
        Some(
            now_epoch_ms
                .saturating_add(backoff_ms)
                .min(active.hard_expiry_epoch_ms.saturating_sub(1)),
        )
    }

    pub fn acquire(
        &self,
        _risk_tier: RiskTier,
        operation_deadline_epoch_ms: i64,
    ) -> Result<ConnectionLease, RiskAdmission> {
        if matches!(self.health, HealthState::Draining | HealthState::NotReady) {
            return Err(RiskAdmission::RejectedUnavailable);
        }
        let active = self
            .active
            .as_ref()
            .ok_or(RiskAdmission::RejectedUnavailable)?;
        let safe_deadline = active
            .hard_expiry_epoch_ms
            .saturating_sub(self.safety_margin_ms);
        if operation_deadline_epoch_ms > safe_deadline {
            return Err(RiskAdmission::RejectedDeadline);
        }
        Ok(ConnectionLease {
            generation_id: active.generation_id,
            lease_id: active.lease_id.clone(),
            credential_hard_expiry_epoch_ms: active.hard_expiry_epoch_ms,
            operation_deadline_epoch_ms,
        })
    }

    pub fn hard_drain(&mut self, now_epoch_ms: i64) {
        for generation in &mut self.draining {
            if now_epoch_ms >= generation.hard_expiry_epoch_ms {
                generation.state = PoolGenerationState::Closed;
            }
        }
        if self
            .active
            .as_ref()
            .is_some_and(|active| now_epoch_ms >= active.hard_expiry_epoch_ms)
        {
            if let Some(mut expired) = self.active.take() {
                expired.state = PoolGenerationState::Closed;
                self.draining.push(expired);
            }
            self.health = HealthState::NotReady;
        }
    }

    pub const fn health(&self) -> HealthState {
        self.health
    }

    pub fn active(&self) -> Option<&PoolGenerationMetadata> {
        self.active.as_ref()
    }

    pub fn draining(&self) -> &[PoolGenerationMetadata] {
        &self.draining
    }

    fn generation_from(
        &mut self,
        credential: &LeasedDbCredential,
        now_epoch_ms: i64,
    ) -> Result<PoolGenerationMetadata, VaultRuntimeError> {
        credential.validate()?;
        if now_epoch_ms < credential.acquired_at_epoch_ms
            || now_epoch_ms >= credential.hard_expiry_epoch_ms
        {
            return Err(VaultRuntimeError::CredentialOutsideValidity);
        }
        let generation_id = self.next_generation;
        self.next_generation = self
            .next_generation
            .checked_add(1)
            .ok_or(VaultRuntimeError::GenerationExhausted)?;
        Ok(PoolGenerationMetadata {
            generation_id,
            lease_id: credential.lease_id.clone(),
            renewable: credential.renewable,
            activated_at_epoch_ms: now_epoch_ms,
            rotate_after_epoch_ms: credential.rotate_after_epoch_ms,
            hard_expiry_epoch_ms: credential.hard_expiry_epoch_ms,
            state: PoolGenerationState::Active,
        })
    }
}

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum VaultRuntimeError {
    #[error("leased database credential metadata is invalid")]
    InvalidCredential,
    #[error("credential is outside its absolute validity interval")]
    CredentialOutsideValidity,
    #[error("a pool generation is already active")]
    GenerationAlreadyActive,
    #[error("pool generation counter is exhausted")]
    GenerationExhausted,
    #[error("safety margin must be positive")]
    InvalidSafetyMargin,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn credential(lease: &str, rotate: i64, expiry: i64) -> LeasedDbCredential {
        LeasedDbCredential {
            username: "v-lease-user".to_owned(),
            password: SecretBytes::new(b"never-log-this".to_vec()).unwrap(),
            lease_id: lease.to_owned(),
            renewable: false,
            acquired_at_epoch_ms: 100,
            rotate_after_epoch_ms: rotate,
            hard_expiry_epoch_ms: expiry,
        }
    }

    #[test]
    fn secret_debug_output_is_redacted() {
        let value = credential("lease-1", 200, 300);
        let rendered = format!("{value:?}");
        assert!(!rendered.contains("never-log-this"));
        assert!(!rendered.contains("v-lease-user"));
    }

    #[test]
    fn every_rotation_uses_new_absolute_lease_deadlines() {
        let mut supervisor = RotationSupervisor::new(10).unwrap();
        supervisor
            .activate_initial(&credential("lease-1", 200, 300), 150)
            .unwrap();
        supervisor
            .rotation_succeeded(&credential("lease-2", 450, 700), 250)
            .unwrap();
        let active = supervisor.active().unwrap();
        assert_eq!(active.lease_id, "lease-2");
        assert_eq!(active.rotate_after_epoch_ms, 450);
        assert_eq!(active.hard_expiry_epoch_ms, 700);
        assert_eq!(supervisor.draining()[0].lease_id, "lease-1");
    }

    #[test]
    fn vault_and_pool_build_failures_share_deadline_state_machine() {
        for failure in [RotationFailure::VaultFetch, RotationFailure::PoolBuild] {
            let mut supervisor = RotationSupervisor::new(20).unwrap();
            supervisor
                .activate_initial(&credential("lease-1", 200, 300), 150)
                .unwrap();
            assert_eq!(
                supervisor.rotation_failed(failure, 210),
                HealthState::Degraded
            );
            assert_eq!(
                supervisor.rotation_failed(failure, 285),
                HealthState::Draining
            );
            assert_eq!(
                supervisor.rotation_failed(failure, 300),
                HealthState::NotReady
            );
        }
    }

    #[test]
    fn retry_and_operation_deadlines_never_cross_hard_expiry() {
        let mut supervisor = RotationSupervisor::new(20).unwrap();
        supervisor
            .activate_initial(&credential("lease-1", 200, 300), 150)
            .unwrap();
        assert_eq!(supervisor.next_retry_at(290, 100), Some(299));
        assert!(supervisor.acquire(RiskTier::Critical, 280).is_ok());
        assert_eq!(
            supervisor.acquire(RiskTier::Critical, 281),
            Err(RiskAdmission::RejectedDeadline)
        );
        supervisor.hard_drain(300);
        assert_eq!(supervisor.health(), HealthState::NotReady);
        assert_eq!(
            supervisor.acquire(RiskTier::Low, 250),
            Err(RiskAdmission::RejectedUnavailable)
        );
    }
}
