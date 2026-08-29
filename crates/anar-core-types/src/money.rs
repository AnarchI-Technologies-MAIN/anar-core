use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::RegisteredId;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AssetSpec {
    pub asset_id: RegisteredId,
    pub registry_version: u32,
    pub scale: u8,
    pub active: bool,
    pub maximum_minor_units: u128,
}

#[derive(Debug, Clone, Default)]
pub struct AssetRegistry {
    assets: BTreeMap<RegisteredId, AssetSpec>,
}

impl AssetRegistry {
    pub fn insert(&mut self, spec: AssetSpec) -> Result<(), MoneyError> {
        if spec.registry_version == 0 || spec.scale > 38 {
            return Err(MoneyError::InvalidAssetSpec);
        }
        if self.assets.insert(spec.asset_id.clone(), spec).is_some() {
            return Err(MoneyError::DuplicateAsset);
        }
        Ok(())
    }

    pub fn get(&self, asset_id: &RegisteredId) -> Result<&AssetSpec, MoneyError> {
        let spec = self
            .assets
            .get(asset_id)
            .ok_or(MoneyError::UnsupportedAsset)?;
        if !spec.active {
            return Err(MoneyError::InactiveAsset);
        }
        Ok(spec)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MoneyLimit {
    pub asset_id: RegisteredId,
    pub registry_version: u32,
    pub minor_units: u128,
}

impl MoneyLimit {
    pub fn parse(
        registry: &AssetRegistry,
        asset_id: RegisteredId,
        registry_version: u32,
        wire_amount: &str,
    ) -> Result<Self, MoneyError> {
        let spec = registry.get(&asset_id)?;
        if spec.registry_version != registry_version {
            return Err(MoneyError::RegistryVersionMismatch);
        }
        let minor_units = parse_minor_units(wire_amount, spec.scale)?;
        if minor_units > spec.maximum_minor_units {
            return Err(MoneyError::MagnitudeExceeded);
        }
        Ok(Self {
            asset_id,
            registry_version,
            minor_units,
        })
    }
}

fn parse_minor_units(value: &str, scale: u8) -> Result<u128, MoneyError> {
    if value.is_empty() || value.starts_with('+') || value.starts_with('-') {
        return Err(MoneyError::NonCanonicalAmount);
    }
    if !value.is_ascii() {
        return Err(MoneyError::NonCanonicalAmount);
    }
    let (whole, fractional) = match value.split_once('.') {
        Some((whole, fractional)) => {
            if value.matches('.').count() != 1 || scale == 0 || fractional.is_empty() {
                return Err(MoneyError::NonCanonicalAmount);
            }
            (whole, fractional)
        }
        None => (value, ""),
    };
    if whole.is_empty()
        || !whole.bytes().all(|byte| byte.is_ascii_digit())
        || !fractional.bytes().all(|byte| byte.is_ascii_digit())
    {
        return Err(MoneyError::NonCanonicalAmount);
    }
    if whole.len() > 1 && whole.starts_with('0') {
        return Err(MoneyError::NonCanonicalAmount);
    }
    if fractional.len() > usize::from(scale) {
        return Err(MoneyError::ScaleExceeded);
    }
    let whole_units = whole
        .parse::<u128>()
        .map_err(|_| MoneyError::MagnitudeExceeded)?;
    let scale_factor = 10_u128
        .checked_pow(u32::from(scale))
        .ok_or(MoneyError::MagnitudeExceeded)?;
    let padded_fraction = if fractional.is_empty() {
        0
    } else {
        let parsed = fractional
            .parse::<u128>()
            .map_err(|_| MoneyError::MagnitudeExceeded)?;
        let missing = usize::from(scale) - fractional.len();
        parsed
            .checked_mul(
                10_u128
                    .checked_pow(u32::try_from(missing).map_err(|_| MoneyError::MagnitudeExceeded)?)
                    .ok_or(MoneyError::MagnitudeExceeded)?,
            )
            .ok_or(MoneyError::MagnitudeExceeded)?
    };
    whole_units
        .checked_mul(scale_factor)
        .and_then(|units| units.checked_add(padded_fraction))
        .ok_or(MoneyError::MagnitudeExceeded)
}

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum MoneyError {
    #[error("asset specification is invalid")]
    InvalidAssetSpec,
    #[error("asset already exists in this registry")]
    DuplicateAsset,
    #[error("asset is unsupported")]
    UnsupportedAsset,
    #[error("asset is inactive")]
    InactiveAsset,
    #[error("asset registry version does not match")]
    RegistryVersionMismatch,
    #[error("money amount is not canonical non-negative ASCII decimal text")]
    NonCanonicalAmount,
    #[error("money amount has more fractional precision than the registry permits")]
    ScaleExceeded,
    #[error("money amount exceeds the configured exact magnitude")]
    MagnitudeExceeded,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn registry() -> AssetRegistry {
        let mut registry = AssetRegistry::default();
        registry
            .insert(AssetSpec {
                asset_id: RegisteredId::new("iso4217:usd").unwrap(),
                registry_version: 1,
                scale: 2,
                active: true,
                maximum_minor_units: 1_000_000,
            })
            .unwrap();
        registry
    }

    #[test]
    fn exact_amount_is_converted_without_float_or_rounding() {
        let value = MoneyLimit::parse(
            &registry(),
            RegisteredId::new("iso4217:usd").unwrap(),
            1,
            "5000.25",
        )
        .unwrap();
        assert_eq!(value.minor_units, 500_025);
    }

    #[test]
    fn lexical_smuggling_fails_closed() {
        for invalid in [
            "+1.00", "-1.00", "-0", "01.00", "1e3", "1.000", "１.00", "1,00", "",
        ] {
            assert!(
                MoneyLimit::parse(
                    &registry(),
                    RegisteredId::new("iso4217:usd").unwrap(),
                    1,
                    invalid,
                )
                .is_err(),
                "accepted invalid amount {invalid:?}"
            );
        }
    }

    #[test]
    fn registry_identity_and_version_are_mandatory() {
        assert_eq!(
            MoneyLimit::parse(
                &registry(),
                RegisteredId::new("iso4217:usd").unwrap(),
                2,
                "1.00",
            ),
            Err(MoneyError::RegistryVersionMismatch)
        );
    }
}
