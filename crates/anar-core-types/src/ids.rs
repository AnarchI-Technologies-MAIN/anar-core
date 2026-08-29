use std::{fmt, str::FromStr};

use serde::{Deserialize, Serialize};
use thiserror::Error;

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct StableId([u8; 16]);

impl StableId {
    pub const fn from_bytes(bytes: [u8; 16]) -> Self {
        Self(bytes)
    }

    pub const fn as_bytes(&self) -> &[u8; 16] {
        &self.0
    }

    pub fn canonical(self) -> String {
        let value = hex::encode(self.0);
        format!(
            "{}-{}-{}-{}-{}",
            &value[0..8],
            &value[8..12],
            &value[12..16],
            &value[16..20],
            &value[20..32]
        )
    }
}

impl fmt::Debug for StableId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.canonical())
    }
}

impl fmt::Display for StableId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.canonical())
    }
}

impl FromStr for StableId {
    type Err = IdError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        if value.len() != 36
            || value.as_bytes()[8] != b'-'
            || value.as_bytes()[13] != b'-'
            || value.as_bytes()[18] != b'-'
            || value.as_bytes()[23] != b'-'
        {
            return Err(IdError::InvalidStableId);
        }
        if value.bytes().any(|byte| byte.is_ascii_uppercase()) {
            return Err(IdError::InvalidStableId);
        }
        let compact: String = value
            .chars()
            .filter(|character| *character != '-')
            .collect();
        let decoded = hex::decode(compact).map_err(|_| IdError::InvalidStableId)?;
        let bytes: [u8; 16] = decoded.try_into().map_err(|_| IdError::InvalidStableId)?;
        Ok(Self(bytes))
    }
}

impl Serialize for StableId {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(&self.canonical())
    }
}

impl<'de> Deserialize<'de> for StableId {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        value.parse().map_err(serde::de::Error::custom)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
#[serde(transparent)]
pub struct RegisteredId(String);

impl RegisteredId {
    pub fn new(value: impl Into<String>) -> Result<Self, IdError> {
        let value = value.into();
        if value.is_empty() || value.len() > 128 {
            return Err(IdError::InvalidRegisteredId);
        }
        let mut bytes = value.bytes();
        let first = bytes.next().ok_or(IdError::InvalidRegisteredId)?;
        if !first.is_ascii_lowercase() {
            return Err(IdError::InvalidRegisteredId);
        }
        if !bytes.all(|byte| {
            byte.is_ascii_lowercase()
                || byte.is_ascii_digit()
                || matches!(byte, b'.' | b':' | b'_' | b'-')
        }) {
            return Err(IdError::InvalidRegisteredId);
        }
        Ok(Self(value))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for RegisteredId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

impl<'de> Deserialize<'de> for RegisteredId {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        Self::new(value).map_err(serde::de::Error::custom)
    }
}

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum IdError {
    #[error("stable identifier must be canonical lowercase UUID text")]
    InvalidStableId,
    #[error("registered identifier violates the canonical ASCII grammar")]
    InvalidRegisteredId,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stable_ids_require_canonical_lowercase_text() {
        let value: StableId = "00112233-4455-6677-8899-aabbccddeeff".parse().unwrap();
        assert_eq!(value.canonical(), "00112233-4455-6677-8899-aabbccddeeff");
        assert!(
            "00112233-4455-6677-8899-AABBCCDDEEFF"
                .parse::<StableId>()
                .is_err()
        );
    }

    #[test]
    fn registered_ids_are_lowercase_ascii() {
        assert!(RegisteredId::new("recoveries.notice.send").is_ok());
        assert!(RegisteredId::new("Recoveries.notice.send").is_err());
        assert!(RegisteredId::new("recoveries/notice").is_err());
    }
}
