use std::fmt;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct SemanticDigest([u8; 32]);

impl SemanticDigest {
    pub const ZERO: Self = Self([0_u8; 32]);

    pub const fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    pub fn to_hex(self) -> String {
        hex::encode(self.0)
    }
}

impl fmt::Debug for SemanticDigest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.to_hex())
    }
}

impl fmt::Display for SemanticDigest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.to_hex())
    }
}

impl TryFrom<String> for SemanticDigest {
    type Error = DigestError;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        if value.len() != 64 || value.bytes().any(|byte| byte.is_ascii_uppercase()) {
            return Err(DigestError::InvalidHex);
        }
        let decoded = hex::decode(value).map_err(|_| DigestError::InvalidHex)?;
        let bytes: [u8; 32] = decoded.try_into().map_err(|_| DigestError::InvalidLength)?;
        Ok(Self(bytes))
    }
}

impl From<SemanticDigest> for String {
    fn from(value: SemanticDigest) -> Self {
        value.to_hex()
    }
}

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum DigestError {
    #[error("semantic digest must be lowercase hexadecimal")]
    InvalidHex,
    #[error("semantic digest must contain exactly 32 bytes")]
    InvalidLength,
}

pub fn domain_hash(domain: &str, framed_parts: &[&[u8]]) -> SemanticDigest {
    let mut hasher = Sha256::new();
    frame(&mut hasher, domain.as_bytes());
    for part in framed_parts {
        frame(&mut hasher, part);
    }
    SemanticDigest::from_bytes(hasher.finalize().into())
}

fn frame(hasher: &mut Sha256, bytes: &[u8]) {
    hasher.update((bytes.len() as u64).to_be_bytes());
    hasher.update(bytes);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn domain_and_boundaries_change_digest() {
        let left = domain_hash("A", &[b"ab", b"c"]);
        let right = domain_hash("A", &[b"a", b"bc"]);
        let other_domain = domain_hash("B", &[b"ab", b"c"]);
        assert_ne!(left, right);
        assert_ne!(left, other_domain);
        assert_eq!(left.to_hex().len(), 64);
    }

    #[test]
    fn digest_text_requires_canonical_lowercase_hex() {
        let lower = "ab".repeat(32);
        assert!(SemanticDigest::try_from(lower).is_ok());
        assert!(SemanticDigest::try_from("AB".repeat(32)).is_err());
    }
}
