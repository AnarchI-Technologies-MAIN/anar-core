use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::{MoneyLimit, RegisteredId, SemanticDigest, StableId};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InputLimitsProfile {
    pub max_body_bytes: usize,
    pub max_nesting_depth: usize,
    pub max_key_length_bytes: usize,
    pub max_keys_per_object: usize,
    pub max_total_object_keys: usize,
    pub max_array_length: usize,
    pub max_total_tokens: usize,
    pub max_string_length_bytes: usize,
    pub max_total_string_bytes: usize,
    pub max_numeric_token_length: usize,
    pub max_escape_count: usize,
    pub max_extensions: usize,
    pub max_evidence_refs: usize,
    pub max_resource_refs: usize,
    pub max_constraint_count: usize,
}

impl Default for InputLimitsProfile {
    fn default() -> Self {
        Self {
            max_body_bytes: 64 * 1024,
            max_nesting_depth: 16,
            max_key_length_bytes: 96,
            max_keys_per_object: 64,
            max_total_object_keys: 512,
            max_array_length: 256,
            max_total_tokens: 4096,
            max_string_length_bytes: 4096,
            max_total_string_bytes: 32 * 1024,
            max_numeric_token_length: 48,
            max_escape_count: 512,
            max_extensions: 0,
            max_evidence_refs: 64,
            max_resource_refs: 128,
            max_constraint_count: 16,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CapabilityRef {
    pub id: RegisteredId,
    pub version: u32,
    pub cal_semantic_hash: SemanticDigest,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "SCREAMING_SNAKE_CASE", deny_unknown_fields)]
pub enum ResourceScopeRequest {
    ExplicitSet { resources: Vec<RegisteredId> },
    Hierarchy { segments: Vec<RegisteredId> },
}

impl ResourceScopeRequest {
    fn cardinality(&self) -> usize {
        match self {
            Self::ExplicitSet { resources } => resources.len(),
            Self::Hierarchy { segments } => segments.len(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EffectScopeRequest {
    pub classes: Vec<RegisteredId>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MoneyConstraintRequest {
    pub asset_id: RegisteredId,
    pub registry_version: u32,
    pub maximum: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ConstraintSet {
    pub max_uses: Option<u64>,
    pub financial: Option<MoneyConstraintRequest>,
    pub expires_at_epoch_ms: Option<i64>,
    pub delegation_allowed: bool,
    pub max_delegation_depth: u16,
}

impl ConstraintSet {
    fn populated_count(&self) -> usize {
        usize::from(self.max_uses.is_some())
            + usize::from(self.financial.is_some())
            + usize::from(self.expires_at_epoch_ms.is_some())
            + usize::from(self.delegation_allowed)
            + usize::from(self.max_delegation_depth != 0)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EvidenceRef {
    pub assertion_id: StableId,
    pub object_digest: SemanticDigest,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NormalizedCapabilityRequest {
    pub authority_context_id: StableId,
    pub organization_id: StableId,
    pub purpose: RegisteredId,
    pub capability: CapabilityRef,
    pub resource_scope: ResourceScopeRequest,
    pub effect_scope: EffectScopeRequest,
    pub constraints: ConstraintSet,
    pub evidence_refs: Vec<EvidenceRef>,
}

impl NormalizedCapabilityRequest {
    pub fn parse_money(
        &self,
        registry: &crate::AssetRegistry,
    ) -> Result<Option<MoneyLimit>, crate::MoneyError> {
        self.constraints
            .financial
            .as_ref()
            .map(|request| {
                MoneyLimit::parse(
                    registry,
                    request.asset_id.clone(),
                    request.registry_version,
                    &request.maximum,
                )
            })
            .transpose()
    }
}

pub fn parse_authority_request(
    raw: &[u8],
    limits: &InputLimitsProfile,
) -> Result<NormalizedCapabilityRequest, AuthorityInputError> {
    validate_bounded_json(raw, limits)?;
    let request: NormalizedCapabilityRequest =
        serde_json::from_slice(raw).map_err(|_| AuthorityInputError::TypedDecodeFailed)?;
    if request.capability.version == 0
        || request.resource_scope.cardinality() > limits.max_resource_refs
        || request.effect_scope.classes.len() > limits.max_resource_refs
        || request.evidence_refs.len() > limits.max_evidence_refs
        || request.constraints.populated_count() > limits.max_constraint_count
    {
        return Err(AuthorityInputError::SemanticLimitExceeded);
    }
    if request.constraints.max_delegation_depth > 0 && !request.constraints.delegation_allowed {
        return Err(AuthorityInputError::SemanticValidationFailed);
    }
    Ok(request)
}

pub fn validate_bounded_json(
    raw: &[u8],
    limits: &InputLimitsProfile,
) -> Result<(), AuthorityInputError> {
    if raw.len() > limits.max_body_bytes {
        return Err(AuthorityInputError::BodyLimitExceeded);
    }
    std::str::from_utf8(raw).map_err(|_| AuthorityInputError::InvalidUtf8)?;
    let mut scanner = Scanner {
        raw,
        limits,
        position: 0,
        total_tokens: 0,
        total_keys: 0,
        total_string_bytes: 0,
        total_escapes: 0,
    };
    scanner.skip_whitespace();
    scanner.parse_value(0)?;
    scanner.skip_whitespace();
    if scanner.position != raw.len() {
        return Err(AuthorityInputError::MalformedJson);
    }
    Ok(())
}

struct Scanner<'a> {
    raw: &'a [u8],
    limits: &'a InputLimitsProfile,
    position: usize,
    total_tokens: usize,
    total_keys: usize,
    total_string_bytes: usize,
    total_escapes: usize,
}

impl Scanner<'_> {
    fn parse_value(&mut self, depth: usize) -> Result<(), AuthorityInputError> {
        self.increment_token()?;
        self.skip_whitespace();
        match self.peek().ok_or(AuthorityInputError::MalformedJson)? {
            b'{' => self.parse_object(depth + 1),
            b'[' => self.parse_array(depth + 1),
            b'"' => self.parse_string(false).map(|_| ()),
            b't' => self.consume_literal(b"true"),
            b'f' => self.consume_literal(b"false"),
            b'n' => self.consume_literal(b"null"),
            b'-' | b'0'..=b'9' => self.parse_number(),
            _ => Err(AuthorityInputError::MalformedJson),
        }
    }

    fn parse_object(&mut self, depth: usize) -> Result<(), AuthorityInputError> {
        self.check_depth(depth)?;
        self.position += 1;
        self.skip_whitespace();
        let mut keys = BTreeSet::<Vec<u8>>::new();
        if self.consume_if(b'}') {
            return Ok(());
        }
        loop {
            if self.peek() != Some(b'"') {
                return Err(AuthorityInputError::MalformedJson);
            }
            let key = self.parse_string(true)?;
            if !canonical_core_key(&key) {
                return Err(AuthorityInputError::NonCanonicalField);
            }
            if !keys.insert(key) {
                return Err(AuthorityInputError::DuplicateField);
            }
            self.total_keys = self
                .total_keys
                .checked_add(1)
                .ok_or(AuthorityInputError::InputLimitExceeded)?;
            if keys.len() > self.limits.max_keys_per_object
                || self.total_keys > self.limits.max_total_object_keys
            {
                return Err(AuthorityInputError::InputLimitExceeded);
            }
            self.skip_whitespace();
            self.require_byte(b':')?;
            self.parse_value(depth)?;
            self.skip_whitespace();
            if self.consume_if(b'}') {
                return Ok(());
            }
            self.require_byte(b',')?;
            self.skip_whitespace();
        }
    }

    fn parse_array(&mut self, depth: usize) -> Result<(), AuthorityInputError> {
        self.check_depth(depth)?;
        self.position += 1;
        self.skip_whitespace();
        if self.consume_if(b']') {
            return Ok(());
        }
        let mut count = 0_usize;
        loop {
            count = count
                .checked_add(1)
                .ok_or(AuthorityInputError::InputLimitExceeded)?;
            if count > self.limits.max_array_length {
                return Err(AuthorityInputError::InputLimitExceeded);
            }
            self.parse_value(depth)?;
            self.skip_whitespace();
            if self.consume_if(b']') {
                return Ok(());
            }
            self.require_byte(b',')?;
            self.skip_whitespace();
        }
    }

    fn parse_string(&mut self, key: bool) -> Result<Vec<u8>, AuthorityInputError> {
        self.require_byte(b'"')?;
        let start = self.position;
        let mut decoded = Vec::new();
        let raw_limit = if key {
            self.limits.max_key_length_bytes
        } else {
            self.limits.max_string_length_bytes
        };
        loop {
            let byte = self.peek().ok_or(AuthorityInputError::MalformedJson)?;
            if byte == b'"' {
                self.position += 1;
                break;
            }
            if self.position - start > raw_limit {
                return Err(AuthorityInputError::InputLimitExceeded);
            }
            match byte {
                0x00..=0x1f => return Err(AuthorityInputError::MalformedJson),
                b'\\' => {
                    self.position += 1;
                    self.total_escapes = self
                        .total_escapes
                        .checked_add(1)
                        .ok_or(AuthorityInputError::InputLimitExceeded)?;
                    if self.total_escapes > self.limits.max_escape_count {
                        return Err(AuthorityInputError::InputLimitExceeded);
                    }
                    self.decode_escape(&mut decoded)?;
                }
                0x20..=0x7f => {
                    decoded.push(byte);
                    self.position += 1;
                }
                _ => {
                    let remaining = std::str::from_utf8(&self.raw[self.position..])
                        .map_err(|_| AuthorityInputError::InvalidUtf8)?;
                    let character = remaining
                        .chars()
                        .next()
                        .ok_or(AuthorityInputError::MalformedJson)?;
                    let length = character.len_utf8();
                    decoded.extend_from_slice(&self.raw[self.position..self.position + length]);
                    self.position += length;
                }
            }
            let maximum = if key {
                self.limits.max_key_length_bytes
            } else {
                self.limits.max_string_length_bytes
            };
            if decoded.len() > maximum {
                return Err(AuthorityInputError::InputLimitExceeded);
            }
        }
        let raw_length = self
            .position
            .checked_sub(start + 1)
            .ok_or(AuthorityInputError::MalformedJson)?;
        if raw_length > raw_limit {
            return Err(AuthorityInputError::InputLimitExceeded);
        }
        self.total_string_bytes = self
            .total_string_bytes
            .checked_add(decoded.len())
            .ok_or(AuthorityInputError::InputLimitExceeded)?;
        if self.total_string_bytes > self.limits.max_total_string_bytes {
            return Err(AuthorityInputError::InputLimitExceeded);
        }
        Ok(decoded)
    }

    fn decode_escape(&mut self, output: &mut Vec<u8>) -> Result<(), AuthorityInputError> {
        let escaped = self.next().ok_or(AuthorityInputError::MalformedJson)?;
        match escaped {
            b'"' | b'\\' | b'/' => output.push(escaped),
            b'b' => output.push(0x08),
            b'f' => output.push(0x0c),
            b'n' => output.push(b'\n'),
            b'r' => output.push(b'\r'),
            b't' => output.push(b'\t'),
            b'u' => {
                let first = self.read_hex_quad()?;
                let code_point = if (0xd800..=0xdbff).contains(&first) {
                    if self.next() != Some(b'\\') || self.next() != Some(b'u') {
                        return Err(AuthorityInputError::MalformedJson);
                    }
                    let second = self.read_hex_quad()?;
                    if !(0xdc00..=0xdfff).contains(&second) {
                        return Err(AuthorityInputError::MalformedJson);
                    }
                    0x10000 + ((u32::from(first) - 0xd800) << 10) + (u32::from(second) - 0xdc00)
                } else if (0xdc00..=0xdfff).contains(&first) {
                    return Err(AuthorityInputError::MalformedJson);
                } else {
                    u32::from(first)
                };
                let character =
                    char::from_u32(code_point).ok_or(AuthorityInputError::MalformedJson)?;
                let mut buffer = [0_u8; 4];
                output.extend_from_slice(character.encode_utf8(&mut buffer).as_bytes());
            }
            _ => return Err(AuthorityInputError::MalformedJson),
        }
        Ok(())
    }

    fn read_hex_quad(&mut self) -> Result<u16, AuthorityInputError> {
        let mut value = 0_u16;
        for _ in 0..4 {
            let byte = self.next().ok_or(AuthorityInputError::MalformedJson)?;
            let digit = match byte {
                b'0'..=b'9' => u16::from(byte - b'0'),
                b'a'..=b'f' => u16::from(byte - b'a' + 10),
                b'A'..=b'F' => u16::from(byte - b'A' + 10),
                _ => return Err(AuthorityInputError::MalformedJson),
            };
            value = value * 16 + digit;
        }
        Ok(value)
    }

    fn parse_number(&mut self) -> Result<(), AuthorityInputError> {
        let start = self.position;
        self.consume_if(b'-');
        match self.next().ok_or(AuthorityInputError::MalformedJson)? {
            b'0' => {
                if self.peek().is_some_and(|byte| byte.is_ascii_digit()) {
                    return Err(AuthorityInputError::MalformedJson);
                }
            }
            b'1'..=b'9' => {
                while self.peek().is_some_and(|byte| byte.is_ascii_digit()) {
                    self.position += 1;
                }
            }
            _ => return Err(AuthorityInputError::MalformedJson),
        }
        if self.consume_if(b'.') {
            let fraction_start = self.position;
            while self.peek().is_some_and(|byte| byte.is_ascii_digit()) {
                self.position += 1;
            }
            if self.position == fraction_start {
                return Err(AuthorityInputError::MalformedJson);
            }
        }
        if self.peek().is_some_and(|byte| matches!(byte, b'e' | b'E')) {
            self.position += 1;
            if self.peek().is_some_and(|byte| matches!(byte, b'+' | b'-')) {
                self.position += 1;
            }
            let exponent_start = self.position;
            while self.peek().is_some_and(|byte| byte.is_ascii_digit()) {
                self.position += 1;
            }
            if self.position == exponent_start {
                return Err(AuthorityInputError::MalformedJson);
            }
        }
        if self.position - start > self.limits.max_numeric_token_length {
            return Err(AuthorityInputError::InputLimitExceeded);
        }
        Ok(())
    }

    fn consume_literal(&mut self, literal: &[u8]) -> Result<(), AuthorityInputError> {
        if self.raw.get(self.position..self.position + literal.len()) != Some(literal) {
            return Err(AuthorityInputError::MalformedJson);
        }
        self.position += literal.len();
        Ok(())
    }

    fn check_depth(&self, depth: usize) -> Result<(), AuthorityInputError> {
        if depth > self.limits.max_nesting_depth {
            Err(AuthorityInputError::InputLimitExceeded)
        } else {
            Ok(())
        }
    }

    fn increment_token(&mut self) -> Result<(), AuthorityInputError> {
        self.total_tokens = self
            .total_tokens
            .checked_add(1)
            .ok_or(AuthorityInputError::InputLimitExceeded)?;
        if self.total_tokens > self.limits.max_total_tokens {
            Err(AuthorityInputError::InputLimitExceeded)
        } else {
            Ok(())
        }
    }

    fn skip_whitespace(&mut self) {
        while self
            .peek()
            .is_some_and(|byte| matches!(byte, b' ' | b'\n' | b'\r' | b'\t'))
        {
            self.position += 1;
        }
    }

    fn require_byte(&mut self, expected: u8) -> Result<(), AuthorityInputError> {
        if self.next() == Some(expected) {
            Ok(())
        } else {
            Err(AuthorityInputError::MalformedJson)
        }
    }

    fn consume_if(&mut self, expected: u8) -> bool {
        if self.peek() == Some(expected) {
            self.position += 1;
            true
        } else {
            false
        }
    }

    fn peek(&self) -> Option<u8> {
        self.raw.get(self.position).copied()
    }

    fn next(&mut self) -> Option<u8> {
        let value = self.peek()?;
        self.position += 1;
        Some(value)
    }
}

fn canonical_core_key(key: &[u8]) -> bool {
    let Some(first) = key.first() else {
        return false;
    };
    first.is_ascii_alphabetic()
        && key
            .iter()
            .skip(1)
            .all(|byte| byte.is_ascii_alphanumeric() || *byte == b'_')
}

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum AuthorityInputError {
    #[error("authority request body exceeds the configured byte limit")]
    BodyLimitExceeded,
    #[error("authority request is not valid UTF-8")]
    InvalidUtf8,
    #[error("authority request exceeds a structural input budget")]
    InputLimitExceeded,
    #[error("authority request contains a duplicate decoded field name")]
    DuplicateField,
    #[error("authority request contains a non-canonical field name")]
    NonCanonicalField,
    #[error("authority request contains malformed JSON")]
    MalformedJson,
    #[error("authority request does not match the typed schema")]
    TypedDecodeFailed,
    #[error("authority request exceeds a semantic collection limit")]
    SemanticLimitExceeded,
    #[error("authority request violates a typed semantic invariant")]
    SemanticValidationFailed,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn request() -> Vec<u8> {
        br#"{
          "authority_context_id":"00112233-4455-6677-8899-aabbccddeeff",
          "organization_id":"10112233-4455-6677-8899-aabbccddeeff",
          "purpose":"recoveries.notice",
          "capability":{"id":"recoveries.notice.send","version":1,"cal_semantic_hash":"0000000000000000000000000000000000000000000000000000000000000000"},
          "resource_scope":{"kind":"EXPLICIT_SET","resources":["recovery:opp_123"]},
          "effect_scope":{"classes":["external.communication"]},
          "constraints":{"max_uses":1,"financial":{"asset_id":"iso4217:usd","registry_version":1,"maximum":"500.00"},"expires_at_epoch_ms":200,"delegation_allowed":false,"max_delegation_depth":0},
          "evidence_refs":[]
        }"#
        .to_vec()
    }

    #[test]
    fn typed_request_is_parsed_once_after_bounded_scan() {
        let parsed = parse_authority_request(&request(), &InputLimitsProfile::default()).unwrap();
        assert_eq!(parsed.capability.id.as_str(), "recoveries.notice.send");
        assert_eq!(parsed.resource_scope.cardinality(), 1);
    }

    #[test]
    fn duplicate_escape_decoded_key_is_rejected() {
        let raw = br#"{"a":1,"\u0061":2}"#;
        assert_eq!(
            validate_bounded_json(raw, &InputLimitsProfile::default()),
            Err(AuthorityInputError::DuplicateField)
        );
    }

    #[test]
    fn duplicate_tracking_is_object_scoped() {
        let raw = br#"{"left":{"value":1},"right":{"value":2}}"#;
        validate_bounded_json(raw, &InputLimitsProfile::default()).unwrap();
    }

    #[test]
    fn surrogate_pair_is_decoded_but_non_ascii_core_key_is_rejected() {
        let raw = br#"{"\ud83d\ude00":1}"#;
        assert_eq!(
            validate_bounded_json(raw, &InputLimitsProfile::default()),
            Err(AuthorityInputError::NonCanonicalField)
        );
    }

    #[test]
    fn unknown_typed_field_fails_closed() {
        let mut raw = String::from_utf8(request()).unwrap();
        raw = raw.replacen(
            "\"evidence_refs\":[]",
            "\"evidence_refs\":[],\"ambient_admin\":true",
            1,
        );
        assert_eq!(
            parse_authority_request(raw.as_bytes(), &InputLimitsProfile::default()),
            Err(AuthorityInputError::TypedDecodeFailed)
        );
    }

    #[test]
    fn body_depth_key_array_and_token_budgets_fail_closed() {
        let limits = InputLimitsProfile {
            max_body_bytes: 4,
            ..InputLimitsProfile::default()
        };
        assert_eq!(
            validate_bounded_json(br#"{"a":1}"#, &limits),
            Err(AuthorityInputError::BodyLimitExceeded)
        );

        let limits = InputLimitsProfile {
            max_nesting_depth: 1,
            ..InputLimitsProfile::default()
        };
        assert_eq!(
            validate_bounded_json(br#"{"a":{"b":1}}"#, &limits),
            Err(AuthorityInputError::InputLimitExceeded)
        );

        let limits = InputLimitsProfile {
            max_key_length_bytes: 2,
            ..InputLimitsProfile::default()
        };
        assert_eq!(
            validate_bounded_json(br#"{"long":1}"#, &limits),
            Err(AuthorityInputError::InputLimitExceeded)
        );

        let limits = InputLimitsProfile {
            max_array_length: 1,
            ..InputLimitsProfile::default()
        };
        assert_eq!(
            validate_bounded_json(br#"[1,2]"#, &limits),
            Err(AuthorityInputError::InputLimitExceeded)
        );

        let limits = InputLimitsProfile {
            max_escape_count: 1,
            ..InputLimitsProfile::default()
        };
        assert_eq!(
            validate_bounded_json(br#"{"a":"\u0061\u0062"}"#, &limits),
            Err(AuthorityInputError::InputLimitExceeded)
        );

        let limits = InputLimitsProfile {
            max_key_length_bytes: 2,
            ..InputLimitsProfile::default()
        };
        assert_eq!(
            validate_bounded_json(br#"{"\u0061":1}"#, &limits),
            Err(AuthorityInputError::InputLimitExceeded)
        );

        let limits = InputLimitsProfile {
            max_total_tokens: 2,
            ..InputLimitsProfile::default()
        };
        assert_eq!(
            validate_bounded_json(br#"[1,2]"#, &limits),
            Err(AuthorityInputError::InputLimitExceeded)
        );
    }

    #[test]
    fn unfinished_structures_and_stack_underflow_fail_closed() {
        for malformed in [
            br#"{"a":1"#.as_slice(),
            br#"[1,2"#.as_slice(),
            br#"}"#.as_slice(),
        ] {
            assert!(validate_bounded_json(malformed, &InputLimitsProfile::default()).is_err());
        }
    }
}
