from __future__ import annotations

import hashlib
import json
import re
import unicodedata
from dataclasses import dataclass
from typing import Any, Mapping


class ContractError(ValueError):
    pass


class BoundaryMismatch(ContractError):
    pass


_TYPED_ID = re.compile(r"^[a-z][a-z0-9]{1,15}_[0-9a-f]{32}$")
_SYMBOL = re.compile(r"^[a-z0-9][a-z0-9._:-]{0,127}$")


def validate_typed_id(value: str, expected_prefix: str | None = None) -> str:
    normalized = str(value or "").strip().lower()

    if not _TYPED_ID.fullmatch(normalized):
        raise ContractError(f"invalid typed identifier: {value!r}")

    if expected_prefix is not None:
        prefix = normalized.split("_", 1)[0]
        if prefix != expected_prefix:
            raise ContractError(
                f"identifier prefix mismatch: expected {expected_prefix!r}, got {prefix!r}"
            )

    return normalized


def normalize_symbol(value: str) -> str:
    normalized = unicodedata.normalize("NFKC", str(value or "")).strip().lower()

    if not _SYMBOL.fullmatch(normalized):
        raise ContractError(f"invalid canonical symbol: {value!r}")

    return normalized


def canonical_json(value: Any) -> str:
    try:
        return json.dumps(
            value,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
            allow_nan=False,
        )
    except (TypeError, ValueError) as exc:
        raise ContractError("value is not canonical JSON") from exc


def _require_positive_integer(value: Any, label: str) -> int:
    if type(value) is not int or value < 1:
        raise ContractError(f"{label} must be a positive integer")

    return value


@dataclass(frozen=True)
class VersionedDefinitionRef:
    definition_id: str
    version: int

    def __post_init__(self) -> None:
        validate_typed_id(self.definition_id)
        _require_positive_integer(self.version, "definition version")


@dataclass(frozen=True)
class MembershipProjection:
    membership_id: str
    identity_id: str
    organization_id: str
    tenant_id: str
    status: str
    authorization_version: int
    entitlement_version: int

    def __post_init__(self) -> None:
        validate_typed_id(self.membership_id, "mbr")
        validate_typed_id(self.identity_id, "idn")
        validate_typed_id(self.organization_id, "org")
        validate_typed_id(self.tenant_id, "tnt")
        normalize_symbol(self.status)

        _require_positive_integer(
            self.authorization_version,
            "authorization version",
        )
        _require_positive_integer(
            self.entitlement_version,
            "entitlement version",
        )


@dataclass(frozen=True)
class AdapterGrantBinding:
    binding_id: str
    identity_id: str
    account_id: str
    organization_id: str
    tenant_id: str
    session_id: str
    adapter_definition_id: str
    operation_definition_id: str
    entitlement_definition_id: str
    entitlement_definition_version: int
    resource_scope_json: str
    authorization_version: int
    entitlement_version: int
    policy_definition_id: str
    policy_definition_version: int
    policy_version: str
    status: str

    def __post_init__(self) -> None:
        validate_typed_id(self.binding_id, "bnd")
        validate_typed_id(self.identity_id, "idn")
        validate_typed_id(self.account_id, "act")
        validate_typed_id(self.organization_id, "org")
        validate_typed_id(self.tenant_id, "tnt")
        validate_typed_id(self.session_id, "ses")
        validate_typed_id(self.adapter_definition_id, "adp")
        validate_typed_id(self.operation_definition_id, "opn")
        validate_typed_id(self.entitlement_definition_id, "ent")

        _require_positive_integer(
            self.entitlement_definition_version,
            "entitlement definition version",
        )

        validate_typed_id(self.policy_definition_id, "pol")

        _require_positive_integer(
            self.policy_definition_version,
            "policy definition version",
        )

        normalize_symbol(self.policy_version)
        normalize_symbol(self.status)

        parsed = json.loads(self.resource_scope_json)
        if canonical_json(parsed) != self.resource_scope_json:
            raise ContractError("resource scope must use canonical JSON")

        _require_positive_integer(
            self.authorization_version,
            "authorization version",
        )
        _require_positive_integer(
            self.entitlement_version,
            "entitlement version",
        )

    def agreement_document(self) -> Mapping[str, Any]:
        return {
            "identityId": self.identity_id,
            "accountId": self.account_id,
            "organizationId": self.organization_id,
            "tenantId": self.tenant_id,
            "sessionId": self.session_id,
            "adapterDefinitionId": self.adapter_definition_id,
            "operationDefinitionId": self.operation_definition_id,
            "entitlementDefinitionId": self.entitlement_definition_id,
            "entitlementDefinitionVersion": self.entitlement_definition_version,
            "resourceScope": json.loads(self.resource_scope_json),
            "authorizationVersion": self.authorization_version,
            "entitlementVersion": self.entitlement_version,
            "policyDefinitionId": self.policy_definition_id,
            "policyDefinitionVersion": self.policy_definition_version,
            "status": self.status,
        }

    def agreement_digest(self) -> str:
        encoded = canonical_json(self.agreement_document()).encode("utf-8")
        return hashlib.sha256(encoded).hexdigest()


def assert_boundary_agreement(
    core_binding: AdapterGrantBinding,
    broker_binding: AdapterGrantBinding,
) -> None:
    core_document = canonical_json(core_binding.agreement_document())
    broker_document = canonical_json(broker_binding.agreement_document())

    if core_document != broker_document:
        raise BoundaryMismatch("Anar-Core/Broker normalized authority boundary mismatch")


@dataclass(frozen=True)
class AuthorizedSubject:
    identity_id: str
    account_id: str
    organization_id: str
    tenant_id: str
    session_id: str
    role_definitions: tuple[VersionedDefinitionRef, ...]
    entitlement_definitions: tuple[VersionedDefinitionRef, ...]
    adapter_bindings: tuple[AdapterGrantBinding, ...]
    authorization_version: int
    entitlement_version: int
    expires_at: float
    active: bool

    def __post_init__(self) -> None:
        validate_typed_id(self.identity_id, "idn")
        validate_typed_id(self.account_id, "act")
        validate_typed_id(self.organization_id, "org")
        validate_typed_id(self.tenant_id, "tnt")
        validate_typed_id(self.session_id, "ses")

        _require_positive_integer(
            self.authorization_version,
            "authorization version",
        )
        _require_positive_integer(
            self.entitlement_version,
            "entitlement version",
        )

        if self.expires_at <= 0:
            raise ContractError("session expiry must be positive")

    def broker_mapping(self) -> Mapping[str, Any]:
        adapter_grants: dict[str, list[str]] = {}

        for binding in self.adapter_bindings:
            adapter_grants.setdefault(binding.adapter_definition_id, [])
            adapter_grants[binding.adapter_definition_id].append(
                binding.operation_definition_id
            )

        for adapter_id in adapter_grants:
            adapter_grants[adapter_id] = sorted(set(adapter_grants[adapter_id]))

        return {
            "accountId": self.account_id,
            "tenantId": self.tenant_id,
            "sessionId": self.session_id,
            "roles": [
                f"{item.definition_id}@{item.version}"
                for item in sorted(
                    self.role_definitions,
                    key=lambda item: (item.definition_id, item.version),
                )
            ],
            "entitlements": [
                f"{item.definition_id}@{item.version}"
                for item in sorted(
                    self.entitlement_definitions,
                    key=lambda item: (item.definition_id, item.version),
                )
            ],
            "adapterGrants": adapter_grants,
            "authorizationVersion": f"auth-v{self.authorization_version}",
            "entitlementVersion": f"ent-v{self.entitlement_version}",
            "expiresAt": self.expires_at,
            "active": self.active,
        }


@dataclass(frozen=True)
class HydrationReference:
    reference_id: str
    kind: str
    target_ref: str
    version: str

    def __post_init__(self) -> None:
        validate_typed_id(self.reference_id, "hyd")
        normalize_symbol(self.kind)
        normalize_symbol(self.version)

        if not str(self.target_ref or "").strip():
            raise ContractError("hydration target reference is required")


@dataclass(frozen=True)
class HydrationProjection:
    organization_id: str
    tenant_id: str
    configuration_version: int
    references: tuple[HydrationReference, ...]

    def __post_init__(self) -> None:
        validate_typed_id(self.organization_id, "org")
        validate_typed_id(self.tenant_id, "tnt")

        _require_positive_integer(
            self.configuration_version,
            "hydration configuration version",
        )


@dataclass(frozen=True)
class ConsumerHandoffProjection:
    handoff_id: str
    consumer: str
    identity_id: str
    account_id: str
    membership_id: str
    organization_id: str
    tenant_id: str
    authorization_version: int
    entitlement_version: int
    hydration: HydrationProjection

    def __post_init__(self) -> None:
        validate_typed_id(self.handoff_id, "hnd")
        validate_typed_id(self.identity_id, "idn")
        validate_typed_id(self.account_id, "act")
        validate_typed_id(self.membership_id, "mbr")
        validate_typed_id(self.organization_id, "org")
        validate_typed_id(self.tenant_id, "tnt")
        normalize_symbol(self.consumer)

        _require_positive_integer(
            self.authorization_version,
            "handoff authorization version",
        )
        _require_positive_integer(
            self.entitlement_version,
            "handoff entitlement version",
        )

        if self.hydration.organization_id != self.organization_id:
            raise ContractError("handoff hydration organization mismatch")

        if self.hydration.tenant_id != self.tenant_id:
            raise ContractError("handoff hydration tenant mismatch")
