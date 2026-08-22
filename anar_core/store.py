from __future__ import annotations

import hashlib
import json
import secrets
import sqlite3
import threading
import time
import uuid
from pathlib import Path
from typing import Any, Iterable

from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerifyMismatchError

from anar_core_contracts import (
    AdapterGrantBinding,
    AuthorizedSubject,
    HydrationProjection,
    ConsumerHandoffProjection,
    HydrationReference,
    VersionedDefinitionRef,
    canonical_json,
    normalize_symbol,
    validate_typed_id,
)


class AuthorityError(RuntimeError):
    pass


def _synchronized(method):
    def synchronized(self, *args, **kwargs):
        with self._lock:
            return method(self, *args, **kwargs)

    synchronized.__name__ = method.__name__
    synchronized.__qualname__ = method.__qualname__
    synchronized.__doc__ = method.__doc__
    return synchronized


_PREFIXES = {
    "identity": "idn",
    "account": "act",
    "organization": "org",
    "tenant": "tnt",
    "membership": "mbr",
    "role": "rol",
    "role_assignment": "ras",
    "entitlement": "ent",
    "entitlement_grant": "egr",
    "adapter": "adp",
    "operation": "opn",
    "binding": "bnd",
    "policy": "pol",
    "session": "ses",
    "account_session": "acs",
    "credential": "crd",
    "password_reset": "pwr",
    "email_verification": "emv",
    "email_change": "emc",
    "mfa_authenticator": "mfa",
    "mfa_step_up": "mfs",
    "mfa_recovery": "mfr",
    "mfa_attestation": "mfaa",
    "invitation": "inv",
    "hydration": "hyd",
    "handoff": "hnd",
}


def _new_id(kind: str) -> str:
    prefix = _PREFIXES[kind]
    return f"{prefix}_{uuid.uuid4().hex}"


def _stable_policy_definition_id(symbolic_name: str) -> str:
    canonical_name = normalize_symbol(symbolic_name)
    digest = hashlib.sha256(canonical_name.encode("utf-8")).hexdigest()
    return f"{_PREFIXES['policy']}_{digest[:32]}"


def _now() -> float:
    return time.time()


_PASSWORD_HASHER = PasswordHasher()


def _normalize_email(value: str) -> str:
    email = str(value or "").strip().casefold()

    if not email or "@" not in email:
        raise AuthorityError("valid email is required")

    local, separator, domain = email.partition("@")

    if not separator or not local or "." not in domain:
        raise AuthorityError("valid email is required")

    return email


def _token_digest(value: str) -> str:
    supplied = str(value or "")

    if not supplied:
        raise AuthorityError("token is required")

    return hashlib.sha256(supplied.encode("utf-8")).hexdigest()


def _require_positive_integer(
    value: int,
    label: str,
    maximum: int | None = None,
) -> int:
    if type(value) is not int or value < 1:
        raise AuthorityError(f"{label} must be positive")

    if maximum is not None and value > maximum:
        raise AuthorityError(f"{label} invalid")

    return value


class AnarCoreStore:
    def __init__(self, path: str | Path) -> None:
        self.path = str(path)
        self._lock = threading.RLock()
        self.connection = sqlite3.connect(
            self.path,
            check_same_thread=False,
        )
        self.connection.row_factory = sqlite3.Row
        self.connection.execute("PRAGMA foreign_keys = ON")
        try:
            self._migrate()
            self.connection.execute("PRAGMA journal_mode = WAL")
        except Exception:
            self.connection.close()
            raise

    @_synchronized
    def close(self) -> None:
        self.connection.close()

    def _migrate(self) -> None:
        metadata_table = self.connection.execute(
            """
            SELECT 1
            FROM sqlite_master
            WHERE type = 'table'
              AND name = 'schema_metadata'
            """
        ).fetchone()

        if metadata_table is not None:
            try:
                existing_metadata = {
                    row["metadata_key"]: row["metadata_value"]
                    for row in self.connection.execute(
                        """
                        SELECT metadata_key, metadata_value
                        FROM schema_metadata
                        """
                    ).fetchall()
                }
            except sqlite3.Error as error:
                raise AuthorityError(
                    "schema metadata is unreadable"
                ) from error

            schema_contract = existing_metadata.get("schema_contract")
            if (
                schema_contract is not None
                and schema_contract != "anar-core.v0.1"
            ):
                raise AuthorityError("foreign schema contract refused")

            schema_revision = existing_metadata.get("schema_revision")
            if schema_revision is not None:
                revision_text = str(schema_revision)
                if not revision_text.isdecimal():
                    raise AuthorityError("schema revision is invalid")

                if int(revision_text) > 9:
                    raise AuthorityError("future schema revision refused")

        self.connection.executescript(
            """
            CREATE TABLE IF NOT EXISTS schema_metadata (
                metadata_key TEXT PRIMARY KEY,
                metadata_value TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS identity (
                identity_id TEXT PRIMARY KEY,
                identity_kind TEXT NOT NULL,
                display_name TEXT NOT NULL,
                status TEXT NOT NULL,
                created_at REAL NOT NULL
            );

            CREATE TABLE IF NOT EXISTS personal_account (
                account_id TEXT PRIMARY KEY,
                identity_id TEXT NOT NULL UNIQUE REFERENCES identity(identity_id),
                status TEXT NOT NULL,
                created_at REAL NOT NULL
            );

            CREATE TABLE IF NOT EXISTS account_email (
                account_id TEXT PRIMARY KEY
                    REFERENCES personal_account(account_id),
                normalized_email TEXT NOT NULL UNIQUE,
                verified_at REAL,
                status TEXT NOT NULL,
                created_at REAL NOT NULL
            );

            CREATE TABLE IF NOT EXISTS password_credential (
                credential_id TEXT PRIMARY KEY,
                account_id TEXT NOT NULL UNIQUE
                    REFERENCES personal_account(account_id),
                password_hash TEXT NOT NULL,
                credential_revision INTEGER NOT NULL DEFAULT 1
                    CHECK(credential_revision >= 1),
                status TEXT NOT NULL,
                created_at REAL NOT NULL,
                updated_at REAL NOT NULL
            );

            CREATE TABLE IF NOT EXISTS password_reset_challenge (
                reset_id TEXT PRIMARY KEY,
                account_id TEXT NOT NULL
                    REFERENCES personal_account(account_id),
                token_sha256 TEXT NOT NULL UNIQUE,
                expires_at REAL NOT NULL,
                consumed_at REAL,
                revoked_at REAL,
                status TEXT NOT NULL,
                created_at REAL NOT NULL
            );

            CREATE TABLE IF NOT EXISTS email_verification_challenge (
                email_verification_id TEXT PRIMARY KEY,
                account_id TEXT NOT NULL
                    REFERENCES personal_account(account_id),
                token_sha256 TEXT NOT NULL UNIQUE,
                expires_at REAL NOT NULL,
                consumed_at REAL,
                revoked_at REAL,
                status TEXT NOT NULL,
                created_at REAL NOT NULL
            );

            CREATE TABLE IF NOT EXISTS email_change_challenge (
                email_change_id TEXT PRIMARY KEY,
                account_id TEXT NOT NULL
                    REFERENCES personal_account(account_id),
                proposed_email TEXT NOT NULL,
                token_sha256 TEXT NOT NULL UNIQUE,
                expires_at REAL NOT NULL,
                consumed_at REAL,
                revoked_at REAL,
                status TEXT NOT NULL,
                created_at REAL NOT NULL
            );

            CREATE TABLE IF NOT EXISTS mfa_authenticator (
                authenticator_id TEXT PRIMARY KEY,
                account_id TEXT NOT NULL
                    REFERENCES personal_account(account_id),
                authenticator_kind TEXT NOT NULL,
                secret_reference TEXT NOT NULL,
                status TEXT NOT NULL,
                verified_at REAL,
                revoked_at REAL,
                created_at REAL NOT NULL,
                CHECK(authenticator_kind IN ('totp'))
            );

            CREATE UNIQUE INDEX IF NOT EXISTS
                one_active_mfa_authenticator_per_kind
            ON mfa_authenticator(
                account_id,
                authenticator_kind
            )
            WHERE status = 'active';

            CREATE TABLE IF NOT EXISTS mfa_recovery_code (
                recovery_code_id TEXT PRIMARY KEY,
                account_id TEXT NOT NULL
                    REFERENCES personal_account(account_id),
                code_sha256 TEXT NOT NULL UNIQUE,
                consumed_at REAL,
                revoked_at REAL,
                status TEXT NOT NULL,
                created_at REAL NOT NULL
            );

            CREATE TABLE IF NOT EXISTS mfa_broker_attestation (
                attestation_id TEXT PRIMARY KEY,
                token_sha256 TEXT NOT NULL UNIQUE,
                account_id TEXT NOT NULL
                    REFERENCES personal_account(account_id),
                account_session_id TEXT NOT NULL
                    REFERENCES account_session(account_session_id),
                authenticator_id TEXT NOT NULL
                    REFERENCES mfa_authenticator(authenticator_id),
                purpose TEXT NOT NULL,
                expires_at REAL NOT NULL,
                consumed_at REAL,
                revoked_at REAL,
                status TEXT NOT NULL,
                created_at REAL NOT NULL
            );

            CREATE TABLE IF NOT EXISTS mfa_step_up_receipt (
                step_up_id TEXT PRIMARY KEY,
                token_sha256 TEXT NOT NULL UNIQUE,
                account_id TEXT NOT NULL
                    REFERENCES personal_account(account_id),
                account_session_id TEXT NOT NULL
                    REFERENCES account_session(account_session_id),
                authenticator_id TEXT NOT NULL
                    REFERENCES mfa_authenticator(authenticator_id),
                purpose TEXT NOT NULL,
                expires_at REAL NOT NULL,
                consumed_at REAL,
                revoked_at REAL,
                status TEXT NOT NULL,
                created_at REAL NOT NULL
            );

            CREATE TABLE IF NOT EXISTS organization (
                organization_id TEXT PRIMARY KEY,
                canonical_name TEXT NOT NULL,
                status TEXT NOT NULL,
                hydration_version INTEGER NOT NULL DEFAULT 1,
                created_at REAL NOT NULL
            );

            CREATE TABLE IF NOT EXISTS tenant (
                tenant_id TEXT PRIMARY KEY,
                organization_id TEXT NOT NULL UNIQUE REFERENCES organization(organization_id),
                status TEXT NOT NULL,
                created_at REAL NOT NULL
            );

            CREATE TABLE IF NOT EXISTS membership (
                membership_id TEXT PRIMARY KEY,
                identity_id TEXT NOT NULL REFERENCES identity(identity_id),
                organization_id TEXT NOT NULL REFERENCES organization(organization_id),
                status TEXT NOT NULL,
                authorization_version INTEGER NOT NULL DEFAULT 1,
                entitlement_version INTEGER NOT NULL DEFAULT 1,
                created_at REAL NOT NULL
            );

            CREATE UNIQUE INDEX IF NOT EXISTS
                one_current_membership_per_identity_organization
            ON membership(
                identity_id,
                organization_id
            )
            WHERE status IN ('active', 'suspended');

            CREATE TABLE IF NOT EXISTS role_definition (
                role_definition_id TEXT NOT NULL,
                version INTEGER NOT NULL,
                symbolic_name TEXT NOT NULL,
                status TEXT NOT NULL,
                grants_json TEXT NOT NULL,
                prohibitions_json TEXT NOT NULL,
                role_metadata_authoritative INTEGER NOT NULL DEFAULT 0
                    CHECK(role_metadata_authoritative = 0),
                created_at REAL NOT NULL,
                PRIMARY KEY(role_definition_id, version)
            );

            CREATE TABLE IF NOT EXISTS policy_definition (
                policy_definition_id TEXT NOT NULL,
                version INTEGER NOT NULL CHECK(version >= 1),
                symbolic_name TEXT NOT NULL,
                status TEXT NOT NULL,
                created_at REAL NOT NULL,
                PRIMARY KEY(policy_definition_id, version)
            );

            CREATE TABLE IF NOT EXISTS role_assignment (
                role_assignment_id TEXT PRIMARY KEY,
                membership_id TEXT NOT NULL REFERENCES membership(membership_id),
                role_definition_id TEXT NOT NULL,
                role_version INTEGER NOT NULL,
                status TEXT NOT NULL,
                created_at REAL NOT NULL,
                FOREIGN KEY(role_definition_id, role_version)
                    REFERENCES role_definition(role_definition_id, version),
                UNIQUE(membership_id, role_definition_id, role_version)
            );

            CREATE TABLE IF NOT EXISTS entitlement_definition (
                entitlement_definition_id TEXT NOT NULL,
                version INTEGER NOT NULL,
                symbolic_name TEXT NOT NULL,
                status TEXT NOT NULL,
                created_at REAL NOT NULL,
                PRIMARY KEY(entitlement_definition_id, version)
            );

            CREATE TABLE IF NOT EXISTS entitlement_grant (
                entitlement_grant_id TEXT PRIMARY KEY,
                membership_id TEXT NOT NULL REFERENCES membership(membership_id),
                entitlement_definition_id TEXT NOT NULL,
                entitlement_version INTEGER NOT NULL,
                status TEXT NOT NULL,
                created_at REAL NOT NULL,
                FOREIGN KEY(entitlement_definition_id, entitlement_version)
                    REFERENCES entitlement_definition(entitlement_definition_id, version),
                UNIQUE(membership_id, entitlement_definition_id, entitlement_version)
            );

            CREATE TABLE IF NOT EXISTS adapter_definition (
                adapter_definition_id TEXT PRIMARY KEY,
                symbolic_name TEXT NOT NULL UNIQUE,
                status TEXT NOT NULL,
                created_at REAL NOT NULL
            );

            CREATE TABLE IF NOT EXISTS operation_definition (
                operation_definition_id TEXT PRIMARY KEY,
                adapter_definition_id TEXT NOT NULL REFERENCES adapter_definition(adapter_definition_id),
                symbolic_name TEXT NOT NULL,
                status TEXT NOT NULL,
                created_at REAL NOT NULL,
                UNIQUE(adapter_definition_id, symbolic_name)
            );

            CREATE TABLE IF NOT EXISTS adapter_grant_binding (
                binding_id TEXT PRIMARY KEY,
                membership_id TEXT NOT NULL REFERENCES membership(membership_id),
                adapter_definition_id TEXT NOT NULL REFERENCES adapter_definition(adapter_definition_id),
                operation_definition_id TEXT NOT NULL REFERENCES operation_definition(operation_definition_id),
                entitlement_definition_id TEXT NOT NULL,
                entitlement_definition_version INTEGER NOT NULL,
                resource_scope_json TEXT NOT NULL,
                policy_definition_id TEXT NOT NULL,
                policy_definition_version INTEGER NOT NULL
                    CHECK(policy_definition_version >= 1),
                policy_version TEXT NOT NULL,
                status TEXT NOT NULL,
                created_at REAL NOT NULL,
                FOREIGN KEY(
                    entitlement_definition_id,
                    entitlement_definition_version
                ) REFERENCES entitlement_definition(
                    entitlement_definition_id,
                    version
                ),
                FOREIGN KEY(
                    policy_definition_id,
                    policy_definition_version
                ) REFERENCES policy_definition(
                    policy_definition_id,
                    version
                )
            );

            CREATE TABLE IF NOT EXISTS account_session (
                account_session_id TEXT PRIMARY KEY,
                bearer_sha256 TEXT NOT NULL UNIQUE,
                identity_id TEXT NOT NULL
                    REFERENCES identity(identity_id),
                account_id TEXT NOT NULL
                    REFERENCES personal_account(account_id),
                credential_revision INTEGER NOT NULL
                    CHECK(credential_revision >= 1),
                expires_at REAL NOT NULL,
                status TEXT NOT NULL,
                revoked_at REAL,
                created_at REAL NOT NULL
            );

            CREATE TABLE IF NOT EXISTS session (
                session_id TEXT PRIMARY KEY,
                bearer_sha256 TEXT NOT NULL UNIQUE,
                identity_id TEXT NOT NULL REFERENCES identity(identity_id),
                account_id TEXT NOT NULL REFERENCES personal_account(account_id),
                membership_id TEXT NOT NULL REFERENCES membership(membership_id),
                organization_id TEXT NOT NULL REFERENCES organization(organization_id),
                tenant_id TEXT NOT NULL REFERENCES tenant(tenant_id),
                authorization_version INTEGER NOT NULL,
                entitlement_version INTEGER NOT NULL,
                credential_revision INTEGER NOT NULL DEFAULT 1
                    CHECK(credential_revision >= 1),
                expires_at REAL NOT NULL,
                status TEXT NOT NULL,
                revoked_at REAL,
                created_at REAL NOT NULL
            );

            CREATE TABLE IF NOT EXISTS invitation (
                invitation_id TEXT PRIMARY KEY,
                code_sha256 TEXT NOT NULL UNIQUE,
                organization_id TEXT NOT NULL REFERENCES organization(organization_id),
                tenant_id TEXT NOT NULL REFERENCES tenant(tenant_id),
                role_refs_json TEXT NOT NULL,
                entitlement_refs_json TEXT NOT NULL,
                expires_at REAL NOT NULL,
                maximum_uses INTEGER NOT NULL,
                consumed_uses INTEGER NOT NULL DEFAULT 0,
                status TEXT NOT NULL,
                created_at REAL NOT NULL
            );

            CREATE TABLE IF NOT EXISTS consumer_handoff (
                handoff_id TEXT PRIMARY KEY,
                token_sha256 TEXT NOT NULL UNIQUE,
                consumer TEXT NOT NULL,
                identity_id TEXT NOT NULL
                    REFERENCES identity(identity_id),
                account_id TEXT NOT NULL
                    REFERENCES personal_account(account_id),
                membership_id TEXT NOT NULL
                    REFERENCES membership(membership_id),
                organization_id TEXT NOT NULL
                    REFERENCES organization(organization_id),
                tenant_id TEXT NOT NULL
                    REFERENCES tenant(tenant_id),
                source_session_id TEXT NOT NULL
                    REFERENCES session(session_id),
                authorization_version INTEGER NOT NULL
                    CHECK(authorization_version >= 1),
                entitlement_version INTEGER NOT NULL
                    CHECK(entitlement_version >= 1),
                expires_at REAL NOT NULL,
                consumed_at REAL,
                revoked_at REAL,
                status TEXT NOT NULL,
                created_at REAL NOT NULL
            );

            CREATE INDEX IF NOT EXISTS
                consumer_handoff_membership_status_idx
            ON consumer_handoff(
                membership_id,
                status
            );

            CREATE TABLE IF NOT EXISTS hydration_reference (
                hydration_reference_id TEXT PRIMARY KEY,
                organization_id TEXT NOT NULL REFERENCES organization(organization_id),
                kind TEXT NOT NULL,
                target_ref TEXT NOT NULL,
                version TEXT NOT NULL,
                status TEXT NOT NULL,
                created_at REAL NOT NULL,
                UNIQUE(organization_id, kind, target_ref, version)
            );
            """
        )

        session_columns = {
            row["name"]
            for row in self.connection.execute(
                "PRAGMA table_info(session)"
            ).fetchall()
        }

        if "credential_revision" not in session_columns:
            self.connection.execute(
                """
                ALTER TABLE session
                ADD COLUMN credential_revision INTEGER NOT NULL
                    DEFAULT 1
                    CHECK(credential_revision >= 1)
                """
            )

        if "revoked_at" not in session_columns:
            self.connection.execute(
                """
                ALTER TABLE session
                ADD COLUMN revoked_at REAL
                """
            )

        if "account_session_id" not in session_columns:
            self.connection.execute(
                """
                ALTER TABLE session
                ADD COLUMN account_session_id TEXT
                    REFERENCES account_session(account_session_id)
                """
            )

        handoff_columns = {
            row["name"]
            for row in self.connection.execute(
                "PRAGMA table_info(consumer_handoff)"
            ).fetchall()
        }

        if "source_session_id" not in handoff_columns:
            self.connection.execute(
                """
                ALTER TABLE consumer_handoff
                ADD COLUMN source_session_id TEXT
                    REFERENCES session(session_id)
                """
            )

            migration_now = _now()

            self.connection.execute(
                """
                UPDATE consumer_handoff
                SET status = 'revoked',
                    revoked_at = ?
                WHERE source_session_id IS NULL
                  AND status = 'active'
                  AND consumed_at IS NULL
                  AND revoked_at IS NULL
                """,
                (migration_now,),
            )

        role_columns = {
            row["name"]
            for row in self.connection.execute(
                "PRAGMA table_info(role_definition)"
            ).fetchall()
        }

        if "role_metadata_authoritative" not in role_columns:
            self.connection.execute(
                """
                ALTER TABLE role_definition
                ADD COLUMN role_metadata_authoritative INTEGER NOT NULL
                    DEFAULT 0
                    CHECK(role_metadata_authoritative = 0)
                """
            )

        binding_columns = {
            row["name"]
            for row in self.connection.execute(
                "PRAGMA table_info(adapter_grant_binding)"
            ).fetchall()
        }

        binding_is_legacy = (
            "policy_definition_id" not in binding_columns
            or "policy_definition_version" not in binding_columns
        )

        if binding_is_legacy:
            legacy_rows = self.connection.execute(
                """
                SELECT *
                FROM adapter_grant_binding
                ORDER BY binding_id
                """
            ).fetchall()

            legacy_policy_definitions: dict[str, tuple[str, int, float]] = {}

            for row in legacy_rows:
                canonical_policy_version = normalize_symbol(row["policy_version"])
                policy_definition_id = _stable_policy_definition_id(
                    canonical_policy_version
                )
                created_at = float(row["created_at"])
                current = legacy_policy_definitions.get(policy_definition_id)

                if current is None:
                    legacy_policy_definitions[policy_definition_id] = (
                        canonical_policy_version,
                        1,
                        created_at,
                    )

                if current is not None and created_at < current[2]:
                    legacy_policy_definitions[policy_definition_id] = (
                        canonical_policy_version,
                        1,
                        created_at,
                    )

            for policy_definition_id in sorted(legacy_policy_definitions):
                symbolic_name, version, created_at = legacy_policy_definitions[
                    policy_definition_id
                ]
                self.connection.execute(
                    """
                    INSERT OR IGNORE INTO policy_definition(
                        policy_definition_id,
                        version,
                        symbolic_name,
                        status,
                        created_at
                    ) VALUES (?, ?, ?, 'active', ?)
                    """,
                    (
                        policy_definition_id,
                        version,
                        symbolic_name,
                        created_at,
                    ),
                )

            self.connection.execute(
                """
                ALTER TABLE adapter_grant_binding
                RENAME TO adapter_grant_binding_legacy_v1
                """
            )

            self.connection.execute(
                """
                CREATE TABLE adapter_grant_binding (
                    binding_id TEXT PRIMARY KEY,
                    membership_id TEXT NOT NULL REFERENCES membership(membership_id),
                    adapter_definition_id TEXT NOT NULL REFERENCES adapter_definition(adapter_definition_id),
                    operation_definition_id TEXT NOT NULL REFERENCES operation_definition(operation_definition_id),
                    entitlement_definition_id TEXT NOT NULL,
                    entitlement_definition_version INTEGER NOT NULL,
                    resource_scope_json TEXT NOT NULL,
                    policy_definition_id TEXT NOT NULL,
                    policy_definition_version INTEGER NOT NULL
                        CHECK(policy_definition_version >= 1),
                    policy_version TEXT NOT NULL,
                    status TEXT NOT NULL,
                    created_at REAL NOT NULL,
                    FOREIGN KEY(
                        entitlement_definition_id,
                        entitlement_definition_version
                    ) REFERENCES entitlement_definition(
                        entitlement_definition_id,
                        version
                    ),
                    FOREIGN KEY(
                        policy_definition_id,
                        policy_definition_version
                    ) REFERENCES policy_definition(
                        policy_definition_id,
                        version
                    )
                )
                """
            )

            for row in legacy_rows:
                canonical_policy_version = normalize_symbol(row["policy_version"])
                policy_definition_id = _stable_policy_definition_id(
                    canonical_policy_version
                )
                self.connection.execute(
                    """
                    INSERT INTO adapter_grant_binding(
                        binding_id,
                        membership_id,
                        adapter_definition_id,
                        operation_definition_id,
                        entitlement_definition_id,
                        entitlement_definition_version,
                        resource_scope_json,
                        policy_definition_id,
                        policy_definition_version,
                        policy_version,
                        status,
                        created_at
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, 1, ?, ?, ?)
                    """,
                    (
                        row["binding_id"],
                        row["membership_id"],
                        row["adapter_definition_id"],
                        row["operation_definition_id"],
                        row["entitlement_definition_id"],
                        row["entitlement_definition_version"],
                        row["resource_scope_json"],
                        policy_definition_id,
                        canonical_policy_version,
                        row["status"],
                        row["created_at"],
                    ),
                )

            self.connection.execute(
                "DROP TABLE adapter_grant_binding_legacy_v1"
            )

        membership_schema_row = self.connection.execute(
            """
            SELECT sql
            FROM sqlite_master
            WHERE type = 'table'
              AND name = 'membership'
            """
        ).fetchone()

        membership_schema_sql = ""

        if membership_schema_row is not None:
            membership_schema_sql = str(
                membership_schema_row[0] or ""
            )

        normalized_membership_schema = "".join(
            membership_schema_sql.upper().split()
        )

        legacy_membership_unique = (
            "UNIQUE(IDENTITY_ID,ORGANIZATION_ID)"
            in normalized_membership_schema
        )

        if legacy_membership_unique:
            self.connection.commit()
            self.connection.execute("PRAGMA foreign_keys = OFF")
            self.connection.execute("BEGIN IMMEDIATE")

            try:
                self.connection.execute(
                    """
                    CREATE TABLE membership_rebuild (
                        membership_id TEXT PRIMARY KEY,
                        identity_id TEXT NOT NULL
                            REFERENCES identity(identity_id),
                        organization_id TEXT NOT NULL
                            REFERENCES organization(organization_id),
                        status TEXT NOT NULL,
                        authorization_version INTEGER NOT NULL DEFAULT 1,
                        entitlement_version INTEGER NOT NULL DEFAULT 1,
                        created_at REAL NOT NULL
                    )
                    """
                )

                self.connection.execute(
                    """
                    INSERT INTO membership_rebuild(
                        membership_id,
                        identity_id,
                        organization_id,
                        status,
                        authorization_version,
                        entitlement_version,
                        created_at
                    )
                    SELECT
                        membership_id,
                        identity_id,
                        organization_id,
                        status,
                        authorization_version,
                        entitlement_version,
                        created_at
                    FROM membership
                    """
                )

                self.connection.execute(
                    """
                    DROP TABLE membership
                    """
                )

                self.connection.execute(
                    """
                    ALTER TABLE membership_rebuild
                    RENAME TO membership
                    """
                )

                self.connection.execute(
                    """
                    CREATE UNIQUE INDEX
                        one_current_membership_per_identity_organization
                    ON membership(
                        identity_id,
                        organization_id
                    )
                    WHERE status IN ('active', 'suspended')
                    """
                )

                self.connection.commit()

            except Exception:
                self.connection.rollback()
                raise

            finally:
                self.connection.execute("PRAGMA foreign_keys = ON")

            membership_fk_rows = self.connection.execute(
                "PRAGMA foreign_key_check"
            ).fetchall()

            if membership_fk_rows:
                raise AuthorityError(
                    "membership migration violated foreign keys"
                )

        schema_metadata = (
            ("schema_contract", "anar-core.v0.1"),
            ("schema_revision", "9"),
            ("role_metadata_authoritative", "false"),
        )

        for metadata_key, metadata_value in schema_metadata:
            self.connection.execute(
                """
                INSERT INTO schema_metadata(metadata_key, metadata_value)
                VALUES (?, ?)
                ON CONFLICT(metadata_key) DO UPDATE
                SET metadata_value = excluded.metadata_value
                """,
                (metadata_key, metadata_value),
            )

        self.connection.commit()

    def _require_password(self, password: str) -> str:
        supplied = str(password or "")

        if len(supplied) < 12:
            raise AuthorityError(
                "password must contain at least 12 characters"
            )

        return supplied

    def _load_account_session(
        self,
        bearer: str,
        account_session_id: str,
    ) -> sqlite3.Row:
        validate_typed_id(account_session_id, "acs")

        supplied_sha256 = _token_digest(bearer)
        now = _now()

        row = self.connection.execute(
            """
            SELECT
                account_session.*,
                password_credential.credential_revision
                    AS current_credential_revision
            FROM account_session
            JOIN password_credential
              ON password_credential.account_id = account_session.account_id
            JOIN personal_account
              ON personal_account.account_id = account_session.account_id
            JOIN identity
              ON identity.identity_id = account_session.identity_id
            WHERE account_session.bearer_sha256 = ?
              AND account_session.account_session_id = ?
              AND account_session.status = 'active'
              AND account_session.revoked_at IS NULL
              AND password_credential.status = 'active'
              AND personal_account.status = 'active'
              AND identity.status = 'active'
            """,
            (
                supplied_sha256,
                account_session_id,
            ),
        ).fetchone()

        if row is None:
            raise AuthorityError("unauthorized")

        if row["expires_at"] <= now:
            raise AuthorityError("account session expired")

        if (
            row["credential_revision"]
            != row["current_credential_revision"]
        ):
            raise AuthorityError("credential revision stale")

        return row

    @_synchronized
    def signup(
        self,
        email: str,
        password: str,
        display_name: str,
        verification_ttl_seconds: int = 1800,
    ) -> tuple[str, str, str, str]:
        normalized_email = _normalize_email(email)
        supplied_password = self._require_password(password)
        name = str(display_name or "").strip()

        if not name:
            raise AuthorityError("display name is required")

        _require_positive_integer(
            verification_ttl_seconds,
            "email verification TTL",
        )

        identity_id = _new_id("identity")
        account_id = _new_id("account")
        credential_id = _new_id("credential")
        email_verification_id = _new_id("email_verification")
        verification_token = secrets.token_urlsafe(32)
        verification_digest = _token_digest(verification_token)
        password_hash = _PASSWORD_HASHER.hash(supplied_password)
        now = _now()

        try:
            with self.connection:
                self.connection.execute(
                    """
                    INSERT INTO identity(
                        identity_id,
                        identity_kind,
                        display_name,
                        status,
                        created_at
                    ) VALUES (?, 'human', ?, 'active', ?)
                    """,
                    (
                        identity_id,
                        name,
                        now,
                    ),
                )

                self.connection.execute(
                    """
                    INSERT INTO personal_account(
                        account_id,
                        identity_id,
                        status,
                        created_at
                    ) VALUES (?, ?, 'active', ?)
                    """,
                    (
                        account_id,
                        identity_id,
                        now,
                    ),
                )

                self.connection.execute(
                    """
                    INSERT INTO account_email(
                        account_id,
                        normalized_email,
                        verified_at,
                        status,
                        created_at
                    ) VALUES (?, ?, NULL, 'pending', ?)
                    """,
                    (
                        account_id,
                        normalized_email,
                        now,
                    ),
                )

                self.connection.execute(
                    """
                    INSERT INTO password_credential(
                        credential_id,
                        account_id,
                        password_hash,
                        credential_revision,
                        status,
                        created_at,
                        updated_at
                    ) VALUES (?, ?, ?, 1, 'active', ?, ?)
                    """,
                    (
                        credential_id,
                        account_id,
                        password_hash,
                        now,
                        now,
                    ),
                )

                self.connection.execute(
                    """
                    INSERT INTO email_verification_challenge(
                        email_verification_id,
                        account_id,
                        token_sha256,
                        expires_at,
                        consumed_at,
                        revoked_at,
                        status,
                        created_at
                    ) VALUES (?, ?, ?, ?, NULL, NULL, 'active', ?)
                    """,
                    (
                        email_verification_id,
                        account_id,
                        verification_digest,
                        now + verification_ttl_seconds,
                        now,
                    ),
                )
        except sqlite3.IntegrityError as exc:
            raise AuthorityError("email unavailable") from exc

        return (
            identity_id,
            account_id,
            email_verification_id,
            verification_token,
        )

    @_synchronized
    def verify_email(self, token: str) -> str:
        digest = _token_digest(token)
        now = _now()

        self.connection.execute("BEGIN IMMEDIATE")

        try:
            challenge = self.connection.execute(
                """
                SELECT *
                FROM email_verification_challenge
                WHERE token_sha256 = ?
                """,
                (digest,),
            ).fetchone()

            if challenge is None:
                raise AuthorityError(
                    "email verification unavailable"
                )

            if challenge["status"] != "active":
                raise AuthorityError(
                    "email verification unavailable"
                )

            if challenge["consumed_at"] is not None:
                raise AuthorityError(
                    "email verification consumed"
                )

            if challenge["revoked_at"] is not None:
                raise AuthorityError(
                    "email verification revoked"
                )

            if challenge["expires_at"] <= now:
                raise AuthorityError(
                    "email verification expired"
                )

            updated_email = self.connection.execute(
                """
                UPDATE account_email
                SET verified_at = ?,
                    status = 'active'
                WHERE account_id = ?
                  AND status = 'pending'
                  AND verified_at IS NULL
                """,
                (
                    now,
                    challenge["account_id"],
                ),
            )

            if updated_email.rowcount != 1:
                raise AuthorityError(
                    "email verification unavailable"
                )

            consumed = self.connection.execute(
                """
                UPDATE email_verification_challenge
                SET consumed_at = ?,
                    status = 'consumed'
                WHERE email_verification_id = ?
                  AND status = 'active'
                  AND consumed_at IS NULL
                  AND revoked_at IS NULL
                """,
                (
                    now,
                    challenge["email_verification_id"],
                ),
            )

            if consumed.rowcount != 1:
                raise AuthorityError(
                    "email verification unavailable"
                )

            self.connection.commit()
            return challenge["account_id"]

        except Exception:
            self.connection.rollback()
            raise

    @_synchronized
    def login(
        self,
        email: str,
        password: str,
        ttl_seconds: int = 3600,
    ) -> tuple[str, str]:
        normalized_email = _normalize_email(email)
        supplied_password = str(password or "")

        _require_positive_integer(ttl_seconds, "account session TTL")

        row = self.connection.execute(
            """
            SELECT
                account_email.account_id,
                personal_account.identity_id,
                password_credential.password_hash,
                password_credential.credential_revision
            FROM account_email
            JOIN personal_account
              ON personal_account.account_id = account_email.account_id
            JOIN identity
              ON identity.identity_id = personal_account.identity_id
            JOIN password_credential
              ON password_credential.account_id = account_email.account_id
            WHERE account_email.normalized_email = ?
              AND account_email.status = 'active'
              AND account_email.verified_at IS NOT NULL
              AND personal_account.status = 'active'
              AND identity.status = 'active'
              AND password_credential.status = 'active'
            """,
            (normalized_email,),
        ).fetchone()

        if row is None:
            raise AuthorityError("unauthorized")

        try:
            verified = _PASSWORD_HASHER.verify(
                row["password_hash"],
                supplied_password,
            )
        except (VerifyMismatchError, InvalidHashError) as exc:
            raise AuthorityError("unauthorized") from exc

        if not verified:
            raise AuthorityError("unauthorized")

        if _PASSWORD_HASHER.check_needs_rehash(
            row["password_hash"]
        ):
            refreshed_hash = _PASSWORD_HASHER.hash(
                supplied_password
            )
            self.connection.execute(
                """
                UPDATE password_credential
                SET password_hash = ?,
                    updated_at = ?
                WHERE account_id = ?
                """,
                (
                    refreshed_hash,
                    _now(),
                    row["account_id"],
                ),
            )

        account_session_id = _new_id("account_session")
        bearer = secrets.token_urlsafe(32)
        bearer_sha256 = _token_digest(bearer)
        now = _now()

        self.connection.execute(
            """
            INSERT INTO account_session(
                account_session_id,
                bearer_sha256,
                identity_id,
                account_id,
                credential_revision,
                expires_at,
                status,
                revoked_at,
                created_at
            ) VALUES (?, ?, ?, ?, ?, ?, 'active', NULL, ?)
            """,
            (
                account_session_id,
                bearer_sha256,
                row["identity_id"],
                row["account_id"],
                row["credential_revision"],
                now + ttl_seconds,
                now,
            ),
        )
        self.connection.commit()

        return account_session_id, bearer

    @_synchronized
    def authenticate_account_session(
        self,
        bearer: str,
        account_session_id: str,
    ) -> tuple[str, str]:
        row = self._load_account_session(
            bearer,
            account_session_id,
        )

        return (
            row["identity_id"],
            row["account_id"],
        )

    @_synchronized
    def signout(
        self,
        bearer: str,
        account_session_id: str,
    ) -> None:
        self._load_account_session(
            bearer,
            account_session_id,
        )
        now = _now()

        with self.connection:
            revoked = self.connection.execute(
                """
                UPDATE account_session
                SET status = 'revoked',
                    revoked_at = ?
                WHERE account_session_id = ?
                  AND status = 'active'
                  AND revoked_at IS NULL
                """,
                (
                    now,
                    account_session_id,
                ),
            )

            if revoked.rowcount != 1:
                raise AuthorityError(
                    "active account session unavailable"
                )

            self.connection.execute(
                """
                UPDATE session
                SET status = 'revoked',
                    revoked_at = ?
                WHERE account_session_id = ?
                  AND status = 'active'
                """,
                (
                    now,
                    account_session_id,
                ),
            )

            self.connection.execute(
                """
                UPDATE consumer_handoff
                SET status = 'revoked',
                    revoked_at = ?
                WHERE source_session_id IN (
                    SELECT session_id
                    FROM session
                    WHERE account_session_id = ?
                      AND status = 'revoked'
                )
                  AND status = 'active'
                  AND consumed_at IS NULL
                  AND revoked_at IS NULL
                """,
                (
                    now,
                    account_session_id,
                ),
            )

            self._revoke_account_session_mfa_authority(
                account_session_id,
                now,
            )

    def _revoke_account_session_mfa_authority(
        self,
        account_session_id: str,
        revoked_at: float,
    ) -> None:
        validate_typed_id(account_session_id, "acs")

        self.connection.execute(
            """
            UPDATE mfa_broker_attestation
            SET status = 'revoked',
                revoked_at = ?
            WHERE account_session_id = ?
              AND status = 'active'
              AND consumed_at IS NULL
              AND revoked_at IS NULL
            """,
            (
                revoked_at,
                account_session_id,
            ),
        )

        self.connection.execute(
            """
            UPDATE mfa_step_up_receipt
            SET status = 'revoked',
                revoked_at = ?
            WHERE account_session_id = ?
              AND status = 'active'
              AND consumed_at IS NULL
              AND revoked_at IS NULL
            """,
            (
                revoked_at,
                account_session_id,
            ),
        )

    def _revoke_account_authority(
        self,
        account_id: str,
        revoked_at: float,
    ) -> None:
        account_sessions = self.connection.execute(
            """
            SELECT account_session_id
            FROM account_session
            WHERE account_id = ?
              AND status = 'active'
              AND revoked_at IS NULL
            """,
            (account_id,),
        ).fetchall()

        account_session_ids = [
            row["account_session_id"]
            for row in account_sessions
        ]

        self.connection.execute(
            """
            UPDATE account_session
            SET status = 'revoked',
                revoked_at = ?
            WHERE account_id = ?
              AND status = 'active'
              AND revoked_at IS NULL
            """,
            (
                revoked_at,
                account_id,
            ),
        )

        for account_session_id in account_session_ids:
            self.connection.execute(
                """
                UPDATE session
                SET status = 'revoked',
                    revoked_at = ?
                WHERE account_session_id = ?
                  AND status = 'active'
                """,
                (
                    revoked_at,
                    account_session_id,
                ),
            )

            self.connection.execute(
                """
                UPDATE consumer_handoff
                SET status = 'revoked',
                    revoked_at = ?
                WHERE source_session_id IN (
                    SELECT session_id
                    FROM session
                    WHERE account_session_id = ?
                      AND status = 'revoked'
                )
                  AND status = 'active'
                  AND consumed_at IS NULL
                  AND revoked_at IS NULL
                """,
                (
                    revoked_at,
                    account_session_id,
                ),
            )

        self._revoke_mfa_authority(
            account_id,
            revoked_at,
        )

    def _revoke_mfa_authority(
        self,
        account_id: str,
        revoked_at: float,
    ) -> None:
        self.connection.execute(
            """
            UPDATE mfa_broker_attestation
            SET status = 'revoked',
                revoked_at = ?
            WHERE account_id = ?
              AND status = 'active'
              AND consumed_at IS NULL
              AND revoked_at IS NULL
            """,
            (
                revoked_at,
                account_id,
            ),
        )

        self.connection.execute(
            """
            UPDATE mfa_step_up_receipt
            SET status = 'revoked',
                revoked_at = ?
            WHERE account_id = ?
              AND status = 'active'
              AND consumed_at IS NULL
              AND revoked_at IS NULL
            """,
            (
                revoked_at,
                account_id,
            ),
        )

    @_synchronized
    def change_password(
        self,
        bearer: str,
        account_session_id: str,
        current_password: str,
        new_password: str,
        repeat_password: str,
        step_up_token: str | None = None,
    ) -> None:
        account_session = self._load_account_session(
            bearer,
            account_session_id,
        )

        supplied_current = str(current_password or "")
        supplied_new = self._require_password(new_password)
        supplied_repeat = str(repeat_password or "")

        if supplied_new != supplied_repeat:
            raise AuthorityError("new passwords do not match")

        credential = self.connection.execute(
            """
            SELECT *
            FROM password_credential
            WHERE account_id = ?
              AND status = 'active'
            """,
            (account_session["account_id"],),
        ).fetchone()

        if credential is None:
            raise AuthorityError("active credential unavailable")

        try:
            verified = _PASSWORD_HASHER.verify(
                credential["password_hash"],
                supplied_current,
            )
        except (VerifyMismatchError, InvalidHashError) as exc:
            raise AuthorityError("current password invalid") from exc

        if not verified:
            raise AuthorityError("current password invalid")

        try:
            same_password = _PASSWORD_HASHER.verify(
                credential["password_hash"],
                supplied_new,
            )
        except VerifyMismatchError:
            same_password = False
        except InvalidHashError as exc:
            raise AuthorityError("active credential unavailable") from exc

        if same_password:
            raise AuthorityError(
                "new password must differ from current password"
            )

        now = _now()
        replacement_hash = _PASSWORD_HASHER.hash(supplied_new)

        self.connection.execute("BEGIN IMMEDIATE")

        try:
            authenticator = self._active_mfa_authenticator(
                account_session["account_id"]
            )

            if authenticator is not None:
                if not step_up_token:
                    raise AuthorityError(
                        "MFA step-up required for password change"
                    )

                self._consume_mfa_step_up_for_action(
                    account_session["account_id"],
                    account_session_id,
                    step_up_token,
                    "password.change",
                    now,
                )

            updated = self.connection.execute(
                """
                UPDATE password_credential
                SET password_hash = ?,
                    credential_revision = credential_revision + 1,
                    updated_at = ?
                WHERE account_id = ?
                  AND credential_id = ?
                  AND status = 'active'
                """,
                (
                    replacement_hash,
                    now,
                    account_session["account_id"],
                    credential["credential_id"],
                ),
            )

            if updated.rowcount != 1:
                raise AuthorityError("active credential unavailable")

            self.connection.execute(
                """
                UPDATE password_reset_challenge
                SET status = 'revoked',
                    revoked_at = ?
                WHERE account_id = ?
                  AND status = 'active'
                  AND consumed_at IS NULL
                  AND revoked_at IS NULL
                """,
                (
                    now,
                    account_session["account_id"],
                ),
            )

            self._revoke_account_authority(
                account_session["account_id"],
                now,
            )

            self.connection.commit()

        except Exception:
            self.connection.rollback()
            raise

    @_synchronized
    def issue_password_reset(
        self,
        email: str,
        ttl_seconds: int = 900,
    ) -> tuple[str, str]:
        normalized_email = _normalize_email(email)

        _require_positive_integer(ttl_seconds, "password reset TTL")

        account = self.connection.execute(
            """
            SELECT account_email.account_id
            FROM account_email
            JOIN personal_account
              ON personal_account.account_id = account_email.account_id
            JOIN password_credential
              ON password_credential.account_id = account_email.account_id
            WHERE account_email.normalized_email = ?
              AND account_email.status = 'active'
              AND account_email.verified_at IS NOT NULL
              AND personal_account.status = 'active'
              AND password_credential.status = 'active'
            """,
            (normalized_email,),
        ).fetchone()

        if account is None:
            raise AuthorityError("password reset unavailable")

        reset_id = _new_id("password_reset")
        token = secrets.token_urlsafe(32)
        token_sha256 = _token_digest(token)
        now = _now()

        with self.connection:
            self.connection.execute(
                """
                UPDATE password_reset_challenge
                SET status = 'revoked',
                    revoked_at = ?
                WHERE account_id = ?
                  AND status = 'active'
                  AND consumed_at IS NULL
                  AND revoked_at IS NULL
                """,
                (
                    now,
                    account["account_id"],
                ),
            )

            self.connection.execute(
                """
                INSERT INTO password_reset_challenge(
                    reset_id,
                    account_id,
                    token_sha256,
                    expires_at,
                    consumed_at,
                    revoked_at,
                    status,
                    created_at
                ) VALUES (?, ?, ?, ?, NULL, NULL, 'active', ?)
                """,
                (
                    reset_id,
                    account["account_id"],
                    token_sha256,
                    now + ttl_seconds,
                    now,
                ),
            )

        return reset_id, token

    @_synchronized
    def consume_password_reset(
        self,
        token: str,
        new_password: str,
        repeat_password: str,
    ) -> str:
        digest = _token_digest(token)
        supplied_new = self._require_password(new_password)
        supplied_repeat = str(repeat_password or "")

        if supplied_new != supplied_repeat:
            raise AuthorityError("new passwords do not match")

        now = _now()
        self.connection.execute("BEGIN IMMEDIATE")

        try:
            challenge = self.connection.execute(
                """
                SELECT *
                FROM password_reset_challenge
                WHERE token_sha256 = ?
                """,
                (digest,),
            ).fetchone()

            if challenge is None:
                raise AuthorityError("password reset unavailable")

            if challenge["status"] != "active":
                raise AuthorityError("password reset unavailable")

            if challenge["consumed_at"] is not None:
                raise AuthorityError("password reset consumed")

            if challenge["revoked_at"] is not None:
                raise AuthorityError("password reset revoked")

            if challenge["expires_at"] <= now:
                raise AuthorityError("password reset expired")

            credential = self.connection.execute(
                """
                SELECT *
                FROM password_credential
                WHERE account_id = ?
                  AND status = 'active'
                """,
                (challenge["account_id"],),
            ).fetchone()

            if credential is None:
                raise AuthorityError("active credential unavailable")

            try:
                same_password = _PASSWORD_HASHER.verify(
                    credential["password_hash"],
                    supplied_new,
                )
            except VerifyMismatchError:
                same_password = False
            except InvalidHashError as exc:
                raise AuthorityError(
                    "active credential unavailable"
                ) from exc

            if same_password:
                raise AuthorityError(
                    "new password must differ from current password"
                )

            replacement_hash = _PASSWORD_HASHER.hash(supplied_new)

            updated = self.connection.execute(
                """
                UPDATE password_credential
                SET password_hash = ?,
                    credential_revision = credential_revision + 1,
                    updated_at = ?
                WHERE account_id = ?
                  AND credential_id = ?
                  AND status = 'active'
                """,
                (
                    replacement_hash,
                    now,
                    challenge["account_id"],
                    credential["credential_id"],
                ),
            )

            if updated.rowcount != 1:
                raise AuthorityError("active credential unavailable")

            consumed = self.connection.execute(
                """
                UPDATE password_reset_challenge
                SET status = 'consumed',
                    consumed_at = ?
                WHERE reset_id = ?
                  AND status = 'active'
                  AND consumed_at IS NULL
                  AND revoked_at IS NULL
                """,
                (
                    now,
                    challenge["reset_id"],
                ),
            )

            if consumed.rowcount != 1:
                raise AuthorityError("password reset unavailable")

            self.connection.execute(
                """
                UPDATE password_reset_challenge
                SET status = 'revoked',
                    revoked_at = ?
                WHERE account_id = ?
                  AND reset_id != ?
                  AND status = 'active'
                  AND consumed_at IS NULL
                  AND revoked_at IS NULL
                """,
                (
                    now,
                    challenge["account_id"],
                    challenge["reset_id"],
                ),
            )

            self._revoke_account_authority(
                challenge["account_id"],
                now,
            )

            self.connection.commit()
            return challenge["account_id"]

        except Exception:
            self.connection.rollback()
            raise

    def _require_mfa_purpose(
        self,
        purpose: str,
    ) -> str:
        normalized = str(purpose or "").strip()

        allowed = {
            "mfa.enroll",
            "mfa.recovery.rotate",
            "password.change",
            "email.change",
        }

        if normalized not in allowed:
            raise AuthorityError("unsupported MFA purpose")

        return normalized

    def _active_mfa_authenticator(
        self,
        account_id: str,
    ):
        return self.connection.execute(
            """
            SELECT *
            FROM mfa_authenticator
            WHERE account_id = ?
              AND authenticator_kind = 'totp'
              AND status = 'active'
              AND verified_at IS NOT NULL
              AND revoked_at IS NULL
            """,
            (account_id,),
        ).fetchone()

    def _consume_mfa_broker_attestation(
        self,
        account_id: str,
        account_session_id: str,
        authenticator_id: str,
        token: str,
        purpose: str,
        now: float,
    ) -> None:
        digest = _token_digest(token)

        row = self.connection.execute(
            """
            SELECT *
            FROM mfa_broker_attestation
            WHERE token_sha256 = ?
            """,
            (digest,),
        ).fetchone()

        if row is None:
            raise AuthorityError("MFA attestation unavailable")

        if row["status"] != "active":
            raise AuthorityError("MFA attestation unavailable")

        if row["consumed_at"] is not None:
            raise AuthorityError("MFA attestation consumed")

        if row["revoked_at"] is not None:
            raise AuthorityError("MFA attestation revoked")

        if row["expires_at"] <= now:
            raise AuthorityError("MFA attestation expired")

        if row["account_id"] != account_id:
            raise AuthorityError("MFA attestation account mismatch")

        if row["account_session_id"] != account_session_id:
            raise AuthorityError("MFA attestation session mismatch")

        if row["authenticator_id"] != authenticator_id:
            raise AuthorityError("MFA attestation authenticator mismatch")

        if row["purpose"] != purpose:
            raise AuthorityError("MFA attestation purpose mismatch")

        consumed = self.connection.execute(
            """
            UPDATE mfa_broker_attestation
            SET status = 'consumed',
                consumed_at = ?
            WHERE attestation_id = ?
              AND status = 'active'
              AND consumed_at IS NULL
              AND revoked_at IS NULL
            """,
            (
                now,
                row["attestation_id"],
            ),
        )

        if consumed.rowcount != 1:
            raise AuthorityError("MFA attestation unavailable")

    def _mint_mfa_step_up(
        self,
        account_id: str,
        account_session_id: str,
        authenticator_id: str,
        purpose: str,
        ttl_seconds: int,
        now: float,
    ) -> tuple[str, str]:
        _require_positive_integer(ttl_seconds, "MFA step-up TTL")

        step_up_id = _new_id("mfa_step_up")
        token = secrets.token_urlsafe(32)

        self.connection.execute(
            """
            INSERT INTO mfa_step_up_receipt(
                step_up_id,
                token_sha256,
                account_id,
                account_session_id,
                authenticator_id,
                purpose,
                expires_at,
                consumed_at,
                revoked_at,
                status,
                created_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, NULL, NULL, 'active', ?)
            """,
            (
                step_up_id,
                _token_digest(token),
                account_id,
                account_session_id,
                authenticator_id,
                purpose,
                now + ttl_seconds,
                now,
            ),
        )

        return step_up_id, token

    @_synchronized
    def begin_totp_enrollment(
        self,
        bearer: str,
        account_session_id: str,
        secret_reference: str,
    ) -> str:
        account_session = self._load_account_session(
            bearer,
            account_session_id,
        )

        reference = str(secret_reference or "").strip()

        if not reference.startswith("vault://"):
            raise AuthorityError(
                "MFA secret reference must be an opaque Vault reference"
            )

        if len(reference) > 512:
            raise AuthorityError("MFA secret reference too long")

        existing = self._active_mfa_authenticator(
            account_session["account_id"]
        )

        if existing is not None:
            raise AuthorityError("active MFA authenticator already exists")

        authenticator_id = _new_id("mfa_authenticator")
        now = _now()

        with self.connection:
            self.connection.execute(
                """
                UPDATE mfa_authenticator
                SET status = 'revoked',
                    revoked_at = ?
                WHERE account_id = ?
                  AND authenticator_kind = 'totp'
                  AND status = 'pending'
                  AND revoked_at IS NULL
                """,
                (
                    now,
                    account_session["account_id"],
                ),
            )

            self.connection.execute(
                """
                INSERT INTO mfa_authenticator(
                    authenticator_id,
                    account_id,
                    authenticator_kind,
                    secret_reference,
                    status,
                    verified_at,
                    revoked_at,
                    created_at
                ) VALUES (?, ?, 'totp', ?, 'pending', NULL, NULL, ?)
                """,
                (
                    authenticator_id,
                    account_session["account_id"],
                    reference,
                    now,
                ),
            )

        return authenticator_id

    @_synchronized
    def complete_totp_enrollment(
        self,
        bearer: str,
        account_session_id: str,
        authenticator_id: str,
        broker_attestation_token: str,
    ) -> str:
        account_session = self._load_account_session(
            bearer,
            account_session_id,
        )

        authenticator = self.connection.execute(
            """
            SELECT *
            FROM mfa_authenticator
            WHERE authenticator_id = ?
              AND account_id = ?
              AND authenticator_kind = 'totp'
              AND status = 'pending'
              AND verified_at IS NULL
              AND revoked_at IS NULL
            """,
            (
                authenticator_id,
                account_session["account_id"],
            ),
        ).fetchone()

        if authenticator is None:
            raise AuthorityError("pending MFA authenticator unavailable")

        now = _now()
        self.connection.execute("BEGIN IMMEDIATE")

        try:
            self._consume_mfa_broker_attestation(
                account_session["account_id"],
                account_session_id,
                authenticator_id,
                broker_attestation_token,
                "mfa.enroll",
                now,
            )

            updated = self.connection.execute(
                """
                UPDATE mfa_authenticator
                SET status = 'active',
                    verified_at = ?
                WHERE authenticator_id = ?
                  AND account_id = ?
                  AND status = 'pending'
                  AND verified_at IS NULL
                  AND revoked_at IS NULL
                """,
                (
                    now,
                    authenticator_id,
                    account_session["account_id"],
                ),
            )

            if updated.rowcount != 1:
                raise AuthorityError(
                    "pending MFA authenticator unavailable"
                )

            self.connection.commit()
            return authenticator_id

        except Exception:
            self.connection.rollback()
            raise

    @_synchronized
    def issue_mfa_recovery_codes(
        self,
        bearer: str,
        account_session_id: str,
        count: int = 8,
        step_up_token: str | None = None,
    ) -> list[str]:
        account_session = self._load_account_session(
            bearer,
            account_session_id,
        )

        _require_positive_integer(count, "MFA recovery code count", maximum=20)

        authenticator = self._active_mfa_authenticator(
            account_session["account_id"]
        )

        if authenticator is None:
            raise AuthorityError("active MFA authenticator required")

        existing = self.connection.execute(
            """
            SELECT COUNT(*) AS total
            FROM mfa_recovery_code
            WHERE account_id = ?
            """,
            (account_session["account_id"],),
        ).fetchone()

        rotation_required = existing["total"] > 0
        now = _now()

        self.connection.execute("BEGIN IMMEDIATE")

        try:
            if rotation_required:
                if not step_up_token:
                    raise AuthorityError(
                        "MFA step-up required for recovery code rotation"
                    )

                digest = _token_digest(step_up_token)

                receipt = self.connection.execute(
                    """
                    SELECT *
                    FROM mfa_step_up_receipt
                    WHERE token_sha256 = ?
                    """,
                    (digest,),
                ).fetchone()

                if receipt is None:
                    raise AuthorityError("MFA step-up unavailable")

                if receipt["status"] != "active":
                    raise AuthorityError("MFA step-up unavailable")

                if receipt["consumed_at"] is not None:
                    raise AuthorityError("MFA step-up consumed")

                if receipt["revoked_at"] is not None:
                    raise AuthorityError("MFA step-up revoked")

                if receipt["expires_at"] <= now:
                    raise AuthorityError("MFA step-up expired")

                if (
                    receipt["account_id"]
                    != account_session["account_id"]
                ):
                    raise AuthorityError("MFA step-up account mismatch")

                if (
                    receipt["account_session_id"]
                    != account_session_id
                ):
                    raise AuthorityError("MFA step-up session mismatch")

                if receipt["purpose"] != "mfa.recovery.rotate":
                    raise AuthorityError("MFA step-up purpose mismatch")

                if (
                    receipt["authenticator_id"]
                    != authenticator["authenticator_id"]
                ):
                    raise AuthorityError("MFA authenticator mismatch")

                consumed = self.connection.execute(
                    """
                    UPDATE mfa_step_up_receipt
                    SET status = 'consumed',
                        consumed_at = ?
                    WHERE step_up_id = ?
                      AND status = 'active'
                      AND consumed_at IS NULL
                      AND revoked_at IS NULL
                    """,
                    (
                        now,
                        receipt["step_up_id"],
                    ),
                )

                if consumed.rowcount != 1:
                    raise AuthorityError("MFA step-up unavailable")

            codes = [
                secrets.token_urlsafe(12)
                for _ in range(count)
            ]

            self.connection.execute(
                """
                UPDATE mfa_recovery_code
                SET status = 'revoked',
                    revoked_at = ?
                WHERE account_id = ?
                  AND status = 'active'
                  AND consumed_at IS NULL
                  AND revoked_at IS NULL
                """,
                (
                    now,
                    account_session["account_id"],
                ),
            )

            for code in codes:
                self.connection.execute(
                    """
                    INSERT INTO mfa_recovery_code(
                        recovery_code_id,
                        account_id,
                        code_sha256,
                        consumed_at,
                        revoked_at,
                        status,
                        created_at
                    ) VALUES (?, ?, ?, NULL, NULL, 'active', ?)
                    """,
                    (
                        _new_id("mfa_recovery"),
                        account_session["account_id"],
                        _token_digest(code),
                        now,
                    ),
                )

            self.connection.commit()
            return codes

        except Exception:
            self.connection.rollback()
            raise

    @_synchronized
    def exchange_mfa_broker_attestation(
        self,
        bearer: str,
        account_session_id: str,
        authenticator_id: str,
        broker_attestation_token: str,
        purpose: str,
        ttl_seconds: int = 300,
    ) -> tuple[str, str]:
        account_session = self._load_account_session(
            bearer,
            account_session_id,
        )

        normalized_purpose = self._require_mfa_purpose(purpose)

        if normalized_purpose == "mfa.enroll":
            raise AuthorityError(
                "enrollment attestation cannot mint step-up"
            )

        authenticator = self._active_mfa_authenticator(
            account_session["account_id"]
        )

        if authenticator is None:
            raise AuthorityError("active MFA authenticator required")

        if authenticator["authenticator_id"] != authenticator_id:
            raise AuthorityError("MFA authenticator mismatch")

        now = _now()
        self.connection.execute("BEGIN IMMEDIATE")

        try:
            self._consume_mfa_broker_attestation(
                account_session["account_id"],
                account_session_id,
                authenticator_id,
                broker_attestation_token,
                normalized_purpose,
                now,
            )

            step_up = self._mint_mfa_step_up(
                account_session["account_id"],
                account_session_id,
                authenticator_id,
                normalized_purpose,
                ttl_seconds,
                now,
            )

            self.connection.commit()
            return step_up

        except Exception:
            self.connection.rollback()
            raise

    @_synchronized
    def exchange_mfa_recovery_code(
        self,
        bearer: str,
        account_session_id: str,
        recovery_code: str,
        purpose: str,
        ttl_seconds: int = 300,
    ) -> tuple[str, str]:
        account_session = self._load_account_session(
            bearer,
            account_session_id,
        )

        normalized_purpose = self._require_mfa_purpose(purpose)

        if normalized_purpose == "mfa.enroll":
            raise AuthorityError(
                "recovery code cannot authorize enrollment"
            )

        authenticator = self._active_mfa_authenticator(
            account_session["account_id"]
        )

        if authenticator is None:
            raise AuthorityError("active MFA authenticator required")

        digest = _token_digest(recovery_code)
        now = _now()

        self.connection.execute("BEGIN IMMEDIATE")

        try:
            recovery = self.connection.execute(
                """
                SELECT *
                FROM mfa_recovery_code
                WHERE code_sha256 = ?
                  AND account_id = ?
                """,
                (
                    digest,
                    account_session["account_id"],
                ),
            ).fetchone()

            if recovery is None:
                raise AuthorityError("MFA recovery code unavailable")

            if recovery["status"] != "active":
                raise AuthorityError("MFA recovery code unavailable")

            if recovery["consumed_at"] is not None:
                raise AuthorityError("MFA recovery code consumed")

            if recovery["revoked_at"] is not None:
                raise AuthorityError("MFA recovery code revoked")

            consumed = self.connection.execute(
                """
                UPDATE mfa_recovery_code
                SET status = 'consumed',
                    consumed_at = ?
                WHERE recovery_code_id = ?
                  AND status = 'active'
                  AND consumed_at IS NULL
                  AND revoked_at IS NULL
                """,
                (
                    now,
                    recovery["recovery_code_id"],
                ),
            )

            if consumed.rowcount != 1:
                raise AuthorityError("MFA recovery code unavailable")

            step_up = self._mint_mfa_step_up(
                account_session["account_id"],
                account_session_id,
                authenticator["authenticator_id"],
                normalized_purpose,
                ttl_seconds,
                now,
            )

            self.connection.commit()
            return step_up

        except Exception:
            self.connection.rollback()
            raise

    def _consume_mfa_step_up_for_action(
        self,
        account_id: str,
        account_session_id: str,
        step_up_token: str,
        purpose: str,
        now: float,
    ) -> str:
        normalized_purpose = self._require_mfa_purpose(purpose)

        if normalized_purpose == "mfa.enroll":
            raise AuthorityError(
                "enrollment cannot consume step-up receipt"
            )

        digest = _token_digest(step_up_token)

        receipt = self.connection.execute(
            """
            SELECT *
            FROM mfa_step_up_receipt
            WHERE token_sha256 = ?
            """,
            (digest,),
        ).fetchone()

        if receipt is None:
            raise AuthorityError("MFA step-up unavailable")

        if receipt["status"] != "active":
            raise AuthorityError("MFA step-up unavailable")

        if receipt["consumed_at"] is not None:
            raise AuthorityError("MFA step-up consumed")

        if receipt["revoked_at"] is not None:
            raise AuthorityError("MFA step-up revoked")

        if receipt["expires_at"] <= now:
            raise AuthorityError("MFA step-up expired")

        if receipt["account_id"] != account_id:
            raise AuthorityError("MFA step-up account mismatch")

        if receipt["account_session_id"] != account_session_id:
            raise AuthorityError("MFA step-up session mismatch")

        if receipt["purpose"] != normalized_purpose:
            raise AuthorityError("MFA step-up purpose mismatch")

        authenticator = self._active_mfa_authenticator(account_id)

        if authenticator is None:
            raise AuthorityError("active MFA authenticator required")

        if (
            authenticator["authenticator_id"]
            != receipt["authenticator_id"]
        ):
            raise AuthorityError("MFA authenticator mismatch")

        consumed = self.connection.execute(
            """
            UPDATE mfa_step_up_receipt
            SET status = 'consumed',
                consumed_at = ?
            WHERE step_up_id = ?
              AND status = 'active'
              AND consumed_at IS NULL
              AND revoked_at IS NULL
            """,
            (
                now,
                receipt["step_up_id"],
            ),
        )

        if consumed.rowcount != 1:
            raise AuthorityError("MFA step-up unavailable")

        return receipt["authenticator_id"]

    @_synchronized
    def consume_mfa_step_up(
        self,
        bearer: str,
        account_session_id: str,
        step_up_token: str,
        purpose: str,
    ) -> str:
        account_session = self._load_account_session(
            bearer,
            account_session_id,
        )

        now = _now()
        self.connection.execute("BEGIN IMMEDIATE")

        try:
            authenticator_id = self._consume_mfa_step_up_for_action(
                account_session["account_id"],
                account_session_id,
                step_up_token,
                purpose,
                now,
            )

            self.connection.commit()
            return authenticator_id

        except Exception:
            self.connection.rollback()
            raise

    @_synchronized
    def request_email_change(
        self,
        bearer: str,
        account_session_id: str,
        current_password: str,
        proposed_email: str,
        ttl_seconds: int = 900,
        step_up_token: str | None = None,
    ) -> tuple[str, str]:
        account_session = self._load_account_session(
            bearer,
            account_session_id,
        )

        normalized_email = _normalize_email(proposed_email)

        _require_positive_integer(ttl_seconds, "email change TTL")

        current_email = self.connection.execute(
            """
            SELECT normalized_email
            FROM account_email
            WHERE account_id = ?
              AND status = 'active'
              AND verified_at IS NOT NULL
            """,
            (account_session["account_id"],),
        ).fetchone()

        if current_email is None:
            raise AuthorityError("active email unavailable")

        if current_email["normalized_email"] == normalized_email:
            raise AuthorityError(
                "new email must differ from current email"
            )

        credential = self.connection.execute(
            """
            SELECT password_hash
            FROM password_credential
            WHERE account_id = ?
              AND status = 'active'
            """,
            (account_session["account_id"],),
        ).fetchone()

        if credential is None:
            raise AuthorityError("active credential unavailable")

        try:
            verified = _PASSWORD_HASHER.verify(
                credential["password_hash"],
                str(current_password or ""),
            )
        except (VerifyMismatchError, InvalidHashError) as exc:
            raise AuthorityError("current password invalid") from exc

        if not verified:
            raise AuthorityError("current password invalid")

        conflict = self.connection.execute(
            """
            SELECT account_id
            FROM account_email
            WHERE normalized_email = ?
            """,
            (normalized_email,),
        ).fetchone()

        if conflict is not None:
            raise AuthorityError("email unavailable")

        email_change_id = _new_id("email_change")
        token = secrets.token_urlsafe(32)
        token_sha256 = _token_digest(token)
        now = _now()

        self.connection.execute("BEGIN IMMEDIATE")

        try:
            authenticator = self._active_mfa_authenticator(
                account_session["account_id"]
            )

            if authenticator is not None:
                if not step_up_token:
                    raise AuthorityError(
                        "MFA step-up required for email change"
                    )

                self._consume_mfa_step_up_for_action(
                    account_session["account_id"],
                    account_session_id,
                    step_up_token,
                    "email.change",
                    now,
                )

            self.connection.execute(
                """
                UPDATE email_change_challenge
                SET status = 'revoked',
                    revoked_at = ?
                WHERE account_id = ?
                  AND status = 'active'
                  AND consumed_at IS NULL
                  AND revoked_at IS NULL
                """,
                (
                    now,
                    account_session["account_id"],
                ),
            )

            self.connection.execute(
                """
                INSERT INTO email_change_challenge(
                    email_change_id,
                    account_id,
                    proposed_email,
                    token_sha256,
                    expires_at,
                    consumed_at,
                    revoked_at,
                    status,
                    created_at
                ) VALUES (?, ?, ?, ?, ?, NULL, NULL, 'active', ?)
                """,
                (
                    email_change_id,
                    account_session["account_id"],
                    normalized_email,
                    token_sha256,
                    now + ttl_seconds,
                    now,
                ),
            )

            self.connection.commit()
            return email_change_id, token

        except Exception:
            self.connection.rollback()
            raise

    @_synchronized
    def consume_email_change(
        self,
        token: str,
    ) -> str:
        digest = _token_digest(token)
        now = _now()

        self.connection.execute("BEGIN IMMEDIATE")

        try:
            challenge = self.connection.execute(
                """
                SELECT *
                FROM email_change_challenge
                WHERE token_sha256 = ?
                """,
                (digest,),
            ).fetchone()

            if challenge is None:
                raise AuthorityError("email change unavailable")

            if challenge["status"] != "active":
                raise AuthorityError("email change unavailable")

            if challenge["consumed_at"] is not None:
                raise AuthorityError("email change consumed")

            if challenge["revoked_at"] is not None:
                raise AuthorityError("email change revoked")

            if challenge["expires_at"] <= now:
                raise AuthorityError("email change expired")

            conflict = self.connection.execute(
                """
                SELECT account_id
                FROM account_email
                WHERE normalized_email = ?
                  AND account_id != ?
                """,
                (
                    challenge["proposed_email"],
                    challenge["account_id"],
                ),
            ).fetchone()

            if conflict is not None:
                raise AuthorityError("email unavailable")

            updated = self.connection.execute(
                """
                UPDATE account_email
                SET normalized_email = ?,
                    verified_at = ?,
                    status = 'active'
                WHERE account_id = ?
                  AND status = 'active'
                  AND verified_at IS NOT NULL
                """,
                (
                    challenge["proposed_email"],
                    now,
                    challenge["account_id"],
                ),
            )

            if updated.rowcount != 1:
                raise AuthorityError("active email unavailable")

            consumed = self.connection.execute(
                """
                UPDATE email_change_challenge
                SET status = 'consumed',
                    consumed_at = ?
                WHERE email_change_id = ?
                  AND status = 'active'
                  AND consumed_at IS NULL
                  AND revoked_at IS NULL
                """,
                (
                    now,
                    challenge["email_change_id"],
                ),
            )

            if consumed.rowcount != 1:
                raise AuthorityError("email change unavailable")

            self.connection.execute(
                """
                UPDATE email_change_challenge
                SET status = 'revoked',
                    revoked_at = ?
                WHERE account_id = ?
                  AND email_change_id != ?
                  AND status = 'active'
                  AND consumed_at IS NULL
                  AND revoked_at IS NULL
                """,
                (
                    now,
                    challenge["account_id"],
                    challenge["email_change_id"],
                ),
            )

            self._revoke_account_authority(
                challenge["account_id"],
                now,
            )

            self.connection.commit()
            return challenge["account_id"]

        except Exception:
            self.connection.rollback()
            raise

    @_synchronized
    def change_display_name(
        self,
        bearer: str,
        account_session_id: str,
        display_name: str,
    ) -> None:
        account_session = self._load_account_session(
            bearer,
            account_session_id,
        )
        name = str(display_name or "").strip()

        if not name:
            raise AuthorityError("display name is required")

        with self.connection:
            updated = self.connection.execute(
                """
                UPDATE identity
                SET display_name = ?
                WHERE identity_id = ?
                  AND status = 'active'
                """,
                (
                    name,
                    account_session["identity_id"],
                ),
            )

            if updated.rowcount != 1:
                raise AuthorityError("active identity unavailable")

    @_synchronized
    def create_identity(
        self,
        display_name: str,
        identity_kind: str = "human",
    ) -> str:
        identity_id = _new_id("identity")
        kind = normalize_symbol(identity_kind)
        name = str(display_name or "").strip()

        if not name:
            raise AuthorityError("display name is required")

        self.connection.execute(
            """
            INSERT INTO identity(
                identity_id,
                identity_kind,
                display_name,
                status,
                created_at
            ) VALUES (?, ?, ?, 'active', ?)
            """,
            (identity_id, kind, name, _now()),
        )
        self.connection.commit()
        return identity_id

    @_synchronized
    def create_personal_account(self, identity_id: str) -> str:
        validate_typed_id(identity_id, "idn")
        account_id = _new_id("account")

        self.connection.execute(
            """
            INSERT INTO personal_account(
                account_id,
                identity_id,
                status,
                created_at
            ) VALUES (?, ?, 'active', ?)
            """,
            (account_id, identity_id, _now()),
        )
        self.connection.commit()
        return account_id

    @_synchronized
    def create_organization(self, canonical_name: str) -> tuple[str, str]:
        name = str(canonical_name or "").strip()

        if not name:
            raise AuthorityError("organization name is required")

        organization_id = _new_id("organization")
        tenant_id = _new_id("tenant")
        now = _now()

        with self.connection:
            self.connection.execute(
                """
                INSERT INTO organization(
                    organization_id,
                    canonical_name,
                    status,
                    hydration_version,
                    created_at
                ) VALUES (?, ?, 'active', 1, ?)
                """,
                (organization_id, name, now),
            )
            self.connection.execute(
                """
                INSERT INTO tenant(
                    tenant_id,
                    organization_id,
                    status,
                    created_at
                ) VALUES (?, ?, 'active', ?)
                """,
                (tenant_id, organization_id, now),
            )

        return organization_id, tenant_id

    @_synchronized
    def define_role(
        self,
        symbolic_name: str,
        grants: Iterable[str] = (),
        prohibitions: Iterable[str] = (),
        role_definition_id: str | None = None,
        version: int = 1,
    ) -> VersionedDefinitionRef:
        role_id = role_definition_id or _new_id("role")
        validate_typed_id(role_id, "rol")

        _require_positive_integer(version, "role version")

        canonical_name = normalize_symbol(symbolic_name)
        canonical_grants = sorted({normalize_symbol(item) for item in grants})
        canonical_prohibitions = sorted(
            {normalize_symbol(item) for item in prohibitions}
        )

        self.connection.execute(
            """
            INSERT INTO role_definition(
                role_definition_id,
                version,
                symbolic_name,
                status,
                grants_json,
                prohibitions_json,
                created_at
            ) VALUES (?, ?, ?, 'active', ?, ?, ?)
            """,
            (
                role_id,
                version,
                canonical_name,
                canonical_json(canonical_grants),
                canonical_json(canonical_prohibitions),
                _now(),
            ),
        )
        self.connection.commit()

        return VersionedDefinitionRef(role_id, version)

    @_synchronized
    def define_policy(
        self,
        symbolic_name: str,
        version: int = 1,
    ) -> VersionedDefinitionRef:
        canonical_name = normalize_symbol(symbolic_name)

        _require_positive_integer(
            version,
            "policy definition version",
        )

        policy_definition_id = _stable_policy_definition_id(canonical_name)

        self.connection.execute(
            """
            INSERT INTO policy_definition(
                policy_definition_id,
                version,
                symbolic_name,
                status,
                created_at
            ) VALUES (?, ?, ?, 'active', ?)
            """,
            (
                policy_definition_id,
                version,
                canonical_name,
                _now(),
            ),
        )
        self.connection.commit()

        return VersionedDefinitionRef(policy_definition_id, version)

    @_synchronized
    def define_entitlement(
        self,
        symbolic_name: str,
        entitlement_definition_id: str | None = None,
        version: int = 1,
    ) -> VersionedDefinitionRef:
        entitlement_id = entitlement_definition_id or _new_id("entitlement")
        validate_typed_id(entitlement_id, "ent")

        _require_positive_integer(version, "entitlement version")

        self.connection.execute(
            """
            INSERT INTO entitlement_definition(
                entitlement_definition_id,
                version,
                symbolic_name,
                status,
                created_at
            ) VALUES (?, ?, ?, 'active', ?)
            """,
            (
                entitlement_id,
                version,
                normalize_symbol(symbolic_name),
                _now(),
            ),
        )
        self.connection.commit()

        return VersionedDefinitionRef(entitlement_id, version)

    @_synchronized
    def define_adapter(self, symbolic_name: str) -> str:
        adapter_id = _new_id("adapter")

        self.connection.execute(
            """
            INSERT INTO adapter_definition(
                adapter_definition_id,
                symbolic_name,
                status,
                created_at
            ) VALUES (?, ?, 'active', ?)
            """,
            (adapter_id, normalize_symbol(symbolic_name), _now()),
        )
        self.connection.commit()
        return adapter_id

    @_synchronized
    def define_operation(
        self,
        adapter_definition_id: str,
        symbolic_name: str,
    ) -> str:
        validate_typed_id(adapter_definition_id, "adp")
        operation_id = _new_id("operation")

        self.connection.execute(
            """
            INSERT INTO operation_definition(
                operation_definition_id,
                adapter_definition_id,
                symbolic_name,
                status,
                created_at
            ) VALUES (?, ?, ?, 'active', ?)
            """,
            (
                operation_id,
                adapter_definition_id,
                normalize_symbol(symbolic_name),
                _now(),
            ),
        )
        self.connection.commit()
        return operation_id

    @_synchronized
    def issue_invitation(
        self,
        organization_id: str,
        tenant_id: str,
        role_refs: Iterable[VersionedDefinitionRef],
        entitlement_refs: Iterable[VersionedDefinitionRef],
        ttl_seconds: int = 3600,
    ) -> tuple[str, str]:
        validate_typed_id(organization_id, "org")
        validate_typed_id(tenant_id, "tnt")

        _require_positive_integer(ttl_seconds, "invitation TTL")

        authority_scope = self.connection.execute(
            """
            SELECT 1
            FROM organization AS o
            JOIN tenant AS t
              ON t.organization_id = o.organization_id
            WHERE o.organization_id = ?
              AND t.tenant_id = ?
              AND o.status = 'active'
              AND t.status = 'active'
            """,
            (
                organization_id,
                tenant_id,
            ),
        ).fetchone()

        if authority_scope is None:
            raise AuthorityError("active organization tenant scope required")

        invitation_id = _new_id("invitation")
        code = secrets.token_urlsafe(32)
        digest = hashlib.sha256(code.encode("utf-8")).hexdigest()

        role_documents = [
            {
                "definitionId": item.definition_id,
                "version": item.version,
            }
            for item in role_refs
        ]

        entitlement_documents = [
            {
                "definitionId": item.definition_id,
                "version": item.version,
            }
            for item in entitlement_refs
        ]

        for item in role_documents:
            active_role = self.connection.execute(
                """
                SELECT 1
                FROM role_definition
                WHERE role_definition_id = ?
                  AND version = ?
                  AND status = 'active'
                """,
                (
                    item["definitionId"],
                    item["version"],
                ),
            ).fetchone()

            if active_role is None:
                raise AuthorityError("active role definition required")

        for item in entitlement_documents:
            active_entitlement = self.connection.execute(
                """
                SELECT 1
                FROM entitlement_definition
                WHERE entitlement_definition_id = ?
                  AND version = ?
                  AND status = 'active'
                """,
                (
                    item["definitionId"],
                    item["version"],
                ),
            ).fetchone()

            if active_entitlement is None:
                raise AuthorityError("active entitlement definition required")

        self.connection.execute(
            """
            INSERT INTO invitation(
                invitation_id,
                code_sha256,
                organization_id,
                tenant_id,
                role_refs_json,
                entitlement_refs_json,
                expires_at,
                maximum_uses,
                consumed_uses,
                status,
                created_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, 1, 0, 'active', ?)
            """,
            (
                invitation_id,
                digest,
                organization_id,
                tenant_id,
                canonical_json(role_documents),
                canonical_json(entitlement_documents),
                _now() + ttl_seconds,
                _now(),
            ),
        )
        self.connection.commit()

        return invitation_id, code

    @_synchronized
    def redeem_invitation(self, code: str, identity_id: str) -> str:
        validate_typed_id(identity_id, "idn")
        digest = hashlib.sha256(str(code).encode("utf-8")).hexdigest()
        now = _now()

        self.connection.execute("BEGIN IMMEDIATE")

        try:
            invitation = self.connection.execute(
                """
                SELECT *
                FROM invitation
                WHERE code_sha256 = ?
                """,
                (digest,),
            ).fetchone()

            if invitation is None:
                raise AuthorityError("invitation unavailable")

            if invitation["status"] != "active":
                raise AuthorityError("invitation unavailable")

            if invitation["expires_at"] <= now:
                raise AuthorityError("invitation expired")

            if invitation["consumed_uses"] >= invitation["maximum_uses"]:
                raise AuthorityError("invitation consumed")

            existing = self.connection.execute(
                """
                SELECT membership_id
                FROM membership
                WHERE identity_id = ?
                  AND organization_id = ?
                  AND status IN ('active', 'suspended')
                """,
                (identity_id, invitation["organization_id"]),
            ).fetchone()

            if existing is not None:
                raise AuthorityError("current membership already exists")

            membership_id = _new_id("membership")

            self.connection.execute(
                """
                INSERT INTO membership(
                    membership_id,
                    identity_id,
                    organization_id,
                    status,
                    authorization_version,
                    entitlement_version,
                    created_at
                ) VALUES (?, ?, ?, 'active', 1, 1, ?)
                """,
                (
                    membership_id,
                    identity_id,
                    invitation["organization_id"],
                    now,
                ),
            )

            for item in json.loads(invitation["role_refs_json"]):
                self.connection.execute(
                    """
                    INSERT INTO role_assignment(
                        role_assignment_id,
                        membership_id,
                        role_definition_id,
                        role_version,
                        status,
                        created_at
                    ) VALUES (?, ?, ?, ?, 'active', ?)
                    """,
                    (
                        _new_id("role_assignment"),
                        membership_id,
                        item["definitionId"],
                        item["version"],
                        now,
                    ),
                )

            for item in json.loads(invitation["entitlement_refs_json"]):
                self.connection.execute(
                    """
                    INSERT INTO entitlement_grant(
                        entitlement_grant_id,
                        membership_id,
                        entitlement_definition_id,
                        entitlement_version,
                        status,
                        created_at
                    ) VALUES (?, ?, ?, ?, 'active', ?)
                    """,
                    (
                        _new_id("entitlement_grant"),
                        membership_id,
                        item["definitionId"],
                        item["version"],
                        now,
                    ),
                )

            self.connection.execute(
                """
                UPDATE invitation
                SET consumed_uses = consumed_uses + 1,
                    status = 'consumed'
                WHERE invitation_id = ?
                  AND status = 'active'
                  AND consumed_uses < maximum_uses
                """,
                (invitation["invitation_id"],),
            )

            self.connection.commit()
            return membership_id

        except Exception:
            self.connection.rollback()
            raise

    @_synchronized
    def grant_adapter_operation(
        self,
        membership_id: str,
        adapter_definition_id: str,
        operation_definition_id: str,
        entitlement_definition: VersionedDefinitionRef,
        resource_scope: Any,
        policy_definition: VersionedDefinitionRef,
        policy_version: str,
    ) -> str:
        validate_typed_id(membership_id, "mbr")
        validate_typed_id(adapter_definition_id, "adp")
        validate_typed_id(operation_definition_id, "opn")
        validate_typed_id(
            entitlement_definition.definition_id,
            "ent",
        )
        validate_typed_id(
            policy_definition.definition_id,
            "pol",
        )

        policy = self.connection.execute(
            """
            SELECT status
            FROM policy_definition
            WHERE policy_definition_id = ?
              AND version = ?
            """,
            (
                policy_definition.definition_id,
                policy_definition.version,
            ),
        ).fetchone()

        if policy is None or policy["status"] != "active":
            raise AuthorityError("active policy definition required")

        entitlement = self.connection.execute(
            """
            SELECT entitlement_grant_id
            FROM entitlement_grant
            WHERE membership_id = ?
              AND entitlement_definition_id = ?
              AND entitlement_version = ?
              AND status = 'active'
            """,
            (
                membership_id,
                entitlement_definition.definition_id,
                entitlement_definition.version,
            ),
        ).fetchone()

        if entitlement is None:
            raise AuthorityError(
                "active entitlement grant required for adapter authority"
            )

        operation = self.connection.execute(
            """
            SELECT adapter_definition_id
            FROM operation_definition
            WHERE operation_definition_id = ?
              AND status = 'active'
            """,
            (operation_definition_id,),
        ).fetchone()

        if operation is None:
            raise AuthorityError("active operation definition required")

        if operation["adapter_definition_id"] != adapter_definition_id:
            raise AuthorityError(
                "operation definition does not belong to adapter definition"
            )

        binding_id = _new_id("binding")

        with self.connection:
            self.connection.execute(
                """
                INSERT INTO adapter_grant_binding(
                    binding_id,
                    membership_id,
                    adapter_definition_id,
                    operation_definition_id,
                    entitlement_definition_id,
                    entitlement_definition_version,
                    resource_scope_json,
                    policy_definition_id,
                    policy_definition_version,
                    policy_version,
                    status,
                    created_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'active', ?)
                """,
                (
                    binding_id,
                    membership_id,
                    adapter_definition_id,
                    operation_definition_id,
                    entitlement_definition.definition_id,
                    entitlement_definition.version,
                    canonical_json(resource_scope),
                    policy_definition.definition_id,
                    policy_definition.version,
                    normalize_symbol(policy_version),
                    _now(),
                ),
            )

            self.connection.execute(
                """
                UPDATE membership
                SET authorization_version = authorization_version + 1
                WHERE membership_id = ?
                """,
                (membership_id,),
            )

        return binding_id

    @_synchronized
    def derive_organization_session(
        self,
        account_bearer: str,
        account_session_id: str,
        organization_id: str,
        ttl_seconds: int = 3600,
    ) -> tuple[str, str]:
        validate_typed_id(account_session_id, "acs")
        validate_typed_id(organization_id, "org")

        _require_positive_integer(ttl_seconds, "session TTL")

        account_session = self._load_account_session(
            account_bearer,
            account_session_id,
        )

        identity_id = account_session["identity_id"]
        account_id = account_session["account_id"]

        membership = self.connection.execute(
            """
            SELECT *
            FROM membership
            WHERE identity_id = ?
              AND organization_id = ?
              AND status = 'active'
            """,
            (
                identity_id,
                organization_id,
            ),
        ).fetchone()

        if membership is None:
            raise AuthorityError("active membership required")

        tenant = self.connection.execute(
            """
            SELECT *
            FROM tenant
            WHERE organization_id = ?
              AND status = 'active'
            """,
            (organization_id,),
        ).fetchone()

        if tenant is None:
            raise AuthorityError("active tenant required")

        session_id = _new_id("session")
        bearer = secrets.token_urlsafe(32)
        bearer_sha256 = _token_digest(bearer)
        now = _now()

        with self.connection:
            self.connection.execute(
                """
                INSERT INTO session(
                    session_id,
                    bearer_sha256,
                    identity_id,
                    account_id,
                    membership_id,
                    organization_id,
                    tenant_id,
                    account_session_id,
                    authorization_version,
                    entitlement_version,
                    credential_revision,
                    expires_at,
                    status,
                    revoked_at,
                    created_at
                ) VALUES (
                    ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'active', NULL, ?
                )
                """,
                (
                    session_id,
                    bearer_sha256,
                    identity_id,
                    account_id,
                    membership["membership_id"],
                    organization_id,
                    tenant["tenant_id"],
                    account_session_id,
                    membership["authorization_version"],
                    membership["entitlement_version"],
                    account_session["credential_revision"],
                    min(now + ttl_seconds, account_session["expires_at"]),
                    now,
                ),
            )

        return session_id, bearer

    @_synchronized
    def create_session(
        self,
        identity_id: str,
        account_id: str,
        organization_id: str,
        ttl_seconds: int = 3600,
    ) -> tuple[str, str]:
        raise AuthorityError(
            "legacy session creation disabled; authenticated account session required"
        )

    @_synchronized
    def authenticate(
        self,
        bearer: str,
        session_id: str,
    ) -> AuthorizedSubject:
        validate_typed_id(session_id, "ses")

        supplied = str(bearer or "")

        if not supplied:
            raise AuthorityError("unauthorized")

        supplied_sha256 = hashlib.sha256(
            supplied.encode("utf-8")
        ).hexdigest()

        session = self.connection.execute(
            """
            SELECT session_id
            FROM session
            WHERE bearer_sha256 = ?
            """,
            (supplied_sha256,),
        ).fetchone()

        if session is None:
            raise AuthorityError("unauthorized")

        if not secrets.compare_digest(
            session["session_id"],
            session_id,
        ):
            raise AuthorityError("session mismatch")

        return self.project_authorized_subject(session_id)

    @_synchronized
    def ensure_cloud_spine_definitions(self) -> dict[str, object]:
        adapter_definition_id = "adp_8e8d46ef8dc04ec58e8719ed9609ed1a"
        operation_definition_id = "opn_337f67b7a38f445e8830e950e81226e1"
        entitlement_definition_id = "ent_1ad920a8de4b46eda4925c0037c21b11"
        entitlement_definition_version = 1
        created_at = _now()

        with self.connection:
            self.connection.execute(
                """
                INSERT OR IGNORE INTO entitlement_definition(
                    entitlement_definition_id,
                    version,
                    symbolic_name,
                    status,
                    created_at
                ) VALUES (?, ?, ?, 'active', ?)
                """,
                (
                    entitlement_definition_id,
                    entitlement_definition_version,
                    "spine.account.status.read",
                    created_at,
                ),
            )

            self.connection.execute(
                """
                INSERT OR IGNORE INTO adapter_definition(
                    adapter_definition_id,
                    symbolic_name,
                    status,
                    created_at
                ) VALUES (?, ?, 'active', ?)
                """,
                (
                    adapter_definition_id,
                    "spine.core",
                    created_at,
                ),
            )

            self.connection.execute(
                """
                INSERT OR IGNORE INTO operation_definition(
                    operation_definition_id,
                    adapter_definition_id,
                    symbolic_name,
                    status,
                    created_at
                ) VALUES (?, ?, ?, 'active', ?)
                """,
                (
                    operation_definition_id,
                    adapter_definition_id,
                    "fetch-account-status",
                    created_at,
                ),
            )

        entitlement = self.connection.execute(
            """
            SELECT symbolic_name, status
            FROM entitlement_definition
            WHERE entitlement_definition_id = ?
              AND version = ?
            """,
            (
                entitlement_definition_id,
                entitlement_definition_version,
            ),
        ).fetchone()

        adapter = self.connection.execute(
            """
            SELECT symbolic_name, status
            FROM adapter_definition
            WHERE adapter_definition_id = ?
            """,
            (adapter_definition_id,),
        ).fetchone()

        operation = self.connection.execute(
            """
            SELECT adapter_definition_id, symbolic_name, status
            FROM operation_definition
            WHERE operation_definition_id = ?
            """,
            (operation_definition_id,),
        ).fetchone()

        if entitlement is None:
            raise AuthorityError("Cloud Spine entitlement definition unavailable")

        if adapter is None:
            raise AuthorityError("Cloud Spine adapter definition unavailable")

        if operation is None:
            raise AuthorityError("Cloud Spine operation definition unavailable")

        if (
            entitlement["symbolic_name"] != "spine.account.status.read"
            or entitlement["status"] != "active"
        ):
            raise AuthorityError("Cloud Spine entitlement definition conflict")

        if (
            adapter["symbolic_name"] != "spine.core"
            or adapter["status"] != "active"
        ):
            raise AuthorityError("Cloud Spine adapter definition conflict")

        if (
            operation["adapter_definition_id"] != adapter_definition_id
            or operation["symbolic_name"] != "fetch-account-status"
            or operation["status"] != "active"
        ):
            raise AuthorityError("Cloud Spine operation definition conflict")

        return {
            "adapter_definition_id": adapter_definition_id,
            "operation_definition_id": operation_definition_id,
            "entitlement_definition": VersionedDefinitionRef(
                entitlement_definition_id,
                entitlement_definition_version,
            ),
        }
    @_synchronized
    def ready(self) -> bool:
        try:
            now = _now()
            rows = self.connection.execute(
                """
                SELECT s.session_id
                FROM session AS s
                JOIN membership AS m
                  ON m.membership_id = s.membership_id
                JOIN account_session AS acs
                  ON acs.account_session_id = s.account_session_id
                JOIN personal_account AS a
                  ON a.account_id = s.account_id
                JOIN password_credential AS pc
                  ON pc.account_id = a.account_id
                JOIN identity AS i
                  ON i.identity_id = s.identity_id
                JOIN organization AS o
                  ON o.organization_id = s.organization_id
                JOIN tenant AS t
                  ON t.tenant_id = s.tenant_id
                WHERE s.status = 'active'
                  AND s.expires_at > ?
                  AND s.revoked_at IS NULL
                  AND acs.status = 'active'
                  AND acs.expires_at > ?
                  AND acs.revoked_at IS NULL
                  AND acs.identity_id = s.identity_id
                  AND acs.account_id = s.account_id
                  AND acs.credential_revision = s.credential_revision
                  AND pc.status = 'active'
                  AND pc.credential_revision = acs.credential_revision
                  AND a.identity_id = s.identity_id
                  AND m.status = 'active'
                  AND m.identity_id = s.identity_id
                  AND m.organization_id = s.organization_id
                  AND a.status = 'active'
                  AND i.status = 'active'
                  AND o.status = 'active'
                  AND t.status = 'active'
                  AND t.organization_id = s.organization_id
                  AND s.authorization_version = m.authorization_version
                  AND s.entitlement_version = m.entitlement_version
                """,
                (now, now),
            ).fetchall()

            for row in rows:
                try:
                    self.project_authorized_subject(row["session_id"])
                    return True
                except (AuthorityError, ValueError):
                    continue

            return False
        except (sqlite3.Error, ValueError):
            return False

    @_synchronized
    def project_authorized_subject(
        self,
        session_id: str,
    ) -> AuthorizedSubject:
        validate_typed_id(session_id, "ses")
        now = _now()

        session = self.connection.execute(
            """
            SELECT *
            FROM session
            WHERE session_id = ?
            """,
            (session_id,),
        ).fetchone()

        if session is None:
            raise AuthorityError("session unavailable")

        if session["status"] != "active":
            raise AuthorityError("session inactive")

        if session["expires_at"] <= now:
            raise AuthorityError("session inactive")

        if session["revoked_at"] is not None:
            raise AuthorityError("session inactive")

        if session["account_session_id"] is None:
            raise AuthorityError("parent account session required")

        authority_graph = self.connection.execute(
            """
            SELECT
                acs.identity_id AS account_session_identity_id,
                acs.account_id AS account_session_account_id,
                acs.credential_revision AS account_session_credential_revision,
                acs.expires_at AS account_session_expires_at,
                acs.status AS account_session_status,
                acs.revoked_at AS account_session_revoked_at,
                pc.credential_revision AS current_credential_revision,
                pc.status AS credential_status,
                a.identity_id AS account_identity_id,
                a.status AS account_status,
                i.status AS identity_status,
                o.status AS organization_status,
                t.organization_id AS tenant_organization_id,
                t.status AS tenant_status
            FROM account_session AS acs
            JOIN password_credential AS pc
              ON pc.account_id = acs.account_id
            JOIN personal_account AS a
              ON a.account_id = acs.account_id
            JOIN identity AS i
              ON i.identity_id = acs.identity_id
            JOIN organization AS o
              ON o.organization_id = ?
            JOIN tenant AS t
              ON t.tenant_id = ?
            WHERE acs.account_session_id = ?
            """,
            (
                session["organization_id"],
                session["tenant_id"],
                session["account_session_id"],
            ),
        ).fetchone()

        if authority_graph is None:
            raise AuthorityError("authority graph unavailable")

        if (
            authority_graph["account_session_status"] != "active"
            or authority_graph["account_session_revoked_at"] is not None
            or authority_graph["account_session_expires_at"] <= now
        ):
            raise AuthorityError("parent account session inactive")

        if (
            authority_graph["account_session_identity_id"]
            != session["identity_id"]
            or authority_graph["account_session_account_id"]
            != session["account_id"]
            or authority_graph["account_identity_id"]
            != session["identity_id"]
            or authority_graph["tenant_organization_id"]
            != session["organization_id"]
        ):
            raise AuthorityError("authority graph mismatch")

        if (
            authority_graph["credential_status"] != "active"
            or authority_graph["current_credential_revision"]
            != authority_graph["account_session_credential_revision"]
            or session["credential_revision"]
            != authority_graph["account_session_credential_revision"]
        ):
            raise AuthorityError("credential revision stale")

        if (
            authority_graph["identity_status"] != "active"
            or authority_graph["account_status"] != "active"
            or authority_graph["organization_status"] != "active"
            or authority_graph["tenant_status"] != "active"
        ):
            raise AuthorityError("authority graph inactive")

        membership = self.connection.execute(
            """
            SELECT *
            FROM membership
            WHERE membership_id = ?
            """,
            (session["membership_id"],),
        ).fetchone()

        if membership is None or membership["status"] != "active":
            raise AuthorityError("membership inactive")

        if (
            membership["identity_id"] != session["identity_id"]
            or membership["organization_id"] != session["organization_id"]
        ):
            raise AuthorityError("membership authority mismatch")

        if session["authorization_version"] != membership["authorization_version"]:
            raise AuthorityError("authorization version stale")

        if session["entitlement_version"] != membership["entitlement_version"]:
            raise AuthorityError("entitlement version stale")

        role_rows = self.connection.execute(
            """
            SELECT
                ra.role_definition_id,
                ra.role_version,
                rd.status AS definition_status
            FROM role_assignment AS ra
            LEFT JOIN role_definition AS rd
              ON rd.role_definition_id = ra.role_definition_id
             AND rd.version = ra.role_version
            WHERE ra.membership_id = ?
              AND ra.status = 'active'
            ORDER BY ra.role_definition_id, ra.role_version
            """,
            (membership["membership_id"],),
        ).fetchall()

        if any(row["definition_status"] != "active" for row in role_rows):
            raise AuthorityError("role definition inactive")

        entitlement_rows = self.connection.execute(
            """
            SELECT
                eg.entitlement_definition_id,
                eg.entitlement_version,
                ed.status AS definition_status
            FROM entitlement_grant AS eg
            LEFT JOIN entitlement_definition AS ed
              ON ed.entitlement_definition_id = eg.entitlement_definition_id
             AND ed.version = eg.entitlement_version
            WHERE eg.membership_id = ?
              AND eg.status = 'active'
            ORDER BY eg.entitlement_definition_id, eg.entitlement_version
            """,
            (membership["membership_id"],),
        ).fetchall()

        if any(
            row["definition_status"] != "active"
            for row in entitlement_rows
        ):
            raise AuthorityError("entitlement definition inactive")

        binding_rows = self.connection.execute(
            """
            SELECT
                b.*,
                ad.status AS adapter_definition_status,
                od.status AS operation_definition_status,
                od.adapter_definition_id AS operation_adapter_definition_id,
                ed.status AS binding_entitlement_definition_status,
                pd.status AS policy_definition_status,
                eg.entitlement_grant_id AS active_entitlement_grant_id
            FROM adapter_grant_binding AS b
            LEFT JOIN adapter_definition AS ad
              ON ad.adapter_definition_id = b.adapter_definition_id
            LEFT JOIN operation_definition AS od
              ON od.operation_definition_id = b.operation_definition_id
            LEFT JOIN entitlement_definition AS ed
              ON ed.entitlement_definition_id = b.entitlement_definition_id
             AND ed.version = b.entitlement_definition_version
            LEFT JOIN policy_definition AS pd
              ON pd.policy_definition_id = b.policy_definition_id
             AND pd.version = b.policy_definition_version
            LEFT JOIN entitlement_grant AS eg
              ON eg.membership_id = b.membership_id
             AND eg.entitlement_definition_id = b.entitlement_definition_id
             AND eg.entitlement_version = b.entitlement_definition_version
             AND eg.status = 'active'
            WHERE b.membership_id = ?
              AND b.status = 'active'
            ORDER BY b.binding_id
            """,
            (membership["membership_id"],),
        ).fetchall()

        for row in binding_rows:
            if (
                row["adapter_definition_status"] != "active"
                or row["operation_definition_status"] != "active"
                or row["operation_adapter_definition_id"]
                != row["adapter_definition_id"]
                or row["binding_entitlement_definition_status"] != "active"
                or row["policy_definition_status"] != "active"
                or row["active_entitlement_grant_id"] is None
            ):
                raise AuthorityError("adapter binding authority inactive")

        bindings = tuple(
            AdapterGrantBinding(
                binding_id=row["binding_id"],
                identity_id=session["identity_id"],
                account_id=session["account_id"],
                organization_id=session["organization_id"],
                tenant_id=session["tenant_id"],
                session_id=session["session_id"],
                adapter_definition_id=row["adapter_definition_id"],
                operation_definition_id=row["operation_definition_id"],
                entitlement_definition_id=row["entitlement_definition_id"],
                entitlement_definition_version=row["entitlement_definition_version"],
                resource_scope_json=row["resource_scope_json"],
                authorization_version=membership["authorization_version"],
                entitlement_version=membership["entitlement_version"],
                policy_definition_id=row["policy_definition_id"],
                policy_definition_version=row["policy_definition_version"],
                policy_version=row["policy_version"],
                status=row["status"],
            )
            for row in binding_rows
        )

        return AuthorizedSubject(
            identity_id=session["identity_id"],
            account_id=session["account_id"],
            organization_id=session["organization_id"],
            tenant_id=session["tenant_id"],
            session_id=session["session_id"],
            role_definitions=tuple(
                VersionedDefinitionRef(
                    row["role_definition_id"],
                    row["role_version"],
                )
                for row in role_rows
            ),
            entitlement_definitions=tuple(
                VersionedDefinitionRef(
                    row["entitlement_definition_id"],
                    row["entitlement_version"],
                )
                for row in entitlement_rows
            ),
            adapter_bindings=bindings,
            authorization_version=membership["authorization_version"],
            entitlement_version=membership["entitlement_version"],
            expires_at=session["expires_at"],
            active=True,
        )

    def _revoke_membership_sessions(
        self,
        membership_id: str,
        revoked_at: float,
    ) -> None:
        validate_typed_id(membership_id, "mbr")

        self.connection.execute(
            """
            UPDATE session
            SET status = 'revoked',
                revoked_at = ?
            WHERE membership_id = ?
              AND status = 'active'
              AND revoked_at IS NULL
            """,
            (
                revoked_at,
                membership_id,
            ),
        )

        self.connection.execute(
            """
            UPDATE consumer_handoff
            SET status = 'revoked',
                revoked_at = ?
            WHERE source_session_id IN (
                SELECT session_id
                FROM session
                WHERE membership_id = ?
                  AND status = 'revoked'
            )
              AND status = 'active'
              AND consumed_at IS NULL
              AND revoked_at IS NULL
            """,
            (
                revoked_at,
                membership_id,
            ),
        )

    @_synchronized
    def suspend_membership(self, membership_id: str) -> None:
        validate_typed_id(membership_id, "mbr")
        now = _now()

        with self.connection:
            updated = self.connection.execute(
                """
                UPDATE membership
                SET status = 'suspended',
                    authorization_version = authorization_version + 1
                WHERE membership_id = ?
                  AND status = 'active'
                """,
                (membership_id,),
            )

            if updated.rowcount != 1:
                raise AuthorityError("active membership unavailable")

            self._revoke_membership_sessions(
                membership_id,
                now,
            )

    @_synchronized
    def leave_membership(self, membership_id: str) -> None:
        validate_typed_id(membership_id, "mbr")
        now = _now()

        with self.connection:
            updated = self.connection.execute(
                """
                UPDATE membership
                SET status = 'left',
                    authorization_version = authorization_version + 1
                WHERE membership_id = ?
                  AND status = 'active'
                """,
                (membership_id,),
            )

            if updated.rowcount != 1:
                raise AuthorityError("active membership unavailable")

            self._revoke_membership_sessions(
                membership_id,
                now,
            )

    @_synchronized
    def revoke_membership(self, membership_id: str) -> None:
        validate_typed_id(membership_id, "mbr")
        now = _now()

        with self.connection:
            updated = self.connection.execute(
                """
                UPDATE membership
                SET status = 'revoked',
                    authorization_version = authorization_version + 1
                WHERE membership_id = ?
                  AND status IN ('active', 'suspended')
                """,
                (membership_id,),
            )

            if updated.rowcount != 1:
                raise AuthorityError("current membership unavailable")

            self._revoke_membership_sessions(
                membership_id,
                now,
            )

    @_synchronized
    def issue_consumer_handoff(
        self,
        session_bearer: str,
        session_id: str,
        consumer: str,
        ttl_seconds: int = 300,
    ) -> tuple[str, str]:
        validate_typed_id(session_id, "ses")

        _require_positive_integer(ttl_seconds, "handoff TTL")

        normalized_consumer = normalize_symbol(consumer)

        if normalized_consumer != "adforge":
            raise AuthorityError("unsupported handoff consumer")

        subject = self.authenticate(
            session_bearer,
            session_id,
        )

        session = self.connection.execute(
            """
            SELECT *
            FROM session
            WHERE session_id = ?
              AND status = 'active'
            """,
            (session_id,),
        ).fetchone()

        if session is None:
            raise AuthorityError("session unavailable")

        membership = self.connection.execute(
            """
            SELECT *
            FROM membership
            WHERE membership_id = ?
              AND identity_id = ?
              AND organization_id = ?
              AND status = 'active'
            """,
            (
                session["membership_id"],
                subject.identity_id,
                subject.organization_id,
            ),
        ).fetchone()

        if membership is None:
            raise AuthorityError("active membership required")

        if (
            membership["authorization_version"]
            != subject.authorization_version
        ):
            raise AuthorityError("authorization version stale")

        if (
            membership["entitlement_version"]
            != subject.entitlement_version
        ):
            raise AuthorityError("entitlement version stale")

        organization = self.connection.execute(
            """
            SELECT *
            FROM organization
            WHERE organization_id = ?
              AND status = 'active'
            """,
            (subject.organization_id,),
        ).fetchone()

        if organization is None:
            raise AuthorityError("organization unavailable")

        tenant = self.connection.execute(
            """
            SELECT *
            FROM tenant
            WHERE tenant_id = ?
              AND organization_id = ?
              AND status = 'active'
            """,
            (
                subject.tenant_id,
                subject.organization_id,
            ),
        ).fetchone()

        if tenant is None:
            raise AuthorityError("tenant unavailable")

        handoff_id = _new_id("handoff")
        token = secrets.token_urlsafe(32)
        token_sha256 = _token_digest(token)
        now = _now()

        with self.connection:
            self.connection.execute(
                """
                INSERT INTO consumer_handoff(
                    handoff_id,
                    token_sha256,
                    consumer,
                    identity_id,
                    account_id,
                    membership_id,
                    organization_id,
                    tenant_id,
                    source_session_id,
                    authorization_version,
                    entitlement_version,
                    expires_at,
                    consumed_at,
                    revoked_at,
                    status,
                    created_at
                ) VALUES (
                    ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, NULL, NULL, 'active', ?
                )
                """,
                (
                    handoff_id,
                    token_sha256,
                    normalized_consumer,
                    subject.identity_id,
                    subject.account_id,
                    session["membership_id"],
                    subject.organization_id,
                    subject.tenant_id,
                    session_id,
                    subject.authorization_version,
                    subject.entitlement_version,
                    now + ttl_seconds,
                    now,
                ),
            )

        return handoff_id, token

    @_synchronized
    def consume_consumer_handoff(
        self,
        token: str,
        consumer: str,
    ) -> ConsumerHandoffProjection:
        token_sha256 = _token_digest(token)
        normalized_consumer = normalize_symbol(consumer)
        now = _now()

        if normalized_consumer != "adforge":
            raise AuthorityError("unsupported handoff consumer")

        self.connection.execute("BEGIN IMMEDIATE")

        try:
            handoff = self.connection.execute(
                """
                SELECT *
                FROM consumer_handoff
                WHERE token_sha256 = ?
                """,
                (token_sha256,),
            ).fetchone()

            if handoff is None:
                raise AuthorityError("handoff unavailable")

            if handoff["consumer"] != normalized_consumer:
                raise AuthorityError("handoff consumer mismatch")

            if handoff["status"] != "active":
                raise AuthorityError("handoff unavailable")

            if handoff["consumed_at"] is not None:
                raise AuthorityError("handoff consumed")

            if handoff["revoked_at"] is not None:
                raise AuthorityError("handoff revoked")

            if handoff["expires_at"] <= now:
                raise AuthorityError("handoff expired")

            source_session = self.connection.execute(
                """
                SELECT *
                FROM session
                WHERE session_id = ?
                """,
                (handoff["source_session_id"],),
            ).fetchone()

            if source_session is None:
                raise AuthorityError(
                    "handoff source session unavailable"
                )

            if (
                source_session["status"] != "active"
                or source_session["revoked_at"] is not None
                or source_session["expires_at"] <= now
            ):
                raise AuthorityError(
                    "handoff source session inactive"
                )

            if (
                source_session["identity_id"]
                != handoff["identity_id"]
                or source_session["account_id"]
                != handoff["account_id"]
                or source_session["membership_id"]
                != handoff["membership_id"]
                or source_session["organization_id"]
                != handoff["organization_id"]
                or source_session["tenant_id"]
                != handoff["tenant_id"]
            ):
                raise AuthorityError(
                    "handoff source session mismatch"
                )

            if (
                source_session["authorization_version"]
                != handoff["authorization_version"]
            ):
                raise AuthorityError(
                    "handoff source authorization version stale"
                )

            if (
                source_session["entitlement_version"]
                != handoff["entitlement_version"]
            ):
                raise AuthorityError(
                    "handoff source entitlement version stale"
                )

            identity = self.connection.execute(
                """
                SELECT *
                FROM identity
                WHERE identity_id = ?
                  AND status = 'active'
                """,
                (handoff["identity_id"],),
            ).fetchone()

            if identity is None:
                raise AuthorityError("active identity required")

            account = self.connection.execute(
                """
                SELECT *
                FROM personal_account
                WHERE account_id = ?
                  AND identity_id = ?
                  AND status = 'active'
                """,
                (
                    handoff["account_id"],
                    handoff["identity_id"],
                ),
            ).fetchone()

            if account is None:
                raise AuthorityError("active personal account required")

            membership = self.connection.execute(
                """
                SELECT *
                FROM membership
                WHERE membership_id = ?
                  AND identity_id = ?
                  AND organization_id = ?
                  AND status = 'active'
                """,
                (
                    handoff["membership_id"],
                    handoff["identity_id"],
                    handoff["organization_id"],
                ),
            ).fetchone()

            if membership is None:
                raise AuthorityError("active membership required")

            if (
                membership["authorization_version"]
                != handoff["authorization_version"]
            ):
                raise AuthorityError("handoff authorization version stale")

            if (
                membership["entitlement_version"]
                != handoff["entitlement_version"]
            ):
                raise AuthorityError("handoff entitlement version stale")

            organization = self.connection.execute(
                """
                SELECT *
                FROM organization
                WHERE organization_id = ?
                  AND status = 'active'
                """,
                (handoff["organization_id"],),
            ).fetchone()

            if organization is None:
                raise AuthorityError("organization unavailable")

            tenant = self.connection.execute(
                """
                SELECT *
                FROM tenant
                WHERE tenant_id = ?
                  AND organization_id = ?
                  AND status = 'active'
                """,
                (
                    handoff["tenant_id"],
                    handoff["organization_id"],
                ),
            ).fetchone()

            if tenant is None:
                raise AuthorityError("tenant unavailable")

            # A handoff is derived authority, not an independent capability.
            # Revalidate the complete parent account/identity/organization graph
            # even when an eager revocation cascade did not update this row.
            self.project_authorized_subject(
                handoff["source_session_id"]
            )

            rows = self.connection.execute(
                """
                SELECT *
                FROM hydration_reference
                WHERE organization_id = ?
                  AND status = 'active'
                ORDER BY kind, target_ref, version
                """,
                (handoff["organization_id"],),
            ).fetchall()

            hydration = HydrationProjection(
                organization_id=handoff["organization_id"],
                tenant_id=handoff["tenant_id"],
                configuration_version=organization["hydration_version"],
                references=tuple(
                    HydrationReference(
                        reference_id=row["hydration_reference_id"],
                        kind=row["kind"],
                        target_ref=row["target_ref"],
                        version=row["version"],
                    )
                    for row in rows
                ),
            )

            updated = self.connection.execute(
                """
                UPDATE consumer_handoff
                SET status = 'consumed',
                    consumed_at = ?
                WHERE handoff_id = ?
                  AND status = 'active'
                  AND consumed_at IS NULL
                  AND revoked_at IS NULL
                """,
                (
                    now,
                    handoff["handoff_id"],
                ),
            )

            if updated.rowcount != 1:
                raise AuthorityError("handoff unavailable")

            projection = ConsumerHandoffProjection(
                handoff_id=handoff["handoff_id"],
                consumer=handoff["consumer"],
                identity_id=handoff["identity_id"],
                account_id=handoff["account_id"],
                membership_id=handoff["membership_id"],
                organization_id=handoff["organization_id"],
                tenant_id=handoff["tenant_id"],
                authorization_version=handoff["authorization_version"],
                entitlement_version=handoff["entitlement_version"],
                hydration=hydration,
            )

            self.connection.commit()
            return projection

        except Exception:
            self.connection.rollback()
            raise


    @_synchronized
    def revoke_consumer_handoff(
        self,
        handoff_id: str,
    ) -> None:
        validate_typed_id(handoff_id, "hnd")
        now = _now()

        with self.connection:
            updated = self.connection.execute(
                """
                UPDATE consumer_handoff
                SET status = 'revoked',
                    revoked_at = ?
                WHERE handoff_id = ?
                  AND status = 'active'
                  AND consumed_at IS NULL
                  AND revoked_at IS NULL
                """,
                (
                    now,
                    handoff_id,
                ),
            )

            if updated.rowcount != 1:
                raise AuthorityError("active handoff unavailable")

    @_synchronized
    def add_hydration_reference(
        self,
        organization_id: str,
        kind: str,
        target_ref: str,
        version: str,
    ) -> str:
        validate_typed_id(organization_id, "org")
        hydration_id = _new_id("hydration")

        clean_target = str(target_ref or "").strip()

        if not clean_target:
            raise AuthorityError("hydration target reference is required")

        lowered = clean_target.lower()

        for forbidden in (
            "secret=",
            "token=",
            "password=",
            "api_key=",
            "apikey=",
            "private_key=",
            "credential=",
        ):
            if forbidden in lowered:
                raise AuthorityError("hydration references must not contain secret material")

        with self.connection:
            self.connection.execute(
                """
                INSERT INTO hydration_reference(
                    hydration_reference_id,
                    organization_id,
                    kind,
                    target_ref,
                    version,
                    status,
                    created_at
                ) VALUES (?, ?, ?, ?, ?, 'active', ?)
                """,
                (
                    hydration_id,
                    organization_id,
                    normalize_symbol(kind),
                    clean_target,
                    normalize_symbol(version),
                    _now(),
                ),
            )

            self.connection.execute(
                """
                UPDATE organization
                SET hydration_version = hydration_version + 1
                WHERE organization_id = ?
                """,
                (organization_id,),
            )

        return hydration_id

    @_synchronized
    def project_hydration(
        self,
        organization_id: str,
    ) -> HydrationProjection:
        validate_typed_id(organization_id, "org")

        organization = self.connection.execute(
            """
            SELECT *
            FROM organization
            WHERE organization_id = ?
              AND status = 'active'
            """,
            (organization_id,),
        ).fetchone()

        if organization is None:
            raise AuthorityError("organization unavailable")

        tenant = self.connection.execute(
            """
            SELECT *
            FROM tenant
            WHERE organization_id = ?
              AND status = 'active'
            """,
            (organization_id,),
        ).fetchone()

        if tenant is None:
            raise AuthorityError("tenant unavailable")

        rows = self.connection.execute(
            """
            SELECT *
            FROM hydration_reference
            WHERE organization_id = ?
              AND status = 'active'
            ORDER BY kind, target_ref, version
            """,
            (organization_id,),
        ).fetchall()

        references = tuple(
            HydrationReference(
                reference_id=row["hydration_reference_id"],
                kind=row["kind"],
                target_ref=row["target_ref"],
                version=row["version"],
            )
            for row in rows
        )

        return HydrationProjection(
            organization_id=organization_id,
            tenant_id=tenant["tenant_id"],
            configuration_version=organization["hydration_version"],
            references=references,
        )
