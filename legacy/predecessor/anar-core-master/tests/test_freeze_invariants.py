from __future__ import annotations

import hashlib
import sqlite3
import tempfile
import time
import unittest
from pathlib import Path

from anar_core import AnarCoreStore, AuthorityError
from anar_core_contracts import VersionedDefinitionRef


class FreezeInvariantTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.database_path = Path(self.temp.name) / "anar-core.sqlite3"
        self.store = AnarCoreStore(self.database_path)

        (
            self.identity_id,
            self.account_id,
            _verification_id,
            verification_token,
        ) = self.store.signup(
            "freeze-invariants@example.com",
            "correct horse battery staple",
            "Freeze Invariants",
        )
        self.store.verify_email(verification_token)
        (
            self.account_session_id,
            self.account_session_bearer,
        ) = self.store.login(
            "freeze-invariants@example.com",
            "correct horse battery staple",
        )
        self.organization_id, self.tenant_id = self.store.create_organization(
            "Freeze Organization"
        )
        invitation_id, invitation_code = self.store.issue_invitation(
            self.organization_id,
            self.tenant_id,
            role_refs=(),
            entitlement_refs=(),
        )
        self.membership_id = self.store.redeem_invitation(
            invitation_code,
            self.identity_id,
        )
        self.session_id, self.session_bearer = (
            self.store.derive_organization_session(
                self.account_session_bearer,
                self.account_session_id,
                self.organization_id,
            )
        )

    def tearDown(self) -> None:
        self.store.close()
        self.temp.cleanup()

    def test_organization_session_expiry_is_bounded_by_parent_session(self) -> None:
        parent_expiry = time.time() + 60
        self.store.connection.execute(
            """
            UPDATE account_session
            SET expires_at = ?
            WHERE account_session_id = ?
            """,
            (parent_expiry, self.account_session_id),
        )
        self.store.connection.commit()

        child_session_id, _child_bearer = (
            self.store.derive_organization_session(
                self.account_session_bearer,
                self.account_session_id,
                self.organization_id,
                ttl_seconds=3600,
            )
        )
        child = self.store.connection.execute(
            "SELECT expires_at FROM session WHERE session_id = ?",
            (child_session_id,),
        ).fetchone()

        self.assertLessEqual(child["expires_at"], parent_expiry)

    def test_parent_session_expiry_invalidates_derived_authority_and_readiness(self) -> None:
        self.store.connection.execute(
            """
            UPDATE account_session
            SET expires_at = 1
            WHERE account_session_id = ?
            """,
            (self.account_session_id,),
        )
        self.store.connection.commit()

        with self.assertRaises(AuthorityError):
            self.store.authenticate(self.session_bearer, self.session_id)

        self.assertFalse(self.store.ready())

    def test_unbound_organization_session_fails_closed(self) -> None:
        self.store.connection.execute(
            """
            UPDATE session
            SET account_session_id = NULL
            WHERE session_id = ?
            """,
            (self.session_id,),
        )
        self.store.connection.commit()

        with self.assertRaises(AuthorityError):
            self.store.authenticate(self.session_bearer, self.session_id)

    def test_handoff_consumption_revalidates_parent_authority_without_eager_cascade(
        self,
    ) -> None:
        handoff_id, token = self.store.issue_consumer_handoff(
            self.session_bearer,
            self.session_id,
            "adforge",
        )
        now = time.time()
        self.store.connection.execute(
            """
            UPDATE account_session
            SET status = 'revoked',
                revoked_at = ?
            WHERE account_session_id = ?
            """,
            (now, self.account_session_id),
        )
        self.store.connection.commit()

        with self.assertRaises(AuthorityError):
            self.store.consume_consumer_handoff(token, "adforge")

        handoff = self.store.connection.execute(
            """
            SELECT status, consumed_at
            FROM consumer_handoff
            WHERE handoff_id = ?
            """,
            (handoff_id,),
        ).fetchone()
        self.assertEqual(handoff["status"], "active")
        self.assertIsNone(handoff["consumed_at"])

    def test_inactive_authority_graph_nodes_fail_closed(self) -> None:
        nodes = (
            ("identity", "identity_id", self.identity_id),
            ("personal_account", "account_id", self.account_id),
            ("organization", "organization_id", self.organization_id),
            ("tenant", "tenant_id", self.tenant_id),
        )

        for table, identifier_column, identifier in nodes:
            with self.subTest(table=table):
                self.store.connection.execute(
                    f"UPDATE {table} SET status = 'inactive' "
                    f"WHERE {identifier_column} = ?",
                    (identifier,),
                )
                self.store.connection.commit()

                with self.assertRaises(AuthorityError):
                    self.store.authenticate(
                        self.session_bearer,
                        self.session_id,
                    )

                self.store.connection.execute(
                    f"UPDATE {table} SET status = 'active' "
                    f"WHERE {identifier_column} = ?",
                    (identifier,),
                )
                self.store.connection.commit()

    def test_invitation_rejects_cross_organization_tenant_without_mutation(self) -> None:
        _other_organization_id, other_tenant_id = (
            self.store.create_organization("Other Organization")
        )
        before = self.store.connection.execute(
            "SELECT COUNT(*) AS total FROM invitation"
        ).fetchone()["total"]

        with self.assertRaises(AuthorityError):
            self.store.issue_invitation(
                self.organization_id,
                other_tenant_id,
                role_refs=(),
                entitlement_refs=(),
            )

        after = self.store.connection.execute(
            "SELECT COUNT(*) AS total FROM invitation"
        ).fetchone()["total"]
        self.assertEqual(after, before)

    def test_invitation_rejects_inactive_or_unknown_definitions_without_mutation(
        self,
    ) -> None:
        role = self.store.define_role("freeze.invitation-role")
        entitlement = self.store.define_entitlement(
            "freeze.invitation-entitlement"
        )
        cases = (
            (
                "role_definition",
                "role_definition_id = ? AND version = ?",
                (role.definition_id, role.version),
                (role,),
                (entitlement,),
            ),
            (
                "entitlement_definition",
                "entitlement_definition_id = ? AND version = ?",
                (entitlement.definition_id, entitlement.version),
                (role,),
                (entitlement,),
            ),
        )

        before = self.store.connection.execute(
            "SELECT COUNT(*) AS total FROM invitation"
        ).fetchone()["total"]

        for table, where, parameters, roles, entitlements in cases:
            with self.subTest(table=table):
                self.store.connection.execute(
                    f"UPDATE {table} SET status = 'inactive' WHERE {where}",
                    parameters,
                )
                self.store.connection.commit()
                with self.assertRaises(AuthorityError):
                    self.store.issue_invitation(
                        self.organization_id,
                        self.tenant_id,
                        role_refs=roles,
                        entitlement_refs=entitlements,
                    )
                self.store.connection.execute(
                    f"UPDATE {table} SET status = 'active' WHERE {where}",
                    parameters,
                )
                self.store.connection.commit()

        with self.assertRaises(AuthorityError):
            self.store.issue_invitation(
                self.organization_id,
                self.tenant_id,
                role_refs=(
                    VersionedDefinitionRef(
                        "rol_00000000000000000000000000000099",
                        1,
                    ),
                ),
                entitlement_refs=(entitlement,),
            )

        after = self.store.connection.execute(
            "SELECT COUNT(*) AS total FROM invitation"
        ).fetchone()["total"]
        self.assertEqual(after, before)

    def test_definition_versions_fail_before_database_mutation(self) -> None:
        definitions = (
            ("role_definition", self.store.define_role),
            ("policy_definition", self.store.define_policy),
            ("entitlement_definition", self.store.define_entitlement),
        )

        for table, define in definitions:
            for version in (True, 1.5, 0, -1):
                with self.subTest(table=table, version=version):
                    before = self.store.connection.execute(
                        f"SELECT COUNT(*) AS total FROM {table}"
                    ).fetchone()["total"]

                    with self.assertRaises(AuthorityError):
                        define(
                            f"freeze.invalid-{table}-{version!s}",
                            version=version,
                        )

                    after = self.store.connection.execute(
                        f"SELECT COUNT(*) AS total FROM {table}"
                    ).fetchone()["total"]
                    self.assertEqual(after, before)

    def test_integer_inputs_reject_fractional_values_without_mutation(self) -> None:
        table_counts = (
            "identity",
            "account_session",
            "password_reset_challenge",
            "email_change_challenge",
            "invitation",
            "session",
            "consumer_handoff",
            "mfa_recovery_code",
        )
        before = {
            table: self.store.connection.execute(
                f"SELECT COUNT(*) AS total FROM {table}"
            ).fetchone()["total"]
            for table in table_counts
        }

        attempts = (
            lambda: self.store.signup(
                "fractional@example.com",
                "correct horse battery staple",
                "Fractional",
                verification_ttl_seconds=1.5,
            ),
            lambda: self.store.login(
                "freeze-invariants@example.com",
                "correct horse battery staple",
                ttl_seconds=1.5,
            ),
            lambda: self.store.issue_password_reset(
                "freeze-invariants@example.com",
                ttl_seconds=1.5,
            ),
            lambda: self.store.request_email_change(
                self.account_session_bearer,
                self.account_session_id,
                "correct horse battery staple",
                "changed@example.com",
                ttl_seconds=1.5,
            ),
            lambda: self.store.issue_invitation(
                self.organization_id,
                self.tenant_id,
                role_refs=(),
                entitlement_refs=(),
                ttl_seconds=1.5,
            ),
            lambda: self.store.derive_organization_session(
                self.account_session_bearer,
                self.account_session_id,
                self.organization_id,
                ttl_seconds=1.5,
            ),
            lambda: self.store.issue_consumer_handoff(
                self.session_bearer,
                self.session_id,
                "adforge",
                ttl_seconds=1.5,
            ),
            lambda: self.store.issue_mfa_recovery_codes(
                self.account_session_bearer,
                self.account_session_id,
                count=1.5,
            ),
        )

        for index, attempt in enumerate(attempts):
            with self.subTest(attempt=index):
                with self.assertRaises(AuthorityError):
                    attempt()

        after = {
            table: self.store.connection.execute(
                f"SELECT COUNT(*) AS total FROM {table}"
            ).fetchone()["total"]
            for table in table_counts
        }
        self.assertEqual(after, before)

    def test_signout_revocation_is_scoped_to_originating_session(self) -> None:
        second_session_id, second_bearer = self.store.login(
            "freeze-invariants@example.com",
            "correct horse battery staple",
        )
        authenticator_id = "mfa_00000000000000000000000000000001"
        now = time.time()
        self.store.connection.execute(
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
            ) VALUES (?, ?, 'totp', ?, 'active', ?, NULL, ?)
            """,
            (
                authenticator_id,
                self.account_id,
                "vault://freeze/totp",
                now,
                now,
            ),
        )
        first_step_up_id, _first_token = self.store._mint_mfa_step_up(
            self.account_id,
            self.account_session_id,
            authenticator_id,
            "password.change",
            300,
            now,
        )
        second_step_up_id, _second_token = self.store._mint_mfa_step_up(
            self.account_id,
            second_session_id,
            authenticator_id,
            "password.change",
            300,
            now,
        )

        for suffix, session_id in (
            ("1", self.account_session_id),
            ("2", second_session_id),
        ):
            token = f"freeze-attestation-{suffix}"
            self.store.connection.execute(
                """
                INSERT INTO mfa_broker_attestation(
                    attestation_id,
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
                ) VALUES (?, ?, ?, ?, ?, 'password.change', ?, NULL, NULL, 'active', ?)
                """,
                (
                    f"mfaa_0000000000000000000000000000000{suffix}",
                    hashlib.sha256(token.encode("utf-8")).hexdigest(),
                    self.account_id,
                    session_id,
                    authenticator_id,
                    now + 300,
                    now,
                ),
            )
        self.store.connection.commit()

        self.store.signout(
            self.account_session_bearer,
            self.account_session_id,
        )

        step_ups = {
            row["step_up_id"]: row["status"]
            for row in self.store.connection.execute(
                """
                SELECT step_up_id, status
                FROM mfa_step_up_receipt
                WHERE step_up_id IN (?, ?)
                """,
                (first_step_up_id, second_step_up_id),
            ).fetchall()
        }
        attestations = {
            row["account_session_id"]: row["status"]
            for row in self.store.connection.execute(
                """
                SELECT account_session_id, status
                FROM mfa_broker_attestation
                WHERE account_session_id IN (?, ?)
                """,
                (self.account_session_id, second_session_id),
            ).fetchall()
        }

        self.assertEqual(step_ups[first_step_up_id], "revoked")
        self.assertEqual(step_ups[second_step_up_id], "active")
        self.assertEqual(attestations[self.account_session_id], "revoked")
        self.assertEqual(attestations[second_session_id], "active")
        self.store.authenticate_account_session(second_bearer, second_session_id)

    def test_future_or_foreign_schema_is_rejected_without_mutation(self) -> None:
        cases = (
            ("anar-core.v0.1", "10"),
            ("anar-core.v0.2", "1"),
            ("anar-core.v0.1", "not-an-integer"),
        )

        for index, (schema_contract, schema_revision) in enumerate(cases):
            with self.subTest(
                schema_contract=schema_contract,
                schema_revision=schema_revision,
            ):
                path = Path(self.temp.name) / f"future-{index}.sqlite3"
                connection = sqlite3.connect(path)
                connection.execute(
                    """
                    CREATE TABLE schema_metadata (
                        metadata_key TEXT PRIMARY KEY,
                        metadata_value TEXT NOT NULL
                    )
                    """
                )
                connection.executemany(
                    """
                    INSERT INTO schema_metadata(metadata_key, metadata_value)
                    VALUES (?, ?)
                    """,
                    (
                        ("schema_contract", schema_contract),
                        ("schema_revision", schema_revision),
                    ),
                )
                connection.commit()
                connection.close()
                before_bytes = path.read_bytes()

                with self.assertRaises(AuthorityError):
                    AnarCoreStore(path)

                after_bytes = path.read_bytes()

                verification = sqlite3.connect(path)
                tables = {
                    row[0]
                    for row in verification.execute(
                        "SELECT name FROM sqlite_master WHERE type = 'table'"
                    ).fetchall()
                }
                metadata = dict(
                    verification.execute(
                        "SELECT metadata_key, metadata_value FROM schema_metadata"
                    ).fetchall()
                )
                verification.close()

                self.assertEqual(tables, {"schema_metadata"})
                self.assertEqual(after_bytes, before_bytes)
                self.assertEqual(
                    metadata,
                    {
                        "schema_contract": schema_contract,
                        "schema_revision": schema_revision,
                    },
                )

    def test_migration_is_idempotent_and_preserves_integrity(self) -> None:
        path = Path(self.temp.name) / "reopen.sqlite3"
        first = AnarCoreStore(path)
        identity_id, account_id, _challenge_id, token = first.signup(
            "reopen@example.com",
            "correct horse battery staple",
            "Reopen",
        )
        first.close()

        second = AnarCoreStore(path)
        self.assertEqual(second.verify_email(token), account_id)
        identity = second.connection.execute(
            "SELECT identity_id, status FROM identity WHERE identity_id = ?",
            (identity_id,),
        ).fetchone()
        metadata = dict(
            second.connection.execute(
                "SELECT metadata_key, metadata_value FROM schema_metadata"
            ).fetchall()
        )
        integrity = second.connection.execute("PRAGMA integrity_check").fetchone()[0]
        foreign_key_violations = second.connection.execute(
            "PRAGMA foreign_key_check"
        ).fetchall()
        second.close()

        self.assertEqual(dict(identity), {"identity_id": identity_id, "status": "active"})
        self.assertEqual(metadata["schema_contract"], "anar-core.v0.1")
        self.assertEqual(metadata["schema_revision"], "9")
        self.assertEqual(integrity, "ok")
        self.assertEqual(foreign_key_violations, [])


if __name__ == "__main__":
    unittest.main()
