from __future__ import annotations

import hashlib
import sqlite3
import tempfile
import time
import unittest
from dataclasses import replace
from pathlib import Path

from anar_core import AnarCoreStore, AuthorityError
from anar_core_contracts import (
    BoundaryMismatch,
    assert_boundary_agreement,
)


class AnarCoreV01Tests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.store = AnarCoreStore(Path(self.temp.name) / "anar-core.sqlite3")

        (
            self.identity_id,
            self.account_id,
            self.verification_id,
            self.verification_token,
        ) = self.store.signup(
            "anar-core-fixture@example.com",
            "correct horse battery staple",
            "Alexander",
        )

        self.store.verify_email(self.verification_token)

        (
            self.account_session_id,
            self.account_session_bearer,
        ) = self.store.login(
            "anar-core-fixture@example.com",
            "correct horse battery staple",
        )
        self.organization_id, self.tenant_id = self.store.create_organization(
            "AnarchI Technologies"
        )

        self.owner_role = self.store.define_role(
            "organization.owner",
            grants=("membership.admin", "product.use"),
            prohibitions=("secret.disclose",),
        )

        self.adforge_entitlement = self.store.define_entitlement(
            "adforge.use"
        )
        self.publication_policy = self.store.define_policy(
            "publication.default"
        )

        self.adapter_id = self.store.define_adapter("adforge.publisher")
        self.operation_id = self.store.define_operation(
            self.adapter_id,
            "publish",
        )

        self.invitation_id, self.invitation_code = self.store.issue_invitation(
            self.organization_id,
            self.tenant_id,
            role_refs=(self.owner_role,),
            entitlement_refs=(self.adforge_entitlement,),
        )

        self.membership_id = self.store.redeem_invitation(
            self.invitation_code,
            self.identity_id,
        )

        self.binding_id = self.store.grant_adapter_operation(
            self.membership_id,
            self.adapter_id,
            self.operation_id,
            self.adforge_entitlement,
            {"providerAccount": "anarchi-linkedin"},
            self.publication_policy,
            "policy-v1",
        )

        (
            self.session_id,
            self.session_bearer,
        ) = self.store.derive_organization_session(
            self.account_session_bearer,
            self.account_session_id,
            self.organization_id,
        )

    def tearDown(self) -> None:
        self.store.close()
        self.temp.cleanup()

    def test_identity_account_membership_org_tenant_shape(self) -> None:
        subject = self.store.project_authorized_subject(self.session_id)

        self.assertEqual(subject.identity_id, self.identity_id)
        self.assertEqual(subject.account_id, self.account_id)
        self.assertEqual(subject.organization_id, self.organization_id)
        self.assertEqual(subject.tenant_id, self.tenant_id)

    def test_session_bearer_authenticates_exact_session(self) -> None:
        subject = self.store.authenticate(
            self.session_bearer,
            self.session_id,
        )

        self.assertEqual(subject.session_id, self.session_id)
        self.assertEqual(subject.identity_id, self.identity_id)

    def test_wrong_session_bearer_fails_closed(self) -> None:
        with self.assertRaisesRegex(AuthorityError, "unauthorized"):
            self.store.authenticate(
                "wrong-session-bearer",
                self.session_id,
            )

    def test_session_bearer_is_not_persisted_plaintext(self) -> None:
        row = self.store.connection.execute(
            """
            SELECT bearer_sha256
            FROM session
            WHERE session_id = ?
            """,
            (self.session_id,),
        ).fetchone()

        self.assertIsNotNone(row)
        self.assertNotEqual(row["bearer_sha256"], self.session_bearer)
        self.assertEqual(len(row["bearer_sha256"]), 64)
    def test_invitation_is_single_use(self) -> None:
        second_identity = self.store.create_identity("Second Person")
        self.store.create_personal_account(second_identity)

        with self.assertRaises(AuthorityError):
            self.store.redeem_invitation(
                self.invitation_code,
                second_identity,
            )

    def test_authorized_subject_uses_definition_ids_not_role_strings(self) -> None:
        subject = self.store.project_authorized_subject(self.session_id)
        mapping = subject.broker_mapping()

        self.assertEqual(
            mapping["roles"],
            [f"{self.owner_role.definition_id}@{self.owner_role.version}"],
        )

        self.assertEqual(
            mapping["entitlements"],
            [
                f"{self.adforge_entitlement.definition_id}@"
                f"{self.adforge_entitlement.version}"
            ],
        )

    def test_adapter_binding_requires_exact_active_entitlement(self) -> None:
        unrelated = self.store.define_entitlement("unrelated.use")

        with self.assertRaisesRegex(
            AuthorityError,
            "active entitlement grant required",
        ):
            self.store.grant_adapter_operation(
                self.membership_id,
                self.adapter_id,
                self.operation_id,
                unrelated,
                {"providerAccount": "anarchi-linkedin"},
                self.publication_policy,
                "policy-v1",
            )

    def test_operation_cannot_cross_adapter_definition_boundary(self) -> None:
        other_adapter = self.store.define_adapter("other.publisher")
        other_operation = self.store.define_operation(
            other_adapter,
            "publish",
        )

        with self.assertRaisesRegex(
            AuthorityError,
            "does not belong",
        ):
            self.store.grant_adapter_operation(
                self.membership_id,
                self.adapter_id,
                other_operation,
                self.adforge_entitlement,
                {"providerAccount": "anarchi-linkedin"},
                self.publication_policy,
                "policy-v1",
            )

    def test_binding_records_entitlement_provenance(self) -> None:
        subject = self.store.project_authorized_subject(self.session_id)
        binding = subject.adapter_bindings[0]

        self.assertEqual(
            binding.entitlement_definition_id,
            self.adforge_entitlement.definition_id,
        )
        self.assertEqual(
            binding.entitlement_definition_version,
            self.adforge_entitlement.version,
        )
        self.assertEqual(len(binding.agreement_digest()), 64)

    def test_binding_records_policy_provenance(self) -> None:
        subject = self.store.project_authorized_subject(self.session_id)
        binding = subject.adapter_bindings[0]

        self.assertEqual(
            binding.policy_definition_id,
            self.publication_policy.definition_id,
        )
        self.assertEqual(
            binding.policy_definition_version,
            self.publication_policy.version,
        )
        self.assertEqual(binding.policy_version, "policy-v1")

    def test_inactive_referenced_definitions_invalidate_projected_authority(
        self,
    ) -> None:
        definitions = (
            (
                "role_definition",
                "role_definition_id = ? AND version = ?",
                (self.owner_role.definition_id, self.owner_role.version),
            ),
            (
                "entitlement_definition",
                "entitlement_definition_id = ? AND version = ?",
                (
                    self.adforge_entitlement.definition_id,
                    self.adforge_entitlement.version,
                ),
            ),
            (
                "policy_definition",
                "policy_definition_id = ? AND version = ?",
                (
                    self.publication_policy.definition_id,
                    self.publication_policy.version,
                ),
            ),
            (
                "adapter_definition",
                "adapter_definition_id = ?",
                (self.adapter_id,),
            ),
            (
                "operation_definition",
                "operation_definition_id = ?",
                (self.operation_id,),
            ),
        )

        for table, where, parameters in definitions:
            with self.subTest(table=table):
                self.store.connection.execute(
                    f"UPDATE {table} SET status = 'inactive' WHERE {where}",
                    parameters,
                )
                self.store.connection.commit()

                with self.assertRaises(AuthorityError):
                    self.store.authenticate(
                        self.session_bearer,
                        self.session_id,
                    )
                self.assertFalse(self.store.ready())

                self.store.connection.execute(
                    f"UPDATE {table} SET status = 'active' WHERE {where}",
                    parameters,
                )
                self.store.connection.commit()

    def test_schema_metadata_declares_v01_revision_9(self) -> None:
        rows = self.store.connection.execute(
            """
            SELECT metadata_key, metadata_value
            FROM schema_metadata
            ORDER BY metadata_key
            """
        ).fetchall()

        metadata = {
            row["metadata_key"]: row["metadata_value"]
            for row in rows
        }

        self.assertEqual(metadata["schema_contract"], "anar-core.v0.1")
        self.assertEqual(metadata["schema_revision"], "9")
        self.assertEqual(
            metadata["role_metadata_authoritative"],
            "false",
        )

    def test_role_metadata_is_explicitly_non_authoritative(self) -> None:
        row = self.store.connection.execute(
            """
            SELECT
                grants_json,
                prohibitions_json,
                role_metadata_authoritative
            FROM role_definition
            WHERE role_definition_id = ?
              AND version = ?
            """,
            (
                self.owner_role.definition_id,
                self.owner_role.version,
            ),
        ).fetchone()

        self.assertIsNotNone(row)
        self.assertEqual(row["role_metadata_authoritative"], 0)
        self.assertTrue(row["grants_json"])
        self.assertTrue(row["prohibitions_json"])

    def test_policy_definition_id_is_stable_across_versions(self) -> None:
        version_two = self.store.define_policy(
            "publication.default",
            version=2,
        )

        self.assertEqual(
            version_two.definition_id,
            self.publication_policy.definition_id,
        )
        self.assertEqual(version_two.version, 2)
        self.assertTrue(version_two.definition_id.startswith("pol_"))

    def test_database_rejects_missing_policy_provenance(self) -> None:
        with self.assertRaises(sqlite3.IntegrityError):
            self.store.connection.execute(
                """
                UPDATE adapter_grant_binding
                SET policy_definition_id = NULL
                WHERE binding_id = ?
                """,
                (self.binding_id,),
            )

        self.store.connection.rollback()

    def test_database_rejects_unknown_policy_provenance(self) -> None:
        invalid_policy_id = "pol_" + ("0" * 32)

        with self.assertRaises(sqlite3.IntegrityError):
            self.store.connection.execute(
                """
                UPDATE adapter_grant_binding
                SET policy_definition_id = ?,
                    policy_definition_version = 1
                WHERE binding_id = ?
                """,
                (
                    invalid_policy_id,
                    self.binding_id,
                ),
            )

        self.store.connection.rollback()

    def test_legacy_policy_version_binding_migrates_in_place(self) -> None:
        database_path = Path(self.temp.name) / "anar-core.sqlite3"
        original_binding_id = self.binding_id

        self.store.close()

        connection = sqlite3.connect(database_path)
        connection.execute("PRAGMA foreign_keys = OFF")

        connection.execute(
            """
            ALTER TABLE adapter_grant_binding
            RENAME TO adapter_grant_binding_hardened_v2
            """
        )

        connection.execute(
            """
            CREATE TABLE adapter_grant_binding (
                binding_id TEXT PRIMARY KEY,
                membership_id TEXT NOT NULL REFERENCES membership(membership_id),
                adapter_definition_id TEXT NOT NULL REFERENCES adapter_definition(adapter_definition_id),
                operation_definition_id TEXT NOT NULL REFERENCES operation_definition(operation_definition_id),
                entitlement_definition_id TEXT NOT NULL,
                entitlement_definition_version INTEGER NOT NULL,
                resource_scope_json TEXT NOT NULL,
                policy_version TEXT NOT NULL,
                status TEXT NOT NULL,
                created_at REAL NOT NULL,
                FOREIGN KEY(
                    entitlement_definition_id,
                    entitlement_definition_version
                ) REFERENCES entitlement_definition(
                    entitlement_definition_id,
                    version
                )
            )
            """
        )

        connection.execute(
            """
            INSERT INTO adapter_grant_binding(
                binding_id,
                membership_id,
                adapter_definition_id,
                operation_definition_id,
                entitlement_definition_id,
                entitlement_definition_version,
                resource_scope_json,
                policy_version,
                status,
                created_at
            )
            SELECT
                binding_id,
                membership_id,
                adapter_definition_id,
                operation_definition_id,
                entitlement_definition_id,
                entitlement_definition_version,
                resource_scope_json,
                policy_version,
                status,
                created_at
            FROM adapter_grant_binding_hardened_v2
            """
        )

        connection.execute(
            "DROP TABLE adapter_grant_binding_hardened_v2"
        )
        connection.execute("DELETE FROM policy_definition")
        connection.commit()
        connection.close()

        self.store = AnarCoreStore(database_path)

        row = self.store.connection.execute(
            """
            SELECT
                binding_id,
                policy_definition_id,
                policy_definition_version,
                policy_version
            FROM adapter_grant_binding
            WHERE binding_id = ?
            """,
            (original_binding_id,),
        ).fetchone()

        expected_digest = hashlib.sha256(
            b"policy-v1"
        ).hexdigest()[:32]

        self.assertIsNotNone(row)
        self.assertEqual(row["binding_id"], original_binding_id)
        self.assertEqual(
            row["policy_definition_id"],
            f"pol_{expected_digest}",
        )
        self.assertEqual(row["policy_definition_version"], 1)
        self.assertEqual(row["policy_version"], "policy-v1")

        policy_row = self.store.connection.execute(
            """
            SELECT symbolic_name, version, status
            FROM policy_definition
            WHERE policy_definition_id = ?
              AND version = 1
            """,
            (row["policy_definition_id"],),
        ).fetchone()

        self.assertIsNotNone(policy_row)
        self.assertEqual(policy_row["symbolic_name"], "policy-v1")
        self.assertEqual(policy_row["version"], 1)
        self.assertEqual(policy_row["status"], "active")

        foreign_key_failures = self.store.connection.execute(
            "PRAGMA foreign_key_check"
        ).fetchall()

        self.assertEqual(foreign_key_failures, [])
    def test_authorization_generation_invalidates_old_session(self) -> None:
        second_adapter = self.store.define_adapter("secondary.adapter")
        second_operation = self.store.define_operation(
            second_adapter,
            "read",
        )

        self.store.grant_adapter_operation(
            self.membership_id,
            second_adapter,
            second_operation,
            self.adforge_entitlement,
            {"resource": "example"},
            self.publication_policy,
            "policy-v1",
        )

        with self.assertRaisesRegex(AuthorityError, "authorization version stale"):
            self.store.project_authorized_subject(self.session_id)

    def test_suspension_fails_closed(self) -> None:
        self.store.suspend_membership(self.membership_id)

        with self.assertRaises(AuthorityError):
            self.store.project_authorized_subject(self.session_id)

    def test_shared_boundary_requires_exact_agreement(self) -> None:
        subject = self.store.project_authorized_subject(self.session_id)
        core_binding = subject.adapter_bindings[0]

        assert_boundary_agreement(core_binding, core_binding)

        broker_binding = replace(
            core_binding,
            tenant_id="tnt_00000000000000000000000000000001",
        )

        with self.assertRaises(BoundaryMismatch):
            assert_boundary_agreement(core_binding, broker_binding)

    def test_signup_stores_argon2_hash_not_plaintext(self) -> None:
        (
            identity_id,
            account_id,
            verification_id,
            verification_token,
        ) = self.store.signup(
            "account@example.com",
            "correct horse battery staple",
            "Account Person",
        )

        row = self.store.connection.execute(
            """
            SELECT password_hash
            FROM password_credential
            WHERE account_id = ?
            """,
            (account_id,),
        ).fetchone()

        self.assertIsNotNone(row)
        self.assertNotEqual(
            row["password_hash"],
            "correct horse battery staple",
        )
        self.assertTrue(row["password_hash"].startswith("$argon2"))
        self.assertTrue(identity_id.startswith("idn_"))
        self.assertTrue(verification_id.startswith("emv_"))
        self.assertTrue(verification_token)

    def test_unverified_email_cannot_login(self) -> None:
        self.store.signup(
            "pending@example.com",
            "correct horse battery staple",
            "Pending Person",
        )

        with self.assertRaisesRegex(AuthorityError, "unauthorized"):
            self.store.login(
                "pending@example.com",
                "correct horse battery staple",
            )

    def test_email_verification_is_single_use(self) -> None:
        (
            identity_id,
            account_id,
            verification_id,
            verification_token,
        ) = self.store.signup(
            "verified@example.com",
            "correct horse battery staple",
            "Verified Person",
        )

        verified_account_id = self.store.verify_email(
            verification_token
        )

        self.assertEqual(verified_account_id, account_id)

        with self.assertRaises(AuthorityError):
            self.store.verify_email(verification_token)

    def test_verified_account_can_login_without_membership(self) -> None:
        (
            identity_id,
            account_id,
            verification_id,
            verification_token,
        ) = self.store.signup(
            "nomembership@example.com",
            "correct horse battery staple",
            "No Membership",
        )

        self.store.verify_email(verification_token)

        membership_count = self.store.connection.execute(
            """
            SELECT COUNT(*) AS count
            FROM membership
            WHERE identity_id = ?
            """,
            (identity_id,),
        ).fetchone()

        self.assertEqual(membership_count["count"], 0)

        account_session_id, bearer = self.store.login(
            "nomembership@example.com",
            "correct horse battery staple",
        )

        authenticated_identity, authenticated_account = (
            self.store.authenticate_account_session(
                bearer,
                account_session_id,
            )
        )

        self.assertEqual(authenticated_identity, identity_id)
        self.assertEqual(authenticated_account, account_id)

    def test_wrong_password_rejects_login(self) -> None:
        (
            identity_id,
            account_id,
            verification_id,
            verification_token,
        ) = self.store.signup(
            "wrongpassword@example.com",
            "correct horse battery staple",
            "Wrong Password",
        )

        self.store.verify_email(verification_token)

        with self.assertRaisesRegex(AuthorityError, "unauthorized"):
            self.store.login(
                "wrongpassword@example.com",
                "definitely the wrong password",
            )

    def test_account_session_bearer_is_not_stored_plaintext(self) -> None:
        (
            identity_id,
            account_id,
            verification_id,
            verification_token,
        ) = self.store.signup(
            "bearer@example.com",
            "correct horse battery staple",
            "Bearer Person",
        )

        self.store.verify_email(verification_token)

        account_session_id, bearer = self.store.login(
            "bearer@example.com",
            "correct horse battery staple",
        )

        row = self.store.connection.execute(
            """
            SELECT bearer_sha256
            FROM account_session
            WHERE account_session_id = ?
            """,
            (account_session_id,),
        ).fetchone()

        self.assertIsNotNone(row)
        self.assertNotEqual(row["bearer_sha256"], bearer)
        self.assertEqual(len(row["bearer_sha256"]), 64)

    def test_signout_revokes_account_session_and_replay_rejects(self) -> None:
        (
            identity_id,
            account_id,
            verification_id,
            verification_token,
        ) = self.store.signup(
            "signout@example.com",
            "correct horse battery staple",
            "Signout Person",
        )

        self.store.verify_email(verification_token)

        account_session_id, bearer = self.store.login(
            "signout@example.com",
            "correct horse battery staple",
        )

        self.store.signout(
            bearer,
            account_session_id,
        )

        row = self.store.connection.execute(
            """
            SELECT status, revoked_at
            FROM account_session
            WHERE account_session_id = ?
            """,
            (account_session_id,),
        ).fetchone()

        self.assertEqual(row["status"], "revoked")
        self.assertIsNotNone(row["revoked_at"])

        with self.assertRaises(AuthorityError):
            self.store.authenticate_account_session(
                bearer,
                account_session_id,
            )

        with self.assertRaises(AuthorityError):
            self.store.signout(
                bearer,
                account_session_id,
            )

    def test_account_session_requires_exact_bearer(self) -> None:
        (
            identity_id,
            account_id,
            verification_id,
            verification_token,
        ) = self.store.signup(
            "exactbearer@example.com",
            "correct horse battery staple",
            "Exact Bearer",
        )

        self.store.verify_email(verification_token)

        account_session_id, bearer = self.store.login(
            "exactbearer@example.com",
            "correct horse battery staple",
        )

        with self.assertRaises(AuthorityError):
            self.store.authenticate_account_session(
                "wrong-account-session-bearer",
                account_session_id,
            )

    def test_display_name_change_preserves_identity(self) -> None:
        (
            identity_id,
            account_id,
            verification_id,
            verification_token,
        ) = self.store.signup(
            "rename@example.com",
            "correct horse battery staple",
            "Original Name",
        )

        self.store.verify_email(verification_token)

        account_session_id, bearer = self.store.login(
            "rename@example.com",
            "correct horse battery staple",
        )

        self.store.change_display_name(
            bearer,
            account_session_id,
            "Updated Name",
        )

        row = self.store.connection.execute(
            """
            SELECT identity_id, display_name
            FROM identity
            WHERE identity_id = ?
            """,
            (identity_id,),
        ).fetchone()

        self.assertEqual(row["identity_id"], identity_id)
        self.assertEqual(row["display_name"], "Updated Name")

    def test_change_password_requires_current_password(self) -> None:
        (
            identity_id,
            account_id,
            verification_id,
            verification_token,
        ) = self.store.signup(
            "change-current@example.com",
            "correct horse battery staple",
            "Change Current",
        )

        self.store.verify_email(verification_token)

        account_session_id, bearer = self.store.login(
            "change-current@example.com",
            "correct horse battery staple",
        )

        with self.assertRaisesRegex(
            AuthorityError,
            "current password invalid",
        ):
            self.store.change_password(
                bearer,
                account_session_id,
                "wrong current password",
                "replacement password phrase",
                "replacement password phrase",
            )

        self.store.authenticate_account_session(
            bearer,
            account_session_id,
        )

    def test_change_password_requires_matching_confirmation(self) -> None:
        (
            identity_id,
            account_id,
            verification_id,
            verification_token,
        ) = self.store.signup(
            "change-match@example.com",
            "correct horse battery staple",
            "Change Match",
        )

        self.store.verify_email(verification_token)

        account_session_id, bearer = self.store.login(
            "change-match@example.com",
            "correct horse battery staple",
        )

        with self.assertRaisesRegex(
            AuthorityError,
            "new passwords do not match",
        ):
            self.store.change_password(
                bearer,
                account_session_id,
                "correct horse battery staple",
                "replacement password phrase",
                "different replacement phrase",
            )

    def test_change_password_rotates_credential_and_revokes_session(self) -> None:
        (
            identity_id,
            account_id,
            verification_id,
            verification_token,
        ) = self.store.signup(
            "change-success@example.com",
            "correct horse battery staple",
            "Change Success",
        )

        self.store.verify_email(verification_token)

        account_session_id, bearer = self.store.login(
            "change-success@example.com",
            "correct horse battery staple",
        )

        before = self.store.connection.execute(
            """
            SELECT credential_revision
            FROM password_credential
            WHERE account_id = ?
            """,
            (account_id,),
        ).fetchone()

        self.store.change_password(
            bearer,
            account_session_id,
            "correct horse battery staple",
            "replacement password phrase",
            "replacement password phrase",
        )

        after = self.store.connection.execute(
            """
            SELECT credential_revision
            FROM password_credential
            WHERE account_id = ?
            """,
            (account_id,),
        ).fetchone()

        self.assertEqual(
            after["credential_revision"],
            before["credential_revision"] + 1,
        )

        with self.assertRaises(AuthorityError):
            self.store.authenticate_account_session(
                bearer,
                account_session_id,
            )

        with self.assertRaisesRegex(AuthorityError, "unauthorized"):
            self.store.login(
                "change-success@example.com",
                "correct horse battery staple",
            )

        new_session_id, new_bearer = self.store.login(
            "change-success@example.com",
            "replacement password phrase",
        )

        authenticated_identity, authenticated_account = (
            self.store.authenticate_account_session(
                new_bearer,
                new_session_id,
            )
        )

        self.assertEqual(authenticated_identity, identity_id)
        self.assertEqual(authenticated_account, account_id)

    def test_password_reset_token_is_not_stored_plaintext(self) -> None:
        (
            identity_id,
            account_id,
            verification_id,
            verification_token,
        ) = self.store.signup(
            "reset-digest@example.com",
            "correct horse battery staple",
            "Reset Digest",
        )

        self.store.verify_email(verification_token)

        reset_id, reset_token = self.store.issue_password_reset(
            "reset-digest@example.com"
        )

        row = self.store.connection.execute(
            """
            SELECT token_sha256
            FROM password_reset_challenge
            WHERE reset_id = ?
            """,
            (reset_id,),
        ).fetchone()

        self.assertIsNotNone(row)
        self.assertNotEqual(row["token_sha256"], reset_token)
        self.assertEqual(len(row["token_sha256"]), 64)

    def test_new_password_reset_revokes_previous_reset(self) -> None:
        (
            identity_id,
            account_id,
            verification_id,
            verification_token,
        ) = self.store.signup(
            "reset-revoke@example.com",
            "correct horse battery staple",
            "Reset Revoke",
        )

        self.store.verify_email(verification_token)

        first_reset_id, first_token = self.store.issue_password_reset(
            "reset-revoke@example.com"
        )

        second_reset_id, second_token = self.store.issue_password_reset(
            "reset-revoke@example.com"
        )

        first = self.store.connection.execute(
            """
            SELECT status, revoked_at
            FROM password_reset_challenge
            WHERE reset_id = ?
            """,
            (first_reset_id,),
        ).fetchone()

        second = self.store.connection.execute(
            """
            SELECT status, revoked_at
            FROM password_reset_challenge
            WHERE reset_id = ?
            """,
            (second_reset_id,),
        ).fetchone()

        self.assertEqual(first["status"], "revoked")
        self.assertIsNotNone(first["revoked_at"])
        self.assertEqual(second["status"], "active")
        self.assertIsNone(second["revoked_at"])

        with self.assertRaises(AuthorityError):
            self.store.consume_password_reset(
                first_token,
                "replacement password phrase",
                "replacement password phrase",
            )

        consumed_account = self.store.consume_password_reset(
            second_token,
            "replacement password phrase",
            "replacement password phrase",
        )

        self.assertEqual(consumed_account, account_id)

    def test_password_reset_consumption_revokes_sessions_and_replay(self) -> None:
        (
            identity_id,
            account_id,
            verification_id,
            verification_token,
        ) = self.store.signup(
            "reset-success@example.com",
            "correct horse battery staple",
            "Reset Success",
        )

        self.store.verify_email(verification_token)

        account_session_id, bearer = self.store.login(
            "reset-success@example.com",
            "correct horse battery staple",
        )

        reset_id, reset_token = self.store.issue_password_reset(
            "reset-success@example.com"
        )

        returned_account_id = self.store.consume_password_reset(
            reset_token,
            "replacement password phrase",
            "replacement password phrase",
        )

        self.assertEqual(returned_account_id, account_id)

        reset_row = self.store.connection.execute(
            """
            SELECT status, consumed_at
            FROM password_reset_challenge
            WHERE reset_id = ?
            """,
            (reset_id,),
        ).fetchone()

        self.assertEqual(reset_row["status"], "consumed")
        self.assertIsNotNone(reset_row["consumed_at"])

        with self.assertRaises(AuthorityError):
            self.store.authenticate_account_session(
                bearer,
                account_session_id,
            )

        with self.assertRaises(AuthorityError):
            self.store.consume_password_reset(
                reset_token,
                "another replacement phrase",
                "another replacement phrase",
            )

        with self.assertRaisesRegex(AuthorityError, "unauthorized"):
            self.store.login(
                "reset-success@example.com",
                "correct horse battery staple",
            )

        new_session_id, new_bearer = self.store.login(
            "reset-success@example.com",
            "replacement password phrase",
        )

        authenticated_identity, authenticated_account = (
            self.store.authenticate_account_session(
                new_bearer,
                new_session_id,
            )
        )

        self.assertEqual(authenticated_identity, identity_id)
        self.assertEqual(authenticated_account, account_id)

    def test_email_change_requires_current_password(self) -> None:
        (
            identity_id,
            account_id,
            verification_id,
            verification_token,
        ) = self.store.signup(
            "email-current@example.com",
            "correct horse battery staple",
            "Email Current",
        )

        self.store.verify_email(verification_token)

        account_session_id, bearer = self.store.login(
            "email-current@example.com",
            "correct horse battery staple",
        )

        with self.assertRaisesRegex(
            AuthorityError,
            "current password invalid",
        ):
            self.store.request_email_change(
                bearer,
                account_session_id,
                "wrong current password",
                "email-current-new@example.com",
            )

        self.store.authenticate_account_session(
            bearer,
            account_session_id,
        )

    def test_email_change_token_is_not_stored_plaintext(self) -> None:
        (
            identity_id,
            account_id,
            verification_id,
            verification_token,
        ) = self.store.signup(
            "email-digest@example.com",
            "correct horse battery staple",
            "Email Digest",
        )

        self.store.verify_email(verification_token)

        account_session_id, bearer = self.store.login(
            "email-digest@example.com",
            "correct horse battery staple",
        )

        email_change_id, token = self.store.request_email_change(
            bearer,
            account_session_id,
            "correct horse battery staple",
            "email-digest-new@example.com",
        )

        row = self.store.connection.execute(
            """
            SELECT token_sha256, proposed_email
            FROM email_change_challenge
            WHERE email_change_id = ?
            """,
            (email_change_id,),
        ).fetchone()

        self.assertIsNotNone(row)
        self.assertNotEqual(row["token_sha256"], token)
        self.assertEqual(len(row["token_sha256"]), 64)
        self.assertEqual(
            row["proposed_email"],
            "email-digest-new@example.com",
        )

    def test_new_email_change_revokes_previous_challenge(self) -> None:
        (
            identity_id,
            account_id,
            verification_id,
            verification_token,
        ) = self.store.signup(
            "email-revoke@example.com",
            "correct horse battery staple",
            "Email Revoke",
        )

        self.store.verify_email(verification_token)

        account_session_id, bearer = self.store.login(
            "email-revoke@example.com",
            "correct horse battery staple",
        )

        first_id, first_token = self.store.request_email_change(
            bearer,
            account_session_id,
            "correct horse battery staple",
            "email-revoke-first@example.com",
        )

        second_id, second_token = self.store.request_email_change(
            bearer,
            account_session_id,
            "correct horse battery staple",
            "email-revoke-second@example.com",
        )

        first = self.store.connection.execute(
            """
            SELECT status, revoked_at
            FROM email_change_challenge
            WHERE email_change_id = ?
            """,
            (first_id,),
        ).fetchone()

        second = self.store.connection.execute(
            """
            SELECT status, revoked_at
            FROM email_change_challenge
            WHERE email_change_id = ?
            """,
            (second_id,),
        ).fetchone()

        self.assertEqual(first["status"], "revoked")
        self.assertIsNotNone(first["revoked_at"])
        self.assertEqual(second["status"], "active")
        self.assertIsNone(second["revoked_at"])

        with self.assertRaises(AuthorityError):
            self.store.consume_email_change(first_token)

        consumed_account = self.store.consume_email_change(
            second_token
        )

        self.assertEqual(consumed_account, account_id)

    def test_email_change_swaps_login_and_revokes_session(self) -> None:
        (
            identity_id,
            account_id,
            verification_id,
            verification_token,
        ) = self.store.signup(
            "email-old@example.com",
            "correct horse battery staple",
            "Email Swap",
        )

        self.store.verify_email(verification_token)

        account_session_id, bearer = self.store.login(
            "email-old@example.com",
            "correct horse battery staple",
        )

        email_change_id, token = self.store.request_email_change(
            bearer,
            account_session_id,
            "correct horse battery staple",
            "email-new@example.com",
        )

        returned_account_id = self.store.consume_email_change(
            token
        )

        self.assertEqual(returned_account_id, account_id)

        row = self.store.connection.execute(
            """
            SELECT normalized_email, verified_at, status
            FROM account_email
            WHERE account_id = ?
            """,
            (account_id,),
        ).fetchone()

        self.assertEqual(
            row["normalized_email"],
            "email-new@example.com",
        )
        self.assertEqual(row["status"], "active")
        self.assertIsNotNone(row["verified_at"])

        with self.assertRaises(AuthorityError):
            self.store.authenticate_account_session(
                bearer,
                account_session_id,
            )

        with self.assertRaisesRegex(AuthorityError, "unauthorized"):
            self.store.login(
                "email-old@example.com",
                "correct horse battery staple",
            )

        new_session_id, new_bearer = self.store.login(
            "email-new@example.com",
            "correct horse battery staple",
        )

        authenticated_identity, authenticated_account = (
            self.store.authenticate_account_session(
                new_bearer,
                new_session_id,
            )
        )

        self.assertEqual(authenticated_identity, identity_id)
        self.assertEqual(authenticated_account, account_id)

    def test_email_change_replay_is_rejected(self) -> None:
        (
            identity_id,
            account_id,
            verification_id,
            verification_token,
        ) = self.store.signup(
            "email-replay@example.com",
            "correct horse battery staple",
            "Email Replay",
        )

        self.store.verify_email(verification_token)

        account_session_id, bearer = self.store.login(
            "email-replay@example.com",
            "correct horse battery staple",
        )

        email_change_id, token = self.store.request_email_change(
            bearer,
            account_session_id,
            "correct horse battery staple",
            "email-replay-new@example.com",
        )

        self.store.consume_email_change(token)

        with self.assertRaises(AuthorityError):
            self.store.consume_email_change(token)

    def test_mfa_schema_allows_only_one_active_totp_per_account(self) -> None:
        (
            identity_id,
            account_id,
            verification_id,
            verification_token,
        ) = self.store.signup(
            "mfa-unique@example.com",
            "correct horse battery staple",
            "MFA Unique",
        )

        now = 1.0

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
                "mfa_11111111111111111111111111111111",
                account_id,
                "vault://client-security/totp/one",
                now,
                now,
            ),
        )
        self.store.connection.commit()

        with self.assertRaises(sqlite3.IntegrityError):
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
                    "mfa_22222222222222222222222222222222",
                    account_id,
                    "vault://client-security/totp/two",
                    now,
                    now,
                ),
            )

        self.store.connection.rollback()

    def test_mfa_schema_rejects_unknown_authenticator_kind(self) -> None:
        (
            identity_id,
            account_id,
            verification_id,
            verification_token,
        ) = self.store.signup(
            "mfa-kind@example.com",
            "correct horse battery staple",
            "MFA Kind",
        )

        with self.assertRaises(sqlite3.IntegrityError):
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
                ) VALUES (?, ?, 'unknown', ?, 'active', ?, NULL, ?)
                """,
                (
                    "mfa_33333333333333333333333333333333",
                    account_id,
                    "vault://client-security/mfa/unknown",
                    1.0,
                    1.0,
                ),
            )

        self.store.connection.rollback()

    def test_mfa_recovery_code_digest_is_unique(self) -> None:
        (
            identity_id,
            account_id,
            verification_id,
            verification_token,
        ) = self.store.signup(
            "mfa-recovery@example.com",
            "correct horse battery staple",
            "MFA Recovery",
        )

        digest = "a" * 64

        self.store.connection.execute(
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
                "mfr_11111111111111111111111111111111",
                account_id,
                digest,
                1.0,
            ),
        )
        self.store.connection.commit()

        with self.assertRaises(sqlite3.IntegrityError):
            self.store.connection.execute(
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
                    "mfr_22222222222222222222222222222222",
                    account_id,
                    digest,
                    1.0,
                ),
            )

        self.store.connection.rollback()

    def test_mfa_step_up_receipt_is_bound_to_account_session(self) -> None:
        (
            identity_id,
            account_id,
            verification_id,
            verification_token,
        ) = self.store.signup(
            "mfa-stepup@example.com",
            "correct horse battery staple",
            "MFA Step Up",
        )

        self.store.verify_email(verification_token)

        account_session_id, bearer = self.store.login(
            "mfa-stepup@example.com",
            "correct horse battery staple",
        )

        authenticator_id = "mfa_44444444444444444444444444444444"

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
                account_id,
                "vault://client-security/totp/four",
                1.0,
                1.0,
            ),
        )

        self.store.connection.execute(
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
            ) VALUES (?, ?, ?, ?, ?, 'password.change', ?, NULL, NULL, 'active', ?)
            """,
            (
                "mfs_11111111111111111111111111111111",
                "b" * 64,
                account_id,
                account_session_id,
                authenticator_id,
                9999999999.0,
                1.0,
            ),
        )

        self.store.connection.commit()

        row = self.store.connection.execute(
            """
            SELECT
                account_id,
                account_session_id,
                authenticator_id,
                purpose
            FROM mfa_step_up_receipt
            WHERE step_up_id = ?
            """,
            ("mfs_11111111111111111111111111111111",),
        ).fetchone()

        self.assertEqual(row["account_id"], account_id)
        self.assertEqual(
            row["account_session_id"],
            account_session_id,
        )
        self.assertEqual(row["authenticator_id"], authenticator_id)
        self.assertEqual(row["purpose"], "password.change")

    def test_totp_enrollment_requires_broker_attestation(self) -> None:
        (
            identity_id,
            account_id,
            verification_id,
            verification_token,
        ) = self.store.signup(
            "mfa-enroll@example.com",
            "correct horse battery staple",
            "MFA Enroll",
        )

        self.store.verify_email(verification_token)

        account_session_id, bearer = self.store.login(
            "mfa-enroll@example.com",
            "correct horse battery staple",
        )

        authenticator_id = self.store.begin_totp_enrollment(
            bearer,
            account_session_id,
            "vault://client-security/totp/enrollment",
        )

        row = self.store.connection.execute(
            """
            SELECT
                secret_reference,
                status,
                verified_at
            FROM mfa_authenticator
            WHERE authenticator_id = ?
            """,
            (authenticator_id,),
        ).fetchone()

        self.assertEqual(
            row["secret_reference"],
            "vault://client-security/totp/enrollment",
        )
        self.assertEqual(row["status"], "pending")
        self.assertIsNone(row["verified_at"])

        with self.assertRaisesRegex(
            AuthorityError,
            "MFA attestation unavailable",
        ):
            self.store.complete_totp_enrollment(
                bearer,
                account_session_id,
                authenticator_id,
                "broker-did-not-authorize-this",
            )

        unchanged = self.store.connection.execute(
            """
            SELECT status, verified_at
            FROM mfa_authenticator
            WHERE authenticator_id = ?
            """,
            (authenticator_id,),
        ).fetchone()

        self.assertEqual(unchanged["status"], "pending")
        self.assertIsNone(unchanged["verified_at"])

    def test_valid_broker_attestation_activates_totp_once(self) -> None:
        (
            identity_id,
            account_id,
            verification_id,
            verification_token,
        ) = self.store.signup(
            "mfa-activate@example.com",
            "correct horse battery staple",
            "MFA Activate",
        )

        self.store.verify_email(verification_token)

        account_session_id, bearer = self.store.login(
            "mfa-activate@example.com",
            "correct horse battery staple",
        )

        authenticator_id = self.store.begin_totp_enrollment(
            bearer,
            account_session_id,
            "vault://client-security/totp/activate",
        )

        token = "broker-enrollment-attestation"
        digest = hashlib.sha256(token.encode("utf-8")).hexdigest()

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
            ) VALUES (?, ?, ?, ?, ?, 'mfa.enroll', ?, NULL, NULL, 'active', ?)
            """,
            (
                "mfaa_11111111111111111111111111111111",
                digest,
                account_id,
                account_session_id,
                authenticator_id,
                9999999999.0,
                1.0,
            ),
        )
        self.store.connection.commit()

        stored = self.store.connection.execute(
            """
            SELECT token_sha256
            FROM mfa_broker_attestation
            WHERE attestation_id = ?
            """,
            ("mfaa_11111111111111111111111111111111",),
        ).fetchone()

        self.assertNotEqual(stored["token_sha256"], token)
        self.assertEqual(len(stored["token_sha256"]), 64)

        returned_authenticator = self.store.complete_totp_enrollment(
            bearer,
            account_session_id,
            authenticator_id,
            token,
        )

        self.assertEqual(returned_authenticator, authenticator_id)

        authenticator = self.store.connection.execute(
            """
            SELECT status, verified_at
            FROM mfa_authenticator
            WHERE authenticator_id = ?
            """,
            (authenticator_id,),
        ).fetchone()

        attestation = self.store.connection.execute(
            """
            SELECT status, consumed_at
            FROM mfa_broker_attestation
            WHERE attestation_id = ?
            """,
            ("mfaa_11111111111111111111111111111111",),
        ).fetchone()

        self.assertEqual(authenticator["status"], "active")
        self.assertIsNotNone(authenticator["verified_at"])
        self.assertEqual(attestation["status"], "consumed")
        self.assertIsNotNone(attestation["consumed_at"])

        with self.assertRaises(AuthorityError):
            self.store.complete_totp_enrollment(
                bearer,
                account_session_id,
                authenticator_id,
                token,
            )

    def test_broker_attestation_step_up_is_purpose_bound_and_single_use(self) -> None:
        (
            identity_id,
            account_id,
            verification_id,
            verification_token,
        ) = self.store.signup(
            "mfa-purpose@example.com",
            "correct horse battery staple",
            "MFA Purpose",
        )

        self.store.verify_email(verification_token)

        account_session_id, bearer = self.store.login(
            "mfa-purpose@example.com",
            "correct horse battery staple",
        )

        authenticator_id = "mfa_55555555555555555555555555555555"

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
                account_id,
                "vault://client-security/totp/purpose",
                1.0,
                1.0,
            ),
        )

        token = "broker-password-change-attestation"
        digest = hashlib.sha256(token.encode("utf-8")).hexdigest()

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
                "mfaa_22222222222222222222222222222222",
                digest,
                account_id,
                account_session_id,
                authenticator_id,
                9999999999.0,
                1.0,
            ),
        )
        self.store.connection.commit()

        with self.assertRaisesRegex(
            AuthorityError,
            "purpose mismatch",
        ):
            self.store.exchange_mfa_broker_attestation(
                bearer,
                account_session_id,
                authenticator_id,
                token,
                "email.change",
            )

        attestation_after_mismatch = self.store.connection.execute(
            """
            SELECT status, consumed_at
            FROM mfa_broker_attestation
            WHERE attestation_id = ?
            """,
            ("mfaa_22222222222222222222222222222222",),
        ).fetchone()

        self.assertEqual(
            attestation_after_mismatch["status"],
            "active",
        )
        self.assertIsNone(
            attestation_after_mismatch["consumed_at"]
        )

        step_up_id, step_up_token = (
            self.store.exchange_mfa_broker_attestation(
                bearer,
                account_session_id,
                authenticator_id,
                token,
                "password.change",
            )
        )

        receipt = self.store.connection.execute(
            """
            SELECT
                token_sha256,
                account_id,
                account_session_id,
                authenticator_id,
                purpose,
                status
            FROM mfa_step_up_receipt
            WHERE step_up_id = ?
            """,
            (step_up_id,),
        ).fetchone()

        self.assertNotEqual(
            receipt["token_sha256"],
            step_up_token,
        )
        self.assertEqual(receipt["account_id"], account_id)
        self.assertEqual(
            receipt["account_session_id"],
            account_session_id,
        )
        self.assertEqual(
            receipt["authenticator_id"],
            authenticator_id,
        )
        self.assertEqual(receipt["purpose"], "password.change")
        self.assertEqual(receipt["status"], "active")

        with self.assertRaises(AuthorityError):
            self.store.exchange_mfa_broker_attestation(
                bearer,
                account_session_id,
                authenticator_id,
                token,
                "password.change",
            )

        with self.assertRaisesRegex(
            AuthorityError,
            "purpose mismatch",
        ):
            self.store.consume_mfa_step_up(
                bearer,
                account_session_id,
                step_up_token,
                "email.change",
            )

        returned_authenticator = self.store.consume_mfa_step_up(
            bearer,
            account_session_id,
            step_up_token,
            "password.change",
        )

        self.assertEqual(
            returned_authenticator,
            authenticator_id,
        )

        with self.assertRaises(AuthorityError):
            self.store.consume_mfa_step_up(
                bearer,
                account_session_id,
                step_up_token,
                "password.change",
            )

    def test_mfa_step_up_is_bound_to_originating_account_session(self) -> None:
        (
            identity_id,
            account_id,
            verification_id,
            verification_token,
        ) = self.store.signup(
            "mfa-session@example.com",
            "correct horse battery staple",
            "MFA Session",
        )

        self.store.verify_email(verification_token)

        first_session_id, first_bearer = self.store.login(
            "mfa-session@example.com",
            "correct horse battery staple",
        )

        second_session_id, second_bearer = self.store.login(
            "mfa-session@example.com",
            "correct horse battery staple",
        )

        authenticator_id = "mfa_66666666666666666666666666666666"

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
                account_id,
                "vault://client-security/totp/session",
                1.0,
                1.0,
            ),
        )

        token = "broker-session-bound-attestation"
        digest = hashlib.sha256(token.encode("utf-8")).hexdigest()

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
                "mfaa_33333333333333333333333333333333",
                digest,
                account_id,
                first_session_id,
                authenticator_id,
                9999999999.0,
                1.0,
            ),
        )
        self.store.connection.commit()

        step_up_id, step_up_token = (
            self.store.exchange_mfa_broker_attestation(
                first_bearer,
                first_session_id,
                authenticator_id,
                token,
                "password.change",
            )
        )

        with self.assertRaisesRegex(
            AuthorityError,
            "session mismatch",
        ):
            self.store.consume_mfa_step_up(
                second_bearer,
                second_session_id,
                step_up_token,
                "password.change",
            )

        returned_authenticator = self.store.consume_mfa_step_up(
            first_bearer,
            first_session_id,
            step_up_token,
            "password.change",
        )

        self.assertEqual(
            returned_authenticator,
            authenticator_id,
        )

    def test_account_signout_revokes_pending_mfa_step_up(self) -> None:
        (
            _identity_id,
            account_id,
            _verification_id,
            verification_token,
        ) = self.store.signup(
            "mfa-signout-stepup@example.com",
            "correct horse battery staple",
            "MFA Signout Step Up",
        )
        self.store.verify_email(verification_token)

        authenticator_id = "mfa_signout_stepup_111111111111111111111111111111"

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
                account_id,
                "vault://client-security/totp/signout-stepup",
                1,
                1,
            ),
        )

        account_session_id, account_session_bearer = self.store.login(
            "mfa-signout-stepup@example.com",
            "correct horse battery staple",
        )

        step_up_id, step_up_token = self.store._mint_mfa_step_up(
            account_id,
            account_session_id,
            authenticator_id,
            "mfa.password.change",
            300,
            time.time(),
        )

        self.store.signout(
            account_session_bearer,
            account_session_id,
        )

        row = self.store.connection.execute(
            """
            SELECT status, consumed_at, revoked_at
            FROM mfa_step_up_receipt
            WHERE step_up_id = ?
            """,
            (step_up_id,),
        ).fetchone()

        self.assertEqual(row["status"], "revoked")
        self.assertIsNone(row["consumed_at"])
        self.assertIsNotNone(row["revoked_at"])

    def test_account_signout_revokes_pending_mfa_attestation(self) -> None:
        (
            _identity_id,
            account_id,
            _verification_id,
            verification_token,
        ) = self.store.signup(
            "mfa-signout-attestation@example.com",
            "correct horse battery staple",
            "MFA Signout Attestation",
        )
        self.store.verify_email(verification_token)

        account_session_id, account_session_bearer = self.store.login(
            "mfa-signout-attestation@example.com",
            "correct horse battery staple",
        )

        authenticator_id = "mfa_signout_attestation_111111111111111111111111111"

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
                account_id,
                "vault://client-security/totp/signout-attestation",
                1.0,
                1.0,
            ),
        )

        token = "broker-signout-attestation"
        digest = hashlib.sha256(token.encode("utf-8")).hexdigest()

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
                "mfaa_signout_11111111111111111111111111111111",
                digest,
                account_id,
                account_session_id,
                authenticator_id,
                9999999999.0,
                1.0,
            ),
        )

        self.store.connection.commit()

        self.store.signout(
            account_session_bearer,
            account_session_id,
        )

        row = self.store.connection.execute(
            """
            SELECT status, consumed_at, revoked_at
            FROM mfa_broker_attestation
            WHERE attestation_id = ?
            """,
            (
                "mfaa_signout_11111111111111111111111111111111",
            ),
        ).fetchone()

        self.assertEqual(row["status"], "revoked")
        self.assertIsNone(row["consumed_at"])
        self.assertIsNotNone(row["revoked_at"])

    def test_mfa_recovery_codes_are_hashed_and_single_use(self) -> None:
        (
            identity_id,
            account_id,
            verification_id,
            verification_token,
        ) = self.store.signup(
            "mfa-recovery-behavior@example.com",
            "correct horse battery staple",
            "MFA Recovery Behavior",
        )

        self.store.verify_email(verification_token)

        account_session_id, bearer = self.store.login(
            "mfa-recovery-behavior@example.com",
            "correct horse battery staple",
        )

        authenticator_id = "mfa_77777777777777777777777777777777"

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
                account_id,
                "vault://client-security/totp/recovery",
                1.0,
                1.0,
            ),
        )
        self.store.connection.commit()

        codes = self.store.issue_mfa_recovery_codes(
            bearer,
            account_session_id,
            count=3,
        )

        self.assertEqual(len(codes), 3)
        self.assertEqual(len(set(codes)), 3)

        rows = self.store.connection.execute(
            """
            SELECT code_sha256, status
            FROM mfa_recovery_code
            WHERE account_id = ?
            ORDER BY recovery_code_id
            """,
            (account_id,),
        ).fetchall()

        self.assertEqual(len(rows), 3)

        stored_digests = {
            row["code_sha256"]
            for row in rows
        }

        for code in codes:
            self.assertNotIn(code, stored_digests)
            self.assertIn(
                hashlib.sha256(
                    code.encode("utf-8")
                ).hexdigest(),
                stored_digests,
            )

        step_up_id, step_up_token = (
            self.store.exchange_mfa_recovery_code(
                bearer,
                account_session_id,
                codes[0],
                "email.change",
            )
        )

        consumed = self.store.connection.execute(
            """
            SELECT status, consumed_at
            FROM mfa_recovery_code
            WHERE code_sha256 = ?
            """,
            (
                hashlib.sha256(
                    codes[0].encode("utf-8")
                ).hexdigest(),
            ),
        ).fetchone()

        self.assertEqual(consumed["status"], "consumed")
        self.assertIsNotNone(consumed["consumed_at"])

        with self.assertRaises(AuthorityError):
            self.store.exchange_mfa_recovery_code(
                bearer,
                account_session_id,
                codes[0],
                "email.change",
            )

        returned_authenticator = self.store.consume_mfa_step_up(
            bearer,
            account_session_id,
            step_up_token,
            "email.change",
        )

        self.assertEqual(
            returned_authenticator,
            authenticator_id,
        )

        with self.assertRaises(AuthorityError):
            self.store.consume_mfa_step_up(
                bearer,
                account_session_id,
                step_up_token,
                "email.change",
            )

    def test_mfa_recovery_rotation_requires_fresh_step_up(self) -> None:
        (
            identity_id,
            account_id,
            verification_id,
            verification_token,
        ) = self.store.signup(
            "mfa-rotate-required@example.com",
            "correct horse battery staple",
            "MFA Rotate Required",
        )

        self.store.verify_email(verification_token)

        account_session_id, bearer = self.store.login(
            "mfa-rotate-required@example.com",
            "correct horse battery staple",
        )

        authenticator_id = "mfa_88888888888888888888888888888888"

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
                account_id,
                "vault://client-security/totp/rotate-required",
                1.0,
                1.0,
            ),
        )
        self.store.connection.commit()

        first_codes = self.store.issue_mfa_recovery_codes(
            bearer,
            account_session_id,
            count=3,
        )

        self.assertEqual(len(first_codes), 3)

        before = self.store.connection.execute(
            """
            SELECT
                recovery_code_id,
                code_sha256,
                status,
                revoked_at
            FROM mfa_recovery_code
            WHERE account_id = ?
            ORDER BY recovery_code_id
            """,
            (account_id,),
        ).fetchall()

        with self.assertRaisesRegex(
            AuthorityError,
            "MFA step-up required for recovery code rotation",
        ):
            self.store.issue_mfa_recovery_codes(
                bearer,
                account_session_id,
                count=3,
            )

        after = self.store.connection.execute(
            """
            SELECT
                recovery_code_id,
                code_sha256,
                status,
                revoked_at
            FROM mfa_recovery_code
            WHERE account_id = ?
            ORDER BY recovery_code_id
            """,
            (account_id,),
        ).fetchall()

        self.assertEqual(
            [tuple(row) for row in after],
            [tuple(row) for row in before],
        )

    def test_mfa_recovery_rotation_is_purpose_bound_and_single_use(self) -> None:
        (
            identity_id,
            account_id,
            verification_id,
            verification_token,
        ) = self.store.signup(
            "mfa-rotate-once@example.com",
            "correct horse battery staple",
            "MFA Rotate Once",
        )

        self.store.verify_email(verification_token)

        account_session_id, bearer = self.store.login(
            "mfa-rotate-once@example.com",
            "correct horse battery staple",
        )

        authenticator_id = "mfa_99999999999999999999999999999999"

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
                account_id,
                "vault://client-security/totp/rotate-once",
                1.0,
                1.0,
            ),
        )
        self.store.connection.commit()

        original_codes = self.store.issue_mfa_recovery_codes(
            bearer,
            account_session_id,
            count=2,
        )

        wrong_attestation_token = "broker-password-change-for-rotation-test"

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
                "mfaa_44444444444444444444444444444444",
                hashlib.sha256(
                    wrong_attestation_token.encode("utf-8")
                ).hexdigest(),
                account_id,
                account_session_id,
                authenticator_id,
                9999999999.0,
                1.0,
            ),
        )
        self.store.connection.commit()

        wrong_step_up_id, wrong_step_up_token = (
            self.store.exchange_mfa_broker_attestation(
                bearer,
                account_session_id,
                authenticator_id,
                wrong_attestation_token,
                "password.change",
            )
        )

        with self.assertRaisesRegex(
            AuthorityError,
            "MFA step-up purpose mismatch",
        ):
            self.store.issue_mfa_recovery_codes(
                bearer,
                account_session_id,
                count=2,
                step_up_token=wrong_step_up_token,
            )

        wrong_receipt = self.store.connection.execute(
            """
            SELECT status, consumed_at
            FROM mfa_step_up_receipt
            WHERE step_up_id = ?
            """,
            (wrong_step_up_id,),
        ).fetchone()

        self.assertEqual(wrong_receipt["status"], "active")
        self.assertIsNone(wrong_receipt["consumed_at"])

        rotation_attestation_token = "broker-recovery-rotation-attestation"

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
            ) VALUES (?, ?, ?, ?, ?, 'mfa.recovery.rotate', ?, NULL, NULL, 'active', ?)
            """,
            (
                "mfaa_55555555555555555555555555555555",
                hashlib.sha256(
                    rotation_attestation_token.encode("utf-8")
                ).hexdigest(),
                account_id,
                account_session_id,
                authenticator_id,
                9999999999.0,
                1.0,
            ),
        )
        self.store.connection.commit()

        rotation_step_up_id, rotation_step_up_token = (
            self.store.exchange_mfa_broker_attestation(
                bearer,
                account_session_id,
                authenticator_id,
                rotation_attestation_token,
                "mfa.recovery.rotate",
            )
        )

        rotated_codes = self.store.issue_mfa_recovery_codes(
            bearer,
            account_session_id,
            count=2,
            step_up_token=rotation_step_up_token,
        )

        self.assertEqual(len(rotated_codes), 2)
        self.assertEqual(len(set(rotated_codes)), 2)
        self.assertTrue(
            set(original_codes).isdisjoint(set(rotated_codes))
        )

        rotation_receipt = self.store.connection.execute(
            """
            SELECT status, consumed_at
            FROM mfa_step_up_receipt
            WHERE step_up_id = ?
            """,
            (rotation_step_up_id,),
        ).fetchone()

        self.assertEqual(rotation_receipt["status"], "consumed")
        self.assertIsNotNone(rotation_receipt["consumed_at"])

        original_digests = {
            hashlib.sha256(code.encode("utf-8")).hexdigest()
            for code in original_codes
        }

        original_rows = self.store.connection.execute(
            """
            SELECT code_sha256, status, revoked_at
            FROM mfa_recovery_code
            WHERE account_id = ?
            """,
            (account_id,),
        ).fetchall()

        original_by_digest = {
            row["code_sha256"]: row
            for row in original_rows
            if row["code_sha256"] in original_digests
        }

        self.assertEqual(
            set(original_by_digest),
            original_digests,
        )

        for row in original_by_digest.values():
            self.assertEqual(row["status"], "revoked")
            self.assertIsNotNone(row["revoked_at"])

        with self.assertRaises(AuthorityError):
            self.store.issue_mfa_recovery_codes(
                bearer,
                account_session_id,
                count=2,
                step_up_token=rotation_step_up_token,
            )

    def test_non_mfa_sensitive_actions_remain_compatible(self) -> None:
        (
            identity_id,
            account_id,
            verification_id,
            verification_token,
        ) = self.store.signup(
            "sensitive-compatible@example.com",
            "correct horse battery staple",
            "Sensitive Compatible",
        )

        self.store.verify_email(verification_token)

        account_session_id, bearer = self.store.login(
            "sensitive-compatible@example.com",
            "correct horse battery staple",
        )

        email_change_id, email_token = self.store.request_email_change(
            bearer,
            account_session_id,
            "correct horse battery staple",
            "sensitive-compatible-new@example.com",
        )

        self.assertTrue(email_change_id.startswith("emc_"))
        self.assertTrue(email_token)

        self.store.change_password(
            bearer,
            account_session_id,
            "correct horse battery staple",
            "replacement password phrase",
            "replacement password phrase",
        )

        with self.assertRaisesRegex(AuthorityError, "unauthorized"):
            self.store.login(
                "sensitive-compatible@example.com",
                "correct horse battery staple",
            )

        new_session_id, new_bearer = self.store.login(
            "sensitive-compatible@example.com",
            "replacement password phrase",
        )

        authenticated_identity, authenticated_account = (
            self.store.authenticate_account_session(
                new_bearer,
                new_session_id,
            )
        )

        self.assertEqual(authenticated_identity, identity_id)
        self.assertEqual(authenticated_account, account_id)

    def test_mfa_password_change_requires_and_consumes_correct_step_up(self) -> None:
        (
            identity_id,
            account_id,
            verification_id,
            verification_token,
        ) = self.store.signup(
            "mfa-password-action@example.com",
            "correct horse battery staple",
            "MFA Password Action",
        )

        self.store.verify_email(verification_token)

        account_session_id, bearer = self.store.login(
            "mfa-password-action@example.com",
            "correct horse battery staple",
        )

        authenticator_id = "mfa_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"

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
                account_id,
                "vault://client-security/totp/password-action",
                1.0,
                1.0,
            ),
        )
        self.store.connection.commit()

        with self.assertRaisesRegex(
            AuthorityError,
            "MFA step-up required for password change",
        ):
            self.store.change_password(
                bearer,
                account_session_id,
                "correct horse battery staple",
                "replacement password phrase",
                "replacement password phrase",
            )

        attestation_token = "broker-password-sensitive-action"

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
                "mfaa_66666666666666666666666666666666",
                hashlib.sha256(
                    attestation_token.encode("utf-8")
                ).hexdigest(),
                account_id,
                account_session_id,
                authenticator_id,
                9999999999.0,
                1.0,
            ),
        )
        self.store.connection.commit()

        step_up_id, step_up_token = (
            self.store.exchange_mfa_broker_attestation(
                bearer,
                account_session_id,
                authenticator_id,
                attestation_token,
                "password.change",
            )
        )

        self.store.change_password(
            bearer,
            account_session_id,
            "correct horse battery staple",
            "replacement password phrase",
            "replacement password phrase",
            step_up_token=step_up_token,
        )

        receipt = self.store.connection.execute(
            """
            SELECT status, consumed_at
            FROM mfa_step_up_receipt
            WHERE step_up_id = ?
            """,
            (step_up_id,),
        ).fetchone()

        self.assertEqual(receipt["status"], "consumed")
        self.assertIsNotNone(receipt["consumed_at"])

        with self.assertRaises(AuthorityError):
            self.store.authenticate_account_session(
                bearer,
                account_session_id,
            )

        with self.assertRaisesRegex(AuthorityError, "unauthorized"):
            self.store.login(
                "mfa-password-action@example.com",
                "correct horse battery staple",
            )

        new_session_id, new_bearer = self.store.login(
            "mfa-password-action@example.com",
            "replacement password phrase",
        )

        self.store.authenticate_account_session(
            new_bearer,
            new_session_id,
        )

    def test_mfa_email_change_is_purpose_bound_and_consumes_correct_step_up(self) -> None:
        (
            identity_id,
            account_id,
            verification_id,
            verification_token,
        ) = self.store.signup(
            "mfa-email-action@example.com",
            "correct horse battery staple",
            "MFA Email Action",
        )

        self.store.verify_email(verification_token)

        account_session_id, bearer = self.store.login(
            "mfa-email-action@example.com",
            "correct horse battery staple",
        )

        authenticator_id = "mfa_bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"

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
                account_id,
                "vault://client-security/totp/email-action",
                1.0,
                1.0,
            ),
        )
        self.store.connection.commit()

        with self.assertRaisesRegex(
            AuthorityError,
            "MFA step-up required for email change",
        ):
            self.store.request_email_change(
                bearer,
                account_session_id,
                "correct horse battery staple",
                "mfa-email-action-new@example.com",
            )

        wrong_attestation_token = "broker-password-for-email-action"

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
                "mfaa_77777777777777777777777777777777",
                hashlib.sha256(
                    wrong_attestation_token.encode("utf-8")
                ).hexdigest(),
                account_id,
                account_session_id,
                authenticator_id,
                9999999999.0,
                1.0,
            ),
        )
        self.store.connection.commit()

        wrong_step_up_id, wrong_step_up_token = (
            self.store.exchange_mfa_broker_attestation(
                bearer,
                account_session_id,
                authenticator_id,
                wrong_attestation_token,
                "password.change",
            )
        )

        with self.assertRaisesRegex(
            AuthorityError,
            "MFA step-up purpose mismatch",
        ):
            self.store.request_email_change(
                bearer,
                account_session_id,
                "correct horse battery staple",
                "mfa-email-action-new@example.com",
                step_up_token=wrong_step_up_token,
            )

        wrong_receipt = self.store.connection.execute(
            """
            SELECT status, consumed_at
            FROM mfa_step_up_receipt
            WHERE step_up_id = ?
            """,
            (wrong_step_up_id,),
        ).fetchone()

        self.assertEqual(wrong_receipt["status"], "active")
        self.assertIsNone(wrong_receipt["consumed_at"])

        correct_attestation_token = "broker-email-sensitive-action"

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
            ) VALUES (?, ?, ?, ?, ?, 'email.change', ?, NULL, NULL, 'active', ?)
            """,
            (
                "mfaa_88888888888888888888888888888888",
                hashlib.sha256(
                    correct_attestation_token.encode("utf-8")
                ).hexdigest(),
                account_id,
                account_session_id,
                authenticator_id,
                9999999999.0,
                1.0,
            ),
        )
        self.store.connection.commit()

        correct_step_up_id, correct_step_up_token = (
            self.store.exchange_mfa_broker_attestation(
                bearer,
                account_session_id,
                authenticator_id,
                correct_attestation_token,
                "email.change",
            )
        )

        email_change_id, email_change_token = (
            self.store.request_email_change(
                bearer,
                account_session_id,
                "correct horse battery staple",
                "mfa-email-action-new@example.com",
                step_up_token=correct_step_up_token,
            )
        )

        self.assertTrue(email_change_id.startswith("emc_"))
        self.assertTrue(email_change_token)

        correct_receipt = self.store.connection.execute(
            """
            SELECT status, consumed_at
            FROM mfa_step_up_receipt
            WHERE step_up_id = ?
            """,
            (correct_step_up_id,),
        ).fetchone()

        self.assertEqual(correct_receipt["status"], "consumed")
        self.assertIsNotNone(correct_receipt["consumed_at"])

        with self.assertRaises(AuthorityError):
            self.store.request_email_change(
                bearer,
                account_session_id,
                "correct horse battery staple",
                "another-email@example.com",
                step_up_token=correct_step_up_token,
            )

    def test_failed_sensitive_action_does_not_burn_mfa_step_up(self) -> None:
        (
            identity_id,
            account_id,
            verification_id,
            verification_token,
        ) = self.store.signup(
            "mfa-action-rollback@example.com",
            "correct horse battery staple",
            "MFA Action Rollback",
        )

        self.store.verify_email(verification_token)

        account_session_id, bearer = self.store.login(
            "mfa-action-rollback@example.com",
            "correct horse battery staple",
        )

        authenticator_id = "mfa_cccccccccccccccccccccccccccccccc"

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
                account_id,
                "vault://client-security/totp/action-rollback",
                1.0,
                1.0,
            ),
        )

        attestation_token = "broker-password-rollback-action"

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
                "mfaa_99999999999999999999999999999999",
                hashlib.sha256(
                    attestation_token.encode("utf-8")
                ).hexdigest(),
                account_id,
                account_session_id,
                authenticator_id,
                9999999999.0,
                1.0,
            ),
        )
        self.store.connection.commit()

        step_up_id, step_up_token = (
            self.store.exchange_mfa_broker_attestation(
                bearer,
                account_session_id,
                authenticator_id,
                attestation_token,
                "password.change",
            )
        )

        with self.assertRaisesRegex(
            AuthorityError,
            "current password invalid",
        ):
            self.store.change_password(
                bearer,
                account_session_id,
                "wrong current password",
                "replacement password phrase",
                "replacement password phrase",
                step_up_token=step_up_token,
            )

        receipt = self.store.connection.execute(
            """
            SELECT status, consumed_at
            FROM mfa_step_up_receipt
            WHERE step_up_id = ?
            """,
            (step_up_id,),
        ).fetchone()

        self.assertEqual(receipt["status"], "active")
        self.assertIsNone(receipt["consumed_at"])

        self.store.change_password(
            bearer,
            account_session_id,
            "correct horse battery staple",
            "replacement password phrase",
            "replacement password phrase",
            step_up_token=step_up_token,
        )

        consumed = self.store.connection.execute(
            """
            SELECT status, consumed_at
            FROM mfa_step_up_receipt
            WHERE step_up_id = ?
            """,
            (step_up_id,),
        ).fetchone()

        self.assertEqual(consumed["status"], "consumed")
        self.assertIsNotNone(consumed["consumed_at"])

    def test_membership_schema_allows_history_but_only_one_current(self) -> None:
        schema = self.store.connection.execute(
            """
            SELECT sql
            FROM sqlite_master
            WHERE type = 'table'
              AND name = 'membership'
            """
        ).fetchone()

        self.assertIsNotNone(schema)

        normalized_schema = "".join(
            str(schema["sql"] or "").upper().split()
        )

        self.assertNotIn(
            "UNIQUE(IDENTITY_ID,ORGANIZATION_ID)",
            normalized_schema,
        )

        index = self.store.connection.execute(
            """
            SELECT sql
            FROM sqlite_master
            WHERE type = 'index'
              AND name = 'one_current_membership_per_identity_organization'
            """
        ).fetchone()

        self.assertIsNotNone(index)
        self.assertIn(
            "WHERE status IN ('active', 'suspended')",
            str(index["sql"]),
        )

        with self.assertRaises(sqlite3.IntegrityError):
            self.store.connection.execute(
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
                    "mbr_11111111111111111111111111111111",
                    self.identity_id,
                    self.organization_id,
                    2.0,
                ),
            )

        self.store.connection.rollback()

        self.store.connection.execute(
            """
            UPDATE membership
            SET status = 'left',
                authorization_version = authorization_version + 1
            WHERE membership_id = ?
            """,
            (self.membership_id,),
        )

        replacement_membership_id = (
            "mbr_22222222222222222222222222222222"
        )

        self.store.connection.execute(
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
                replacement_membership_id,
                self.identity_id,
                self.organization_id,
                3.0,
            ),
        )

        historical_membership_id = (
            "mbr_33333333333333333333333333333333"
        )

        self.store.connection.execute(
            """
            INSERT INTO membership(
                membership_id,
                identity_id,
                organization_id,
                status,
                authorization_version,
                entitlement_version,
                created_at
            ) VALUES (?, ?, ?, 'left', 1, 1, ?)
            """,
            (
                historical_membership_id,
                self.identity_id,
                self.organization_id,
                4.0,
            ),
        )

        self.store.connection.commit()

        rows = self.store.connection.execute(
            """
            SELECT membership_id, status
            FROM membership
            WHERE identity_id = ?
              AND organization_id = ?
            """,
            (
                self.identity_id,
                self.organization_id,
            ),
        ).fetchall()

        self.assertEqual(len(rows), 3)

        memberships = {
            row["membership_id"]: row["status"]
            for row in rows
        }

        self.assertEqual(
            memberships[self.membership_id],
            "left",
        )
        self.assertEqual(
            memberships[replacement_membership_id],
            "active",
        )
        self.assertEqual(
            memberships[historical_membership_id],
            "left",
        )

    def test_legacy_membership_unique_migrates_without_severing_dependents(self) -> None:
        database_path = Path(self.temp.name) / "anar-core.sqlite3"

        original_membership_id = self.membership_id
        original_binding_id = self.binding_id

        role_assignment = self.store.connection.execute(
            """
            SELECT role_assignment_id
            FROM role_assignment
            WHERE membership_id = ?
            """,
            (original_membership_id,),
        ).fetchone()

        entitlement_grant = self.store.connection.execute(
            """
            SELECT entitlement_grant_id
            FROM entitlement_grant
            WHERE membership_id = ?
            """,
            (original_membership_id,),
        ).fetchone()

        self.assertIsNotNone(role_assignment)
        self.assertIsNotNone(entitlement_grant)

        original_role_assignment_id = (
            role_assignment["role_assignment_id"]
        )
        original_entitlement_grant_id = (
            entitlement_grant["entitlement_grant_id"]
        )

        self.store.close()

        connection = sqlite3.connect(database_path)
        connection.execute("PRAGMA foreign_keys = OFF")
        connection.execute("PRAGMA legacy_alter_table = ON")

        connection.execute(
            """
            DROP INDEX
                one_current_membership_per_identity_organization
            """
        )

        connection.execute(
            """
            ALTER TABLE membership
            RENAME TO membership_revision_7
            """
        )

        connection.execute(
            """
            CREATE TABLE membership (
                membership_id TEXT PRIMARY KEY,
                identity_id TEXT NOT NULL
                    REFERENCES identity(identity_id),
                organization_id TEXT NOT NULL
                    REFERENCES organization(organization_id),
                status TEXT NOT NULL,
                authorization_version INTEGER NOT NULL DEFAULT 1,
                entitlement_version INTEGER NOT NULL DEFAULT 1,
                created_at REAL NOT NULL,
                UNIQUE(identity_id, organization_id)
            )
            """
        )

        connection.execute(
            """
            INSERT INTO membership(
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
            FROM membership_revision_7
            """
        )

        connection.execute(
            "DROP TABLE membership_revision_7"
        )

        connection.commit()
        connection.close()

        self.store = AnarCoreStore(database_path)

        membership = self.store.connection.execute(
            """
            SELECT
                membership_id,
                identity_id,
                organization_id,
                status
            FROM membership
            WHERE membership_id = ?
            """,
            (original_membership_id,),
        ).fetchone()

        self.assertIsNotNone(membership)
        self.assertEqual(
            membership["membership_id"],
            original_membership_id,
        )
        self.assertEqual(
            membership["identity_id"],
            self.identity_id,
        )
        self.assertEqual(
            membership["organization_id"],
            self.organization_id,
        )
        self.assertEqual(membership["status"], "active")

        migrated_role = self.store.connection.execute(
            """
            SELECT membership_id
            FROM role_assignment
            WHERE role_assignment_id = ?
            """,
            (original_role_assignment_id,),
        ).fetchone()

        migrated_entitlement = self.store.connection.execute(
            """
            SELECT membership_id
            FROM entitlement_grant
            WHERE entitlement_grant_id = ?
            """,
            (original_entitlement_grant_id,),
        ).fetchone()

        migrated_binding = self.store.connection.execute(
            """
            SELECT membership_id
            FROM adapter_grant_binding
            WHERE binding_id = ?
            """,
            (original_binding_id,),
        ).fetchone()

        self.assertIsNotNone(migrated_role)
        self.assertIsNotNone(migrated_entitlement)
        self.assertIsNotNone(migrated_binding)

        self.assertEqual(
            migrated_role["membership_id"],
            original_membership_id,
        )
        self.assertEqual(
            migrated_entitlement["membership_id"],
            original_membership_id,
        )
        self.assertEqual(
            migrated_binding["membership_id"],
            original_membership_id,
        )

        for table in (
            "role_assignment",
            "entitlement_grant",
            "adapter_grant_binding",
            "session",
        ):
            foreign_keys = self.store.connection.execute(
                f"PRAGMA foreign_key_list({table})"
            ).fetchall()

            membership_targets = {
                row["table"]
                for row in foreign_keys
                if row["from"] == "membership_id"
            }

            if membership_targets:
                self.assertEqual(
                    membership_targets,
                    {"membership"},
                )

        index = self.store.connection.execute(
            """
            SELECT sql
            FROM sqlite_master
            WHERE type = 'index'
              AND name = 'one_current_membership_per_identity_organization'
            """
        ).fetchone()

        self.assertIsNotNone(index)

        schema = self.store.connection.execute(
            """
            SELECT sql
            FROM sqlite_master
            WHERE type = 'table'
              AND name = 'membership'
            """
        ).fetchone()

        normalized_schema = "".join(
            str(schema["sql"] or "").upper().split()
        )

        self.assertNotIn(
            "UNIQUE(IDENTITY_ID,ORGANIZATION_ID)",
            normalized_schema,
        )

        foreign_key_failures = self.store.connection.execute(
            "PRAGMA foreign_key_check"
        ).fetchall()

        self.assertEqual(foreign_key_failures, [])

    def test_active_membership_blocks_fresh_invitation_without_consuming_it(self) -> None:
        invitation_id, invitation_code = self.store.issue_invitation(
            self.organization_id,
            self.tenant_id,
            role_refs=(self.owner_role,),
            entitlement_refs=(self.adforge_entitlement,),
        )

        with self.assertRaisesRegex(
            AuthorityError,
            "current membership already exists",
        ):
            self.store.redeem_invitation(
                invitation_code,
                self.identity_id,
            )

        invitation = self.store.connection.execute(
            """
            SELECT status, consumed_uses
            FROM invitation
            WHERE invitation_id = ?
            """,
            (invitation_id,),
        ).fetchone()

        self.assertIsNotNone(invitation)
        self.assertEqual(invitation["status"], "active")
        self.assertEqual(invitation["consumed_uses"], 0)

    def test_suspended_membership_blocks_fresh_invitation_without_consuming_it(self) -> None:
        self.store.connection.execute(
            """
            UPDATE membership
            SET status = 'suspended'
            WHERE membership_id = ?
            """,
            (self.membership_id,),
        )
        self.store.connection.commit()

        invitation_id, invitation_code = self.store.issue_invitation(
            self.organization_id,
            self.tenant_id,
            role_refs=(self.owner_role,),
            entitlement_refs=(self.adforge_entitlement,),
        )

        with self.assertRaisesRegex(
            AuthorityError,
            "current membership already exists",
        ):
            self.store.redeem_invitation(
                invitation_code,
                self.identity_id,
            )

        invitation = self.store.connection.execute(
            """
            SELECT status, consumed_uses
            FROM invitation
            WHERE invitation_id = ?
            """,
            (invitation_id,),
        ).fetchone()

        self.assertIsNotNone(invitation)
        self.assertEqual(invitation["status"], "active")
        self.assertEqual(invitation["consumed_uses"], 0)

    def test_left_membership_can_rejoin_only_with_fresh_invitation_and_new_membership_id(self) -> None:
        self.store.connection.execute(
            """
            UPDATE membership
            SET status = 'left',
                authorization_version = authorization_version + 1
            WHERE membership_id = ?
            """,
            (self.membership_id,),
        )
        self.store.connection.commit()

        with self.assertRaises(AuthorityError):
            self.store.redeem_invitation(
                self.invitation_code,
                self.identity_id,
            )

        invitation_id, invitation_code = self.store.issue_invitation(
            self.organization_id,
            self.tenant_id,
            role_refs=(self.owner_role,),
            entitlement_refs=(self.adforge_entitlement,),
        )

        replacement_membership_id = self.store.redeem_invitation(
            invitation_code,
            self.identity_id,
        )

        self.assertNotEqual(
            replacement_membership_id,
            self.membership_id,
        )

        memberships = self.store.connection.execute(
            """
            SELECT membership_id, status
            FROM membership
            WHERE identity_id = ?
              AND organization_id = ?
            """,
            (
                self.identity_id,
                self.organization_id,
            ),
        ).fetchall()

        status_by_membership = {
            row["membership_id"]: row["status"]
            for row in memberships
        }

        self.assertEqual(len(memberships), 2)
        self.assertEqual(
            status_by_membership[self.membership_id],
            "left",
        )
        self.assertEqual(
            status_by_membership[replacement_membership_id],
            "active",
        )

        invitation = self.store.connection.execute(
            """
            SELECT status, consumed_uses
            FROM invitation
            WHERE invitation_id = ?
            """,
            (invitation_id,),
        ).fetchone()

        self.assertIsNotNone(invitation)
        self.assertEqual(invitation["status"], "consumed")
        self.assertEqual(invitation["consumed_uses"], 1)

    def test_revoked_membership_can_rejoin_with_new_membership_id(self) -> None:
        self.store.connection.execute(
            """
            UPDATE membership
            SET status = 'revoked',
                authorization_version = authorization_version + 1
            WHERE membership_id = ?
            """,
            (self.membership_id,),
        )
        self.store.connection.commit()

        invitation_id, invitation_code = self.store.issue_invitation(
            self.organization_id,
            self.tenant_id,
            role_refs=(self.owner_role,),
            entitlement_refs=(self.adforge_entitlement,),
        )

        replacement_membership_id = self.store.redeem_invitation(
            invitation_code,
            self.identity_id,
        )

        self.assertNotEqual(
            replacement_membership_id,
            self.membership_id,
        )

        old_membership = self.store.connection.execute(
            """
            SELECT status
            FROM membership
            WHERE membership_id = ?
            """,
            (self.membership_id,),
        ).fetchone()

        new_membership = self.store.connection.execute(
            """
            SELECT status
            FROM membership
            WHERE membership_id = ?
            """,
            (replacement_membership_id,),
        ).fetchone()

        invitation = self.store.connection.execute(
            """
            SELECT status, consumed_uses
            FROM invitation
            WHERE invitation_id = ?
            """,
            (invitation_id,),
        ).fetchone()

        self.assertIsNotNone(old_membership)
        self.assertIsNotNone(new_membership)
        self.assertIsNotNone(invitation)

        self.assertEqual(old_membership["status"], "revoked")
        self.assertEqual(new_membership["status"], "active")
        self.assertEqual(invitation["status"], "consumed")
        self.assertEqual(invitation["consumed_uses"], 1)

    def test_rejoin_does_not_resurrect_historical_role_or_entitlement_rows(self) -> None:
        old_role_rows = self.store.connection.execute(
            """
            SELECT role_assignment_id
            FROM role_assignment
            WHERE membership_id = ?
            """,
            (self.membership_id,),
        ).fetchall()

        old_entitlement_rows = self.store.connection.execute(
            """
            SELECT entitlement_grant_id
            FROM entitlement_grant
            WHERE membership_id = ?
            """,
            (self.membership_id,),
        ).fetchall()

        self.store.connection.execute(
            """
            UPDATE membership
            SET status = 'left',
                authorization_version = authorization_version + 1
            WHERE membership_id = ?
            """,
            (self.membership_id,),
        )
        self.store.connection.commit()

        _, invitation_code = self.store.issue_invitation(
            self.organization_id,
            self.tenant_id,
            role_refs=(self.owner_role,),
            entitlement_refs=(self.adforge_entitlement,),
        )

        replacement_membership_id = self.store.redeem_invitation(
            invitation_code,
            self.identity_id,
        )

        new_role_rows = self.store.connection.execute(
            """
            SELECT role_assignment_id
            FROM role_assignment
            WHERE membership_id = ?
            """,
            (replacement_membership_id,),
        ).fetchall()

        new_entitlement_rows = self.store.connection.execute(
            """
            SELECT entitlement_grant_id
            FROM entitlement_grant
            WHERE membership_id = ?
            """,
            (replacement_membership_id,),
        ).fetchall()

        self.assertEqual(len(old_role_rows), 1)
        self.assertEqual(len(old_entitlement_rows), 1)
        self.assertEqual(len(new_role_rows), 1)
        self.assertEqual(len(new_entitlement_rows), 1)

        self.assertNotEqual(
            old_role_rows[0]["role_assignment_id"],
            new_role_rows[0]["role_assignment_id"],
        )
        self.assertNotEqual(
            old_entitlement_rows[0]["entitlement_grant_id"],
            new_entitlement_rows[0]["entitlement_grant_id"],
        )

    def test_leave_membership_revokes_org_session_but_preserves_account_session(self) -> None:
        (
            identity_id,
            account_id,
            verification_id,
            verification_token,
        ) = self.store.signup(
            "leave-isolation@example.com",
            "correct horse battery staple",
            "Leave Isolation",
        )

        self.store.verify_email(verification_token)

        account_session_id, account_bearer = self.store.login(
            "leave-isolation@example.com",
            "correct horse battery staple",
        )

        invitation_id, invitation_code = self.store.issue_invitation(
            self.organization_id,
            self.tenant_id,
            role_refs=(self.owner_role,),
            entitlement_refs=(self.adforge_entitlement,),
        )

        membership_id = self.store.redeem_invitation(
            invitation_code,
            identity_id,
        )

        (
            org_session_id,
            org_bearer,
        ) = self.store.derive_organization_session(
            account_bearer,
            account_session_id,
            self.organization_id,
        )

        self.store.authenticate(
            org_bearer,
            org_session_id,
        )

        self.store.leave_membership(membership_id)

        membership = self.store.connection.execute(
            """
            SELECT status
            FROM membership
            WHERE membership_id = ?
            """,
            (membership_id,),
        ).fetchone()

        org_session = self.store.connection.execute(
            """
            SELECT status, revoked_at
            FROM session
            WHERE session_id = ?
            """,
            (org_session_id,),
        ).fetchone()

        self.assertEqual(membership["status"], "left")
        self.assertEqual(org_session["status"], "revoked")
        self.assertIsNotNone(org_session["revoked_at"])

        with self.assertRaises(AuthorityError):
            self.store.authenticate(
                org_bearer,
                org_session_id,
            )

        authenticated_identity, authenticated_account = (
            self.store.authenticate_account_session(
                account_bearer,
                account_session_id,
            )
        )

        self.assertEqual(authenticated_identity, identity_id)
        self.assertEqual(authenticated_account, account_id)

    def test_suspend_membership_revokes_org_session_but_preserves_account_session(self) -> None:
        (
            identity_id,
            account_id,
            verification_id,
            verification_token,
        ) = self.store.signup(
            "suspend-isolation@example.com",
            "correct horse battery staple",
            "Suspend Isolation",
        )

        self.store.verify_email(verification_token)

        account_session_id, account_bearer = self.store.login(
            "suspend-isolation@example.com",
            "correct horse battery staple",
        )

        _, invitation_code = self.store.issue_invitation(
            self.organization_id,
            self.tenant_id,
            role_refs=(self.owner_role,),
            entitlement_refs=(self.adforge_entitlement,),
        )

        membership_id = self.store.redeem_invitation(
            invitation_code,
            identity_id,
        )

        (
            org_session_id,
            org_bearer,
        ) = self.store.derive_organization_session(
            account_bearer,
            account_session_id,
            self.organization_id,
        )

        self.store.suspend_membership(membership_id)

        membership = self.store.connection.execute(
            """
            SELECT status
            FROM membership
            WHERE membership_id = ?
            """,
            (membership_id,),
        ).fetchone()

        org_session = self.store.connection.execute(
            """
            SELECT status, revoked_at
            FROM session
            WHERE session_id = ?
            """,
            (org_session_id,),
        ).fetchone()

        self.assertEqual(membership["status"], "suspended")
        self.assertEqual(org_session["status"], "revoked")
        self.assertIsNotNone(org_session["revoked_at"])

        with self.assertRaises(AuthorityError):
            self.store.authenticate(
                org_bearer,
                org_session_id,
            )

        authenticated_identity, authenticated_account = (
            self.store.authenticate_account_session(
                account_bearer,
                account_session_id,
            )
        )

        self.assertEqual(authenticated_identity, identity_id)
        self.assertEqual(authenticated_account, account_id)

    def test_revoke_membership_revokes_org_session_and_rejects_old_authority(self) -> None:
        (
            identity_id,
            account_id,
            verification_id,
            verification_token,
        ) = self.store.signup(
            "revoke-isolation@example.com",
            "correct horse battery staple",
            "Revoke Isolation",
        )

        self.store.verify_email(verification_token)

        account_session_id, account_bearer = self.store.login(
            "revoke-isolation@example.com",
            "correct horse battery staple",
        )

        _, invitation_code = self.store.issue_invitation(
            self.organization_id,
            self.tenant_id,
            role_refs=(self.owner_role,),
            entitlement_refs=(self.adforge_entitlement,),
        )

        membership_id = self.store.redeem_invitation(
            invitation_code,
            identity_id,
        )

        (
            org_session_id,
            org_bearer,
        ) = self.store.derive_organization_session(
            account_bearer,
            account_session_id,
            self.organization_id,
        )

        self.store.revoke_membership(membership_id)

        membership = self.store.connection.execute(
            """
            SELECT status
            FROM membership
            WHERE membership_id = ?
            """,
            (membership_id,),
        ).fetchone()

        org_session = self.store.connection.execute(
            """
            SELECT status, revoked_at
            FROM session
            WHERE session_id = ?
            """,
            (org_session_id,),
        ).fetchone()

        self.assertEqual(membership["status"], "revoked")
        self.assertEqual(org_session["status"], "revoked")
        self.assertIsNotNone(org_session["revoked_at"])

        with self.assertRaises(AuthorityError):
            self.store.authenticate(
                org_bearer,
                org_session_id,
            )

        authenticated_identity, authenticated_account = (
            self.store.authenticate_account_session(
                account_bearer,
                account_session_id,
            )
        )

        self.assertEqual(authenticated_identity, identity_id)
        self.assertEqual(authenticated_account, account_id)

    def test_leaving_one_organization_preserves_other_organization_authority(self) -> None:
        (
            identity_id,
            account_id,
            verification_id,
            verification_token,
        ) = self.store.signup(
            "multi-org@example.com",
            "correct horse battery staple",
            "Multi Org",
        )

        self.store.verify_email(verification_token)

        account_session_id, account_bearer = self.store.login(
            "multi-org@example.com",
            "correct horse battery staple",
        )

        organization_b_id, tenant_b_id = self.store.create_organization(
            "Independent Tenant B"
        )

        invitation_a_id, invitation_a_code = (
            self.store.issue_invitation(
                self.organization_id,
                self.tenant_id,
                role_refs=(self.owner_role,),
                entitlement_refs=(self.adforge_entitlement,),
            )
        )

        invitation_b_id, invitation_b_code = (
            self.store.issue_invitation(
                organization_b_id,
                tenant_b_id,
                role_refs=(self.owner_role,),
                entitlement_refs=(self.adforge_entitlement,),
            )
        )

        membership_a_id = self.store.redeem_invitation(
            invitation_a_code,
            identity_id,
        )

        membership_b_id = self.store.redeem_invitation(
            invitation_b_code,
            identity_id,
        )

        self.assertNotEqual(
            membership_a_id,
            membership_b_id,
        )

        (
            session_a_id,
            bearer_a,
        ) = self.store.derive_organization_session(
            account_bearer,
            account_session_id,
            self.organization_id,
        )

        (
            session_b_id,
            bearer_b,
        ) = self.store.derive_organization_session(
            account_bearer,
            account_session_id,
            organization_b_id,
        )

        subject_a = self.store.authenticate(
            bearer_a,
            session_a_id,
        )

        subject_b = self.store.authenticate(
            bearer_b,
            session_b_id,
        )

        self.assertEqual(
            subject_a.organization_id,
            self.organization_id,
        )
        self.assertEqual(
            subject_b.organization_id,
            organization_b_id,
        )

        self.store.leave_membership(membership_a_id)

        with self.assertRaises(AuthorityError):
            self.store.authenticate(
                bearer_a,
                session_a_id,
            )

        surviving_subject_b = self.store.authenticate(
            bearer_b,
            session_b_id,
        )

        self.assertEqual(
            surviving_subject_b.organization_id,
            organization_b_id,
        )

        authenticated_identity, authenticated_account = (
            self.store.authenticate_account_session(
                account_bearer,
                account_session_id,
            )
        )

        self.assertEqual(authenticated_identity, identity_id)
        self.assertEqual(authenticated_account, account_id)

        membership_rows = self.store.connection.execute(
            """
            SELECT membership_id, organization_id, status
            FROM membership
            WHERE identity_id = ?
              AND membership_id IN (?, ?)
            """,
            (
                identity_id,
                membership_a_id,
                membership_b_id,
            ),
        ).fetchall()

        status_by_id = {
            row["membership_id"]: (
                row["organization_id"],
                row["status"],
            )
            for row in membership_rows
        }

        self.assertEqual(
            status_by_id[membership_a_id],
            (
                self.organization_id,
                "left",
            ),
        )

        self.assertEqual(
            status_by_id[membership_b_id],
            (
                organization_b_id,
                "active",
            ),
        )

    def test_revoked_membership_can_rejoin_but_old_org_session_stays_dead(self) -> None:
        (
            identity_id,
            account_id,
            verification_id,
            verification_token,
        ) = self.store.signup(
            "revoked-rejoin@example.com",
            "correct horse battery staple",
            "Revoked Rejoin",
        )

        self.store.verify_email(verification_token)

        account_session_id, account_bearer = self.store.login(
            "revoked-rejoin@example.com",
            "correct horse battery staple",
        )

        _, first_invitation_code = self.store.issue_invitation(
            self.organization_id,
            self.tenant_id,
            role_refs=(self.owner_role,),
            entitlement_refs=(self.adforge_entitlement,),
        )

        old_membership_id = self.store.redeem_invitation(
            first_invitation_code,
            identity_id,
        )

        (
            old_session_id,
            old_bearer,
        ) = self.store.derive_organization_session(
            account_bearer,
            account_session_id,
            self.organization_id,
        )

        self.store.revoke_membership(old_membership_id)

        _, fresh_invitation_code = self.store.issue_invitation(
            self.organization_id,
            self.tenant_id,
            role_refs=(self.owner_role,),
            entitlement_refs=(self.adforge_entitlement,),
        )

        new_membership_id = self.store.redeem_invitation(
            fresh_invitation_code,
            identity_id,
        )

        self.assertNotEqual(
            old_membership_id,
            new_membership_id,
        )

        with self.assertRaises(AuthorityError):
            self.store.authenticate(
                old_bearer,
                old_session_id,
            )

        (
            new_session_id,
            new_bearer,
        ) = self.store.derive_organization_session(
            account_bearer,
            account_session_id,
            self.organization_id,
        )

        new_subject = self.store.authenticate(
            new_bearer,
            new_session_id,
        )

        self.assertEqual(
            new_subject.organization_id,
            self.organization_id,
        )

        old_membership = self.store.connection.execute(
            """
            SELECT status
            FROM membership
            WHERE membership_id = ?
            """,
            (old_membership_id,),
        ).fetchone()

        new_membership = self.store.connection.execute(
            """
            SELECT status
            FROM membership
            WHERE membership_id = ?
            """,
            (new_membership_id,),
        ).fetchone()

        self.assertEqual(
            old_membership["status"],
            "revoked",
        )
        self.assertEqual(
            new_membership["status"],
            "active",
        )

    def test_consumer_handoff_schema_binds_authority_and_hashes_token(self) -> None:
        table = self.store.connection.execute(
            """
            SELECT sql
            FROM sqlite_master
            WHERE type = 'table'
              AND name = 'consumer_handoff'
            """
        ).fetchone()

        self.assertIsNotNone(table)

        schema_sql = str(table["sql"] or "")

        self.assertIn("token_sha256 TEXT NOT NULL UNIQUE", schema_sql)
        self.assertNotIn("token TEXT", schema_sql)
        self.assertIn(
            "CHECK(authorization_version >= 1)",
            schema_sql,
        )
        self.assertIn(
            "CHECK(entitlement_version >= 1)",
            schema_sql,
        )

        foreign_keys = self.store.connection.execute(
            "PRAGMA foreign_key_list(consumer_handoff)"
        ).fetchall()

        targets = {
            row["from"]: row["table"]
            for row in foreign_keys
        }

        self.assertEqual(
            targets["identity_id"],
            "identity",
        )
        self.assertEqual(
            targets["account_id"],
            "personal_account",
        )
        self.assertEqual(
            targets["membership_id"],
            "membership",
        )
        self.assertEqual(
            targets["organization_id"],
            "organization",
        )
        self.assertEqual(
            targets["tenant_id"],
            "tenant",
        )

        index = self.store.connection.execute(
            """
            SELECT sql
            FROM sqlite_master
            WHERE type = 'index'
              AND name = 'consumer_handoff_membership_status_idx'
            """
        ).fetchone()

        self.assertIsNotNone(index)

        foreign_key_failures = self.store.connection.execute(
            "PRAGMA foreign_key_check"
        ).fetchall()

        self.assertEqual(foreign_key_failures, [])

    def test_wrong_org_session_bearer_cannot_mint_consumer_handoff(self) -> None:
        before = self.store.connection.execute(
            """
            SELECT COUNT(*) AS count
            FROM consumer_handoff
            """
        ).fetchone()["count"]

        with self.assertRaisesRegex(
            AuthorityError,
            "unauthorized",
        ):
            self.store.issue_consumer_handoff(
                "wrong-org-session-bearer",
                self.session_id,
                "adforge",
            )

        after = self.store.connection.execute(
            """
            SELECT COUNT(*) AS count
            FROM consumer_handoff
            """
        ).fetchone()["count"]

        self.assertEqual(after, before)

    def test_org_session_bearer_cannot_mint_handoff_for_another_session_id(self) -> None:
        (
            identity_id,
            account_id,
            verification_id,
            verification_token,
        ) = self.store.signup(
            "handoff-session-mismatch@example.com",
            "correct horse battery staple",
            "Handoff Session Mismatch",
        )

        self.store.verify_email(verification_token)

        _, invitation_code = self.store.issue_invitation(
            self.organization_id,
            self.tenant_id,
            role_refs=(self.owner_role,),
            entitlement_refs=(self.adforge_entitlement,),
        )

        self.store.redeem_invitation(
            invitation_code,
            identity_id,
        )

        account_session_id, account_bearer = self.store.login(
            "handoff-session-mismatch@example.com",
            "correct horse battery staple",
        )

        other_session_id, other_bearer = (
            self.store.derive_organization_session(
                account_bearer,
                account_session_id,
                self.organization_id,
            )
        )

        before = self.store.connection.execute(
            """
            SELECT COUNT(*) AS count
            FROM consumer_handoff
            """
        ).fetchone()["count"]

        with self.assertRaisesRegex(
            AuthorityError,
            "session mismatch",
        ):
            self.store.issue_consumer_handoff(
                self.session_bearer,
                other_session_id,
                "adforge",
            )

        after = self.store.connection.execute(
            """
            SELECT COUNT(*) AS count
            FROM consumer_handoff
            """
        ).fetchone()["count"]

        self.assertEqual(after, before)

        subject = self.store.authenticate(
            other_bearer,
            other_session_id,
        )

        self.assertEqual(
            subject.identity_id,
            identity_id,
        )
        self.assertEqual(
            subject.account_id,
            account_id,
        )

    def test_consumer_handoff_records_source_organization_session(self) -> None:
        handoff_id, token = self.store.issue_consumer_handoff(
            self.session_bearer,
            self.session_id,
            "adforge",
        )

        row = self.store.connection.execute(
            """
            SELECT
                source_session_id,
                membership_id,
                organization_id,
                tenant_id
            FROM consumer_handoff
            WHERE handoff_id = ?
            """,
            (handoff_id,),
        ).fetchone()

        self.assertIsNotNone(row)
        self.assertEqual(
            row["source_session_id"],
            self.session_id,
        )
        self.assertEqual(
            row["membership_id"],
            self.membership_id,
        )
        self.assertEqual(
            row["organization_id"],
            self.organization_id,
        )
        self.assertEqual(
            row["tenant_id"],
            self.tenant_id,
        )

        foreign_keys = self.store.connection.execute(
            "PRAGMA foreign_key_list(consumer_handoff)"
        ).fetchall()

        source_session_foreign_keys = [
            foreign_key
            for foreign_key in foreign_keys
            if foreign_key["from"] == "source_session_id"
        ]

        self.assertEqual(
            len(source_session_foreign_keys),
            1,
        )
        self.assertEqual(
            source_session_foreign_keys[0]["table"],
            "session",
        )
        self.assertEqual(
            source_session_foreign_keys[0]["to"],
            "session_id",
        )

    def test_legacy_unproven_active_handoff_is_revoked_during_revision_9_migration(self) -> None:
        database_path = Path(self.temp.name) / "anar-core.sqlite3"

        handoff_id, token = self.store.issue_consumer_handoff(
            self.session_bearer,
            self.session_id,
            "adforge",
        )

        self.store.connection.execute(
            """
            UPDATE schema_metadata
            SET metadata_value = '8'
            WHERE metadata_key = 'schema_revision'
            """
        )
        self.store.connection.commit()
        self.store.close()

        import sqlite3

        legacy = sqlite3.connect(database_path)
        legacy.row_factory = sqlite3.Row
        legacy.execute("PRAGMA foreign_keys = OFF")

        legacy.execute(
            """
            CREATE TABLE consumer_handoff_legacy_revision_8 (
                handoff_id TEXT PRIMARY KEY,
                token_sha256 TEXT NOT NULL UNIQUE,
                consumer TEXT NOT NULL,
                identity_id TEXT NOT NULL,
                account_id TEXT NOT NULL,
                membership_id TEXT NOT NULL,
                organization_id TEXT NOT NULL,
                tenant_id TEXT NOT NULL,
                authorization_version INTEGER NOT NULL,
                entitlement_version INTEGER NOT NULL,
                expires_at REAL NOT NULL,
                consumed_at REAL,
                revoked_at REAL,
                status TEXT NOT NULL,
                created_at REAL NOT NULL
            )
            """
        )

        legacy.execute(
            """
            INSERT INTO consumer_handoff_legacy_revision_8(
                handoff_id,
                token_sha256,
                consumer,
                identity_id,
                account_id,
                membership_id,
                organization_id,
                tenant_id,
                authorization_version,
                entitlement_version,
                expires_at,
                consumed_at,
                revoked_at,
                status,
                created_at
            )
            SELECT
                handoff_id,
                token_sha256,
                consumer,
                identity_id,
                account_id,
                membership_id,
                organization_id,
                tenant_id,
                authorization_version,
                entitlement_version,
                expires_at,
                consumed_at,
                revoked_at,
                status,
                created_at
            FROM consumer_handoff
            """
        )

        legacy.execute(
            "DROP TABLE consumer_handoff"
        )
        legacy.execute(
            """
            ALTER TABLE consumer_handoff_legacy_revision_8
            RENAME TO consumer_handoff
            """
        )
        legacy.commit()
        legacy.close()

        self.store = AnarCoreStore(database_path)

        columns = {
            row["name"]
            for row in self.store.connection.execute(
                "PRAGMA table_info(consumer_handoff)"
            ).fetchall()
        }

        self.assertIn(
            "source_session_id",
            columns,
        )

        row = self.store.connection.execute(
            """
            SELECT
                source_session_id,
                status,
                revoked_at,
                consumed_at
            FROM consumer_handoff
            WHERE handoff_id = ?
            """,
            (handoff_id,),
        ).fetchone()

        self.assertIsNotNone(row)
        self.assertIsNone(
            row["source_session_id"],
        )
        self.assertEqual(
            row["status"],
            "revoked",
        )
        self.assertIsNotNone(
            row["revoked_at"],
        )
        self.assertIsNone(
            row["consumed_at"],
        )

        metadata_rows = self.store.connection.execute(
            """
            SELECT metadata_key, metadata_value
            FROM schema_metadata
            """
        ).fetchall()

        metadata = {
            metadata_row["metadata_key"]:
                metadata_row["metadata_value"]
            for metadata_row in metadata_rows
        }

        self.assertEqual(
            metadata["schema_revision"],
            "9",
        )

    def test_account_signout_revokes_pending_consumer_handoff(self) -> None:
        handoff_id, token = self.store.issue_consumer_handoff(
            self.session_bearer,
            self.session_id,
            "adforge",
        )

        self.store.signout(
            self.account_session_bearer,
            self.account_session_id,
        )

        session = self.store.connection.execute(
            """
            SELECT status, revoked_at
            FROM session
            WHERE session_id = ?
            """,
            (self.session_id,),
        ).fetchone()

        handoff = self.store.connection.execute(
            """
            SELECT status, revoked_at, consumed_at
            FROM consumer_handoff
            WHERE handoff_id = ?
            """,
            (handoff_id,),
        ).fetchone()

        self.assertEqual(
            session["status"],
            "revoked",
        )
        self.assertIsNotNone(
            session["revoked_at"],
        )

        self.assertEqual(
            handoff["status"],
            "revoked",
        )
        self.assertIsNotNone(
            handoff["revoked_at"],
        )
        self.assertIsNone(
            handoff["consumed_at"],
        )

        with self.assertRaises(AuthorityError):
            self.store.consume_consumer_handoff(
                token,
                "adforge",
            )

    def test_inactive_source_session_rejects_handoff_even_without_eager_cascade(self) -> None:
        handoff_id, token = self.store.issue_consumer_handoff(
            self.session_bearer,
            self.session_id,
            "adforge",
        )

        self.store.connection.execute(
            """
            UPDATE session
            SET status = 'revoked',
                revoked_at = 1
            WHERE session_id = ?
            """,
            (self.session_id,),
        )
        self.store.connection.commit()

        handoff_before = self.store.connection.execute(
            """
            SELECT status, consumed_at, revoked_at
            FROM consumer_handoff
            WHERE handoff_id = ?
            """,
            (handoff_id,),
        ).fetchone()

        self.assertEqual(
            handoff_before["status"],
            "active",
        )
        self.assertIsNone(
            handoff_before["consumed_at"],
        )
        self.assertIsNone(
            handoff_before["revoked_at"],
        )

        with self.assertRaisesRegex(
            AuthorityError,
            "handoff source session inactive",
        ):
            self.store.consume_consumer_handoff(
                token,
                "adforge",
            )

        handoff_after = self.store.connection.execute(
            """
            SELECT status, consumed_at, revoked_at
            FROM consumer_handoff
            WHERE handoff_id = ?
            """,
            (handoff_id,),
        ).fetchone()

        self.assertEqual(
            handoff_after["status"],
            "active",
        )
        self.assertIsNone(
            handoff_after["consumed_at"],
        )
        self.assertIsNone(
            handoff_after["revoked_at"],
        )

    def test_consumer_handoff_token_is_digest_only_and_adforge_bound(self) -> None:
        handoff_id, token = self.store.issue_consumer_handoff(
            self.session_bearer,
            self.session_id,
            "adforge",
        )

        row = self.store.connection.execute(
            """
            SELECT
                handoff_id,
                token_sha256,
                consumer,
                membership_id,
                organization_id,
                tenant_id,
                status
            FROM consumer_handoff
            WHERE handoff_id = ?
            """,
            (handoff_id,),
        ).fetchone()

        self.assertIsNotNone(row)
        self.assertEqual(row["handoff_id"], handoff_id)
        self.assertEqual(row["consumer"], "adforge")
        self.assertEqual(row["membership_id"], self.membership_id)
        self.assertEqual(row["organization_id"], self.organization_id)
        self.assertEqual(row["tenant_id"], self.tenant_id)
        self.assertEqual(row["status"], "active")
        self.assertNotEqual(row["token_sha256"], token)
        self.assertEqual(
            row["token_sha256"],
            hashlib.sha256(token.encode("utf-8")).hexdigest(),
        )

    def test_consumer_handoff_rejects_non_adforge_issuance(self) -> None:
        before = self.store.connection.execute(
            """
            SELECT COUNT(*) AS count
            FROM consumer_handoff
            """
        ).fetchone()["count"]

        with self.assertRaisesRegex(
            AuthorityError,
            "unsupported handoff consumer",
        ):
            self.store.issue_consumer_handoff(
                self.session_bearer,
                self.session_id,
                "other-consumer",
            )

        after = self.store.connection.execute(
            """
            SELECT COUNT(*) AS count
            FROM consumer_handoff
            """
        ).fetchone()["count"]

        self.assertEqual(after, before)

    def test_consumer_handoff_consumes_once_and_returns_hydration(self) -> None:
        hydration_id = self.store.add_hydration_reference(
            self.organization_id,
            "brand.config",
            "vault://tenant/adforge/brand-config",
            "v1",
        )

        handoff_id, token = self.store.issue_consumer_handoff(
            self.session_bearer,
            self.session_id,
            "adforge",
        )

        projection = self.store.consume_consumer_handoff(
            token,
            "adforge",
        )

        self.assertEqual(projection.handoff_id, handoff_id)
        self.assertEqual(projection.consumer, "adforge")
        self.assertEqual(projection.identity_id, self.identity_id)
        self.assertEqual(projection.account_id, self.account_id)
        self.assertEqual(projection.membership_id, self.membership_id)
        self.assertEqual(
            projection.organization_id,
            self.organization_id,
        )
        self.assertEqual(projection.tenant_id, self.tenant_id)

        self.assertEqual(
            projection.hydration.organization_id,
            self.organization_id,
        )
        self.assertEqual(
            projection.hydration.tenant_id,
            self.tenant_id,
        )
        self.assertEqual(len(projection.hydration.references), 1)
        self.assertEqual(
            projection.hydration.references[0].reference_id,
            hydration_id,
        )
        self.assertEqual(
            projection.hydration.references[0].target_ref,
            "vault://tenant/adforge/brand-config",
        )

        consumed = self.store.connection.execute(
            """
            SELECT status, consumed_at
            FROM consumer_handoff
            WHERE handoff_id = ?
            """,
            (handoff_id,),
        ).fetchone()

        self.assertEqual(consumed["status"], "consumed")
        self.assertIsNotNone(consumed["consumed_at"])

        with self.assertRaises(AuthorityError):
            self.store.consume_consumer_handoff(
                token,
                "adforge",
            )

    def test_wrong_consumer_attempt_does_not_burn_handoff(self) -> None:
        handoff_id, token = self.store.issue_consumer_handoff(
            self.session_bearer,
            self.session_id,
            "adforge",
        )

        with self.assertRaisesRegex(
            AuthorityError,
            "unsupported handoff consumer",
        ):
            self.store.consume_consumer_handoff(
                token,
                "not-adforge",
            )

        row = self.store.connection.execute(
            """
            SELECT status, consumed_at, revoked_at
            FROM consumer_handoff
            WHERE handoff_id = ?
            """,
            (handoff_id,),
        ).fetchone()

        self.assertEqual(row["status"], "active")
        self.assertIsNone(row["consumed_at"])
        self.assertIsNone(row["revoked_at"])

        projection = self.store.consume_consumer_handoff(
            token,
            "adforge",
        )

        self.assertEqual(projection.handoff_id, handoff_id)

    def test_revoked_membership_revokes_pending_handoff(self) -> None:
        handoff_id, token = self.store.issue_consumer_handoff(
            self.session_bearer,
            self.session_id,
            "adforge",
        )

        self.store.revoke_membership(self.membership_id)

        with self.assertRaisesRegex(
            AuthorityError,
            "handoff unavailable",
        ):
            self.store.consume_consumer_handoff(
                token,
                "adforge",
            )

        row = self.store.connection.execute(
            """
            SELECT status, consumed_at, revoked_at
            FROM consumer_handoff
            WHERE handoff_id = ?
            """,
            (handoff_id,),
        ).fetchone()

        self.assertEqual(row["status"], "revoked")
        self.assertIsNone(row["consumed_at"])
        self.assertIsNotNone(row["revoked_at"])

    def test_authorization_version_drift_rejects_handoff_without_consuming_it(self) -> None:
        handoff_id, token = self.store.issue_consumer_handoff(
            self.session_bearer,
            self.session_id,
            "adforge",
        )

        self.store.connection.execute(
            """
            UPDATE membership
            SET authorization_version = authorization_version + 1
            WHERE membership_id = ?
            """,
            (self.membership_id,),
        )
        self.store.connection.commit()

        with self.assertRaisesRegex(
            AuthorityError,
            "handoff authorization version stale",
        ):
            self.store.consume_consumer_handoff(
                token,
                "adforge",
            )

        row = self.store.connection.execute(
            """
            SELECT status, consumed_at
            FROM consumer_handoff
            WHERE handoff_id = ?
            """,
            (handoff_id,),
        ).fetchone()

        self.assertEqual(row["status"], "active")
        self.assertIsNone(row["consumed_at"])

    def test_entitlement_version_drift_rejects_handoff_without_consuming_it(self) -> None:
        handoff_id, token = self.store.issue_consumer_handoff(
            self.session_bearer,
            self.session_id,
            "adforge",
        )

        self.store.connection.execute(
            """
            UPDATE membership
            SET entitlement_version = entitlement_version + 1
            WHERE membership_id = ?
            """,
            (self.membership_id,),
        )
        self.store.connection.commit()

        with self.assertRaisesRegex(
            AuthorityError,
            "handoff entitlement version stale",
        ):
            self.store.consume_consumer_handoff(
                token,
                "adforge",
            )

        row = self.store.connection.execute(
            """
            SELECT status, consumed_at
            FROM consumer_handoff
            WHERE handoff_id = ?
            """,
            (handoff_id,),
        ).fetchone()

        self.assertEqual(row["status"], "active")
        self.assertIsNone(row["consumed_at"])

    def test_revoked_consumer_handoff_cannot_be_consumed_or_revoked_twice(self) -> None:
        handoff_id, token = self.store.issue_consumer_handoff(
            self.session_bearer,
            self.session_id,
            "adforge",
        )

        self.store.revoke_consumer_handoff(handoff_id)

        row = self.store.connection.execute(
            """
            SELECT status, revoked_at, consumed_at
            FROM consumer_handoff
            WHERE handoff_id = ?
            """,
            (handoff_id,),
        ).fetchone()

        self.assertEqual(row["status"], "revoked")
        self.assertIsNotNone(row["revoked_at"])
        self.assertIsNone(row["consumed_at"])

        with self.assertRaises(AuthorityError):
            self.store.consume_consumer_handoff(
                token,
                "adforge",
            )

        with self.assertRaisesRegex(
            AuthorityError,
            "active handoff unavailable",
        ):
            self.store.revoke_consumer_handoff(handoff_id)

    def test_expired_consumer_handoff_rejects_without_consumption(self) -> None:
        handoff_id, token = self.store.issue_consumer_handoff(
            self.session_bearer,
            self.session_id,
            "adforge",
        )

        self.store.connection.execute(
            """
            UPDATE consumer_handoff
            SET expires_at = 1
            WHERE handoff_id = ?
            """,
            (handoff_id,),
        )
        self.store.connection.commit()

        with self.assertRaisesRegex(
            AuthorityError,
            "handoff expired",
        ):
            self.store.consume_consumer_handoff(
                token,
                "adforge",
            )

        row = self.store.connection.execute(
            """
            SELECT status, consumed_at
            FROM consumer_handoff
            WHERE handoff_id = ?
            """,
            (handoff_id,),
        ).fetchone()

        self.assertEqual(row["status"], "active")
        self.assertIsNone(row["consumed_at"])

    def test_suspended_membership_revokes_pending_handoff(self) -> None:
        handoff_id, token = self.store.issue_consumer_handoff(
            self.session_bearer,
            self.session_id,
            "adforge",
        )

        self.store.suspend_membership(self.membership_id)

        with self.assertRaisesRegex(
            AuthorityError,
            "handoff unavailable",
        ):
            self.store.consume_consumer_handoff(
                token,
                "adforge",
            )

        row = self.store.connection.execute(
            """
            SELECT status, consumed_at, revoked_at
            FROM consumer_handoff
            WHERE handoff_id = ?
            """,
            (handoff_id,),
        ).fetchone()

        self.assertEqual(row["status"], "revoked")
        self.assertIsNone(row["consumed_at"])
        self.assertIsNotNone(row["revoked_at"])

    def test_left_membership_revokes_pending_handoff(self) -> None:
        handoff_id, token = self.store.issue_consumer_handoff(
            self.session_bearer,
            self.session_id,
            "adforge",
        )

        self.store.leave_membership(self.membership_id)

        with self.assertRaisesRegex(
            AuthorityError,
            "handoff unavailable",
        ):
            self.store.consume_consumer_handoff(
                token,
                "adforge",
            )

        row = self.store.connection.execute(
            """
            SELECT status, consumed_at, revoked_at
            FROM consumer_handoff
            WHERE handoff_id = ?
            """,
            (handoff_id,),
        ).fetchone()

        self.assertEqual(row["status"], "revoked")
        self.assertIsNone(row["consumed_at"])
        self.assertIsNotNone(row["revoked_at"])

    def test_legacy_create_session_is_disabled_and_mints_nothing(self) -> None:
        before = self.store.connection.execute(
            """
            SELECT COUNT(*) AS count
            FROM session
            """
        ).fetchone()["count"]

        with self.assertRaisesRegex(
            AuthorityError,
            "legacy session creation disabled; authenticated account session required",
        ):
            self.store.create_session(
                self.identity_id,
                self.account_id,
                self.organization_id,
            )

        after = self.store.connection.execute(
            """
            SELECT COUNT(*) AS count
            FROM session
            """
        ).fetchone()["count"]

        self.assertEqual(after, before)

    def test_authenticated_account_session_derives_organization_session(self) -> None:
        (
            identity_id,
            account_id,
            verification_id,
            verification_token,
        ) = self.store.signup(
            "derive-org@example.com",
            "correct horse battery staple",
            "Derived Org Session",
        )

        self.store.verify_email(verification_token)

        _, invitation_code = self.store.issue_invitation(
            self.organization_id,
            self.tenant_id,
            role_refs=(self.owner_role,),
            entitlement_refs=(self.adforge_entitlement,),
        )

        membership_id = self.store.redeem_invitation(
            invitation_code,
            identity_id,
        )

        account_session_id, account_bearer = self.store.login(
            "derive-org@example.com",
            "correct horse battery staple",
        )

        org_session_id, org_bearer = (
            self.store.derive_organization_session(
                account_bearer,
                account_session_id,
                self.organization_id,
            )
        )

        subject = self.store.authenticate(
            org_bearer,
            org_session_id,
        )

        self.assertEqual(subject.identity_id, identity_id)
        self.assertEqual(subject.account_id, account_id)
        self.assertEqual(
            subject.organization_id,
            self.organization_id,
        )

        row = self.store.connection.execute(
            """
            SELECT
                account_session_id,
                membership_id,
                identity_id,
                account_id,
                organization_id,
                status
            FROM session
            WHERE session_id = ?
            """,
            (org_session_id,),
        ).fetchone()

        self.assertIsNotNone(row)
        self.assertEqual(
            row["account_session_id"],
            account_session_id,
        )
        self.assertEqual(
            row["membership_id"],
            membership_id,
        )
        self.assertEqual(row["identity_id"], identity_id)
        self.assertEqual(row["account_id"], account_id)
        self.assertEqual(
            row["organization_id"],
            self.organization_id,
        )
        self.assertEqual(row["status"], "active")

    def test_wrong_account_bearer_cannot_derive_organization_session(self) -> None:
        (
            identity_id,
            account_id,
            verification_id,
            verification_token,
        ) = self.store.signup(
            "derive-wrong-bearer@example.com",
            "correct horse battery staple",
            "Wrong Bearer",
        )

        self.store.verify_email(verification_token)

        _, invitation_code = self.store.issue_invitation(
            self.organization_id,
            self.tenant_id,
            role_refs=(self.owner_role,),
            entitlement_refs=(self.adforge_entitlement,),
        )

        self.store.redeem_invitation(
            invitation_code,
            identity_id,
        )

        account_session_id, account_bearer = self.store.login(
            "derive-wrong-bearer@example.com",
            "correct horse battery staple",
        )

        before = self.store.connection.execute(
            """
            SELECT COUNT(*) AS count
            FROM session
            WHERE account_session_id = ?
            """,
            (account_session_id,),
        ).fetchone()["count"]

        with self.assertRaisesRegex(
            AuthorityError,
            "unauthorized",
        ):
            self.store.derive_organization_session(
                "wrong-account-bearer",
                account_session_id,
                self.organization_id,
            )

        after = self.store.connection.execute(
            """
            SELECT COUNT(*) AS count
            FROM session
            WHERE account_session_id = ?
            """,
            (account_session_id,),
        ).fetchone()["count"]

        self.assertEqual(after, before)

    def test_account_signout_revokes_derived_organization_session(self) -> None:
        (
            identity_id,
            account_id,
            verification_id,
            verification_token,
        ) = self.store.signup(
            "derive-signout@example.com",
            "correct horse battery staple",
            "Derived Signout",
        )

        self.store.verify_email(verification_token)

        _, invitation_code = self.store.issue_invitation(
            self.organization_id,
            self.tenant_id,
            role_refs=(self.owner_role,),
            entitlement_refs=(self.adforge_entitlement,),
        )

        self.store.redeem_invitation(
            invitation_code,
            identity_id,
        )

        account_session_id, account_bearer = self.store.login(
            "derive-signout@example.com",
            "correct horse battery staple",
        )

        org_session_id, org_bearer = (
            self.store.derive_organization_session(
                account_bearer,
                account_session_id,
                self.organization_id,
            )
        )

        self.store.authenticate(
            org_bearer,
            org_session_id,
        )

        self.store.signout(
            account_bearer,
            account_session_id,
        )

        row = self.store.connection.execute(
            """
            SELECT status, revoked_at
            FROM session
            WHERE session_id = ?
            """,
            (org_session_id,),
        ).fetchone()

        self.assertEqual(row["status"], "revoked")
        self.assertIsNotNone(row["revoked_at"])

        with self.assertRaises(AuthorityError):
            self.store.authenticate(
                org_bearer,
                org_session_id,
            )

        with self.assertRaises(AuthorityError):
            self.store.authenticate_account_session(
                account_bearer,
                account_session_id,
            )

    def test_account_session_cannot_derive_unjoined_organization(self) -> None:
        (
            identity_id,
            account_id,
            verification_id,
            verification_token,
        ) = self.store.signup(
            "derive-unjoined@example.com",
            "correct horse battery staple",
            "Unjoined Org",
        )

        self.store.verify_email(verification_token)

        account_session_id, account_bearer = self.store.login(
            "derive-unjoined@example.com",
            "correct horse battery staple",
        )

        other_organization_id, other_tenant_id = (
            self.store.create_organization(
                "Unjoined Organization"
            )
        )

        with self.assertRaisesRegex(
            AuthorityError,
            "active membership required",
        ):
            self.store.derive_organization_session(
                account_bearer,
                account_session_id,
                other_organization_id,
            )

        row = self.store.connection.execute(
            """
            SELECT COUNT(*) AS count
            FROM session
            WHERE account_session_id = ?
              AND organization_id = ?
            """,
            (
                account_session_id,
                other_organization_id,
            ),
        ).fetchone()

        self.assertEqual(row["count"], 0)

    def test_account_session_for_one_identity_cannot_mint_other_identity_authority(self) -> None:
        (
            identity_a,
            account_a,
            verification_a_id,
            verification_a_token,
        ) = self.store.signup(
            "derive-account-a@example.com",
            "correct horse battery staple",
            "Account A",
        )

        (
            identity_b,
            account_b,
            verification_b_id,
            verification_b_token,
        ) = self.store.signup(
            "derive-account-b@example.com",
            "correct horse battery staple",
            "Account B",
        )

        self.store.verify_email(verification_a_token)
        self.store.verify_email(verification_b_token)

        _, invitation_code = self.store.issue_invitation(
            self.organization_id,
            self.tenant_id,
            role_refs=(self.owner_role,),
            entitlement_refs=(self.adforge_entitlement,),
        )

        membership_b = self.store.redeem_invitation(
            invitation_code,
            identity_b,
        )

        account_session_a, bearer_a = self.store.login(
            "derive-account-a@example.com",
            "correct horse battery staple",
        )

        with self.assertRaisesRegex(
            AuthorityError,
            "active membership required",
        ):
            self.store.derive_organization_session(
                bearer_a,
                account_session_a,
                self.organization_id,
            )

        count = self.store.connection.execute(
            """
            SELECT COUNT(*) AS count
            FROM session
            WHERE identity_id = ?
              AND account_id = ?
              AND membership_id = ?
            """,
            (
                identity_b,
                account_b,
                membership_b,
            ),
        ).fetchone()

        self.assertEqual(count["count"], 0)

    def test_hydration_contains_references_not_secrets(self) -> None:
        self.store.add_hydration_reference(
            self.organization_id,
            "brand-dna",
            "anarchi://brand/anarchi-technologies",
            "v3",
        )

        self.store.add_hydration_reference(
            self.organization_id,
            "product-dna",
            "anarchi://product/wsrs",
            "v2",
        )

        hydration = self.store.project_hydration(self.organization_id)

        self.assertEqual(hydration.organization_id, self.organization_id)
        self.assertEqual(hydration.tenant_id, self.tenant_id)
        self.assertEqual(len(hydration.references), 2)

    def test_hydration_rejects_obvious_secret_material(self) -> None:
        with self.assertRaises(AuthorityError):
            self.store.add_hydration_reference(
                self.organization_id,
                "integration",
                "provider://linkedin?token=do-not-store-this",
                "v1",
            )


if __name__ == "__main__":
    unittest.main()
