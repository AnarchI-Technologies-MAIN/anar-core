from __future__ import annotations

import concurrent.futures
import tempfile
import unittest
from pathlib import Path

from anar_core import AnarCoreStore, AuthorityError


class ThreadSafetyTests(unittest.TestCase):
    def setUp(self) -> None:
        self.directory = tempfile.TemporaryDirectory()
        self.path = Path(self.directory.name) / "core.sqlite3"
        self.store = AnarCoreStore(self.path)

    def tearDown(self) -> None:
        self.store.close()
        self.directory.cleanup()

    def test_store_can_be_used_from_worker_thread(self) -> None:
        with concurrent.futures.ThreadPoolExecutor(
            max_workers=1
        ) as executor:
            future = executor.submit(
                self.store.create_identity,
                "Threaded Identity",
                "human",
            )

            identity_id = future.result(timeout=5)

        self.assertTrue(
            identity_id.startswith("idn_")
        )

    def test_single_use_invitation_has_one_concurrent_winner(self) -> None:
        identity_a = self.store.create_identity(
            "Identity A",
            "human",
        )

        identity_b = self.store.create_identity(
            "Identity B",
            "human",
        )

        organization_id, tenant_id = self.store.create_organization(
            "thread-race-test"
        )

        role_ref = self.store.define_role(
            "operator",
            (),
            (),
            None,
            1,
        )

        entitlement_ref = self.store.define_entitlement(
            "thread-race-entitlement",
            None,
            1,
        )

        invitation = self.store.issue_invitation(
            organization_id,
            tenant_id,
            (role_ref,),
            (entitlement_ref,),
            300,
        )

        if isinstance(invitation, dict):
            code = invitation["code"]
        else:
            code = invitation[1]

        def redeem(identity_id: str) -> tuple[str, str]:
            try:
                membership_id = self.store.redeem_invitation(
                    code,
                    identity_id,
                )

                return (
                    "success",
                    membership_id,
                )
            except AuthorityError as exc:
                return (
                    "denied",
                    str(exc),
                )

        with concurrent.futures.ThreadPoolExecutor(
            max_workers=2
        ) as executor:
            futures = (
                executor.submit(
                    redeem,
                    identity_a,
                ),
                executor.submit(
                    redeem,
                    identity_b,
                ),
            )

            results = [
                future.result(timeout=5)
                for future in futures
            ]

        successes = [
            value
            for status, value in results
            if status == "success"
        ]

        denials = [
            value
            for status, value in results
            if status == "denied"
        ]

        self.assertEqual(
            len(successes),
            1,
        )

        self.assertEqual(
            len(denials),
            1,
        )


    def test_single_use_consumer_handoff_has_one_cross_store_winner(self) -> None:
        (
            identity_id,
            account_id,
            verification_id,
            verification_token,
        ) = self.store.signup(
            "handoff-race@example.com",
            "correct horse battery staple",
            "Handoff Race",
        )

        self.store.verify_email(
            verification_token,
        )

        account_session_id, account_bearer = self.store.login(
            "handoff-race@example.com",
            "correct horse battery staple",
        )

        organization_id, tenant_id = self.store.create_organization(
            "handoff-race-organization"
        )

        role_ref = self.store.define_role(
            "handoff-race-operator",
            (),
            (),
            None,
            1,
        )

        entitlement_ref = self.store.define_entitlement(
            "handoff-race-entitlement",
            None,
            1,
        )

        _, invitation_code = self.store.issue_invitation(
            organization_id,
            tenant_id,
            (role_ref,),
            (entitlement_ref,),
            300,
        )

        self.store.redeem_invitation(
            invitation_code,
            identity_id,
        )

        session_id, session_bearer = (
            self.store.derive_organization_session(
                account_bearer,
                account_session_id,
                organization_id,
            )
        )

        handoff_id, token = self.store.issue_consumer_handoff(
            session_bearer,
            session_id,
            "adforge",
        )

        self.store.connection.commit()

        def consume() -> tuple[str, str]:
            worker_store = AnarCoreStore(self.path)

            try:
                projection = worker_store.consume_consumer_handoff(
                    token,
                    "adforge",
                )

                return (
                    "success",
                    projection.handoff_id,
                )
            except AuthorityError as exc:
                return (
                    "denied",
                    str(exc),
                )
            finally:
                worker_store.close()

        with concurrent.futures.ThreadPoolExecutor(
            max_workers=2
        ) as executor:
            futures = (
                executor.submit(consume),
                executor.submit(consume),
            )

            results = [
                future.result(timeout=5)
                for future in futures
            ]

        successes = [
            value
            for status, value in results
            if status == "success"
        ]

        denials = [
            value
            for status, value in results
            if status == "denied"
        ]

        self.assertEqual(
            successes,
            [handoff_id],
        )

        self.assertEqual(
            len(denials),
            1,
        )

        row = self.store.connection.execute(
            """
            SELECT
                status,
                consumed_at,
                revoked_at
            FROM consumer_handoff
            WHERE handoff_id = ?
            """,
            (handoff_id,),
        ).fetchone()

        self.assertEqual(
            row["status"],
            "consumed",
        )
        self.assertIsNotNone(
            row["consumed_at"],
        )
        self.assertIsNone(
            row["revoked_at"],
        )

    def test_single_use_email_verification_has_one_cross_store_winner(self) -> None:
        _identity_id, account_id, _challenge_id, token = self.store.signup(
            "verification-race@example.com",
            "correct horse battery staple",
            "Verification Race",
        )
        self.store.connection.commit()

        def verify() -> tuple[str, str]:
            worker_store = AnarCoreStore(self.path)
            try:
                return ("success", worker_store.verify_email(token))
            except AuthorityError as exc:
                return ("denied", str(exc))
            finally:
                worker_store.close()

        with concurrent.futures.ThreadPoolExecutor(max_workers=2) as executor:
            results = [
                future.result(timeout=5)
                for future in (
                    executor.submit(verify),
                    executor.submit(verify),
                )
            ]

        self.assertEqual(
            [value for status, value in results if status == "success"],
            [account_id],
        )
        self.assertEqual(
            len([value for status, value in results if status == "denied"]),
            1,
        )

    def test_single_use_password_reset_has_one_cross_store_winner(self) -> None:
        _identity_id, account_id, _challenge_id, verification_token = (
            self.store.signup(
                "password-race@example.com",
                "correct horse battery staple",
                "Password Race",
            )
        )
        self.store.verify_email(verification_token)
        _reset_id, reset_token = self.store.issue_password_reset(
            "password-race@example.com"
        )
        self.store.connection.commit()

        def consume(password: str) -> tuple[str, str]:
            worker_store = AnarCoreStore(self.path)
            try:
                return (
                    "success",
                    worker_store.consume_password_reset(
                        reset_token,
                        password,
                        password,
                    ),
                )
            except AuthorityError as exc:
                return ("denied", str(exc))
            finally:
                worker_store.close()

        with concurrent.futures.ThreadPoolExecutor(max_workers=2) as executor:
            results = [
                future.result(timeout=10)
                for future in (
                    executor.submit(
                        consume,
                        "new correct horse battery staple one",
                    ),
                    executor.submit(
                        consume,
                        "new correct horse battery staple two",
                    ),
                )
            ]

        self.assertEqual(
            [value for status, value in results if status == "success"],
            [account_id],
        )
        self.assertEqual(
            len([value for status, value in results if status == "denied"]),
            1,
        )

if __name__ == "__main__":
    unittest.main()
