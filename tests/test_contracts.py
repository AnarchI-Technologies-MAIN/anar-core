from __future__ import annotations

import unittest
from dataclasses import replace

from anar_core_contracts import (
    AdapterGrantBinding,
    BoundaryMismatch,
    ConsumerHandoffProjection,
    HydrationProjection,
    HydrationReference,
    MembershipProjection,
    VersionedDefinitionRef,
    assert_boundary_agreement,
    canonical_json,
    normalize_symbol,
)


class ContractTests(unittest.TestCase):
    def binding(self) -> AdapterGrantBinding:
        return AdapterGrantBinding(
            binding_id="bnd_00000000000000000000000000000001",
            identity_id="idn_00000000000000000000000000000001",
            account_id="act_00000000000000000000000000000001",
            organization_id="org_00000000000000000000000000000001",
            tenant_id="tnt_00000000000000000000000000000001",
            session_id="ses_00000000000000000000000000000001",
            adapter_definition_id="adp_00000000000000000000000000000001",
            operation_definition_id="opn_00000000000000000000000000000001",
            entitlement_definition_id="ent_00000000000000000000000000000001",
            entitlement_definition_version=2,
            resource_scope_json=canonical_json({"account": "publisher-1"}),
            authorization_version=4,
            entitlement_version=3,
            policy_definition_id="pol_72993b6cb83904d39a8c73bd0651aa62",
            policy_definition_version=1,
            policy_version="policy-v1",
            status="active",
        )

    def hydration(self) -> HydrationProjection:
        return HydrationProjection(
            organization_id="org_00000000000000000000000000000001",
            tenant_id="tnt_00000000000000000000000000000001",
            configuration_version=7,
            references=(
                HydrationReference(
                    reference_id="hyd_00000000000000000000000000000001",
                    kind="brand.config",
                    target_ref="vault://tenant/adforge/brand-config",
                    version="v1",
                ),
            ),
        )

    def handoff_projection(self) -> ConsumerHandoffProjection:
        return ConsumerHandoffProjection(
            handoff_id="hnd_00000000000000000000000000000001",
            consumer="adforge",
            identity_id="idn_00000000000000000000000000000001",
            account_id="act_00000000000000000000000000000001",
            membership_id="mbr_00000000000000000000000000000001",
            organization_id="org_00000000000000000000000000000001",
            tenant_id="tnt_00000000000000000000000000000001",
            authorization_version=4,
            entitlement_version=3,
            hydration=self.hydration(),
        )

    def test_symbol_normalization_is_deterministic(self) -> None:
        self.assertEqual(normalize_symbol("  MEMBER.READ  "), "member.read")

    def test_canonical_json_rejects_non_finite_numbers(self) -> None:
        with self.assertRaises(ValueError):
            canonical_json({"risk": float("nan")})

    def test_definition_version_rejects_non_positive_and_non_integer(self) -> None:
        definition_id = "rol_00000000000000000000000000000001"

        for version in (0, -1, True, 1.5):
            with self.subTest(version=version):
                with self.assertRaises(ValueError):
                    VersionedDefinitionRef(definition_id, version)

    def test_binding_requires_canonical_resource_json(self) -> None:
        with self.assertRaises(ValueError):
            replace(
                self.binding(),
                resource_scope_json='{ "account": "publisher-1" }',
            )

    def test_binding_versions_require_strict_integers(self) -> None:
        for field in (
            "entitlement_definition_version",
            "authorization_version",
            "entitlement_version",
            "policy_definition_version",
        ):
            for value in (True, 1.5):
                with self.subTest(field=field, value=value):
                    with self.assertRaises(ValueError):
                        replace(self.binding(), **{field: value})

    def test_exact_shared_boundary_agrees(self) -> None:
        value = self.binding()
        assert_boundary_agreement(value, value)

    def test_boundary_digest_is_stable_and_sensitive(self) -> None:
        first = self.binding()
        second = self.binding()

        self.assertEqual(first.agreement_digest(), second.agreement_digest())
        self.assertNotEqual(
            first.agreement_digest(),
            replace(first, entitlement_definition_version=3).agreement_digest(),
        )

    def test_shared_boundary_mismatch_fails_closed(self) -> None:
        core = self.binding()

        for changed in (
            replace(core, authorization_version=5),
            replace(
                core,
                policy_definition_id="pol_00000000000000000000000000000002",
            ),
            replace(core, policy_definition_version=2),
        ):
            with self.subTest(changed=changed):
                with self.assertRaises(BoundaryMismatch):
                    assert_boundary_agreement(core, changed)

    def test_policy_label_is_not_authority_fact(self) -> None:
        binding = self.binding()
        relabelled = replace(binding, policy_version="diagnostic-label")

        self.assertEqual(binding.agreement_digest(), relabelled.agreement_digest())
        assert_boundary_agreement(binding, relabelled)

    def test_projection_versions_require_strict_integers(self) -> None:
        membership = MembershipProjection(
            membership_id="mbr_00000000000000000000000000000001",
            identity_id="idn_00000000000000000000000000000001",
            organization_id="org_00000000000000000000000000000001",
            tenant_id="tnt_00000000000000000000000000000001",
            status="active",
            authorization_version=1,
            entitlement_version=1,
        )

        for field in ("authorization_version", "entitlement_version"):
            for value in (True, 1.5):
                with self.subTest(
                    projection="membership",
                    field=field,
                    value=value,
                ):
                    with self.assertRaises(ValueError):
                        replace(membership, **{field: value})

        for value in (True, 1.5):
            with self.subTest(projection="hydration", value=value):
                with self.assertRaises(ValueError):
                    replace(self.hydration(), configuration_version=value)

        for field in ("authorization_version", "entitlement_version"):
            for value in (True, 1.5):
                with self.subTest(
                    projection="handoff",
                    field=field,
                    value=value,
                ):
                    with self.assertRaises(ValueError):
                        replace(self.handoff_projection(), **{field: value})

    def test_consumer_handoff_projection_requires_aligned_hydration(self) -> None:
        projection = self.handoff_projection()

        with self.assertRaises(ValueError):
            replace(
                projection,
                hydration=replace(
                    projection.hydration,
                    organization_id="org_00000000000000000000000000000002",
                ),
            )

        with self.assertRaises(ValueError):
            replace(
                projection,
                hydration=replace(
                    projection.hydration,
                    tenant_id="tnt_00000000000000000000000000000002",
                ),
            )


if __name__ == "__main__":
    unittest.main()
