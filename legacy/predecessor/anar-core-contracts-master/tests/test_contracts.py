from __future__ import annotations

import unittest
from dataclasses import replace

from anar_core_contracts import (
    AdapterGrantBinding,
    BoundaryMismatch,
    ConsumerHandoffProjection,
    HydrationProjection,
    HydrationReference,
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
            policy_definition_id=(
                "pol_72993b6cb83904d39a8c73bd0651aa62"
            ),
            policy_definition_version=1,
            policy_version="policy-v1",
            status="active",
        )

    def test_symbol_normalization_is_deterministic(self) -> None:
        self.assertEqual(normalize_symbol("  MEMBER.READ  "), "member.read")

    def test_definition_version_cannot_be_zero(self) -> None:
        with self.assertRaises(ValueError):
            VersionedDefinitionRef(
                "rol_00000000000000000000000000000001",
                0,
            )

    def test_exact_shared_boundary_agrees(self) -> None:
        value = self.binding()
        assert_boundary_agreement(value, value)

    def test_boundary_digest_is_stable_and_sensitive(self) -> None:
        first = self.binding()
        second = self.binding()

        self.assertEqual(
            first.agreement_digest(),
            second.agreement_digest(),
        )

        changed = replace(
            first,
            entitlement_definition_version=3,
        )

        self.assertNotEqual(
            first.agreement_digest(),
            changed.agreement_digest(),
        )
    def test_shared_boundary_mismatch_fails_closed(self) -> None:
        core = self.binding()
        broker = replace(core, authorization_version=5)

        with self.assertRaises(BoundaryMismatch):
            assert_boundary_agreement(core, broker)


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

    def test_consumer_handoff_projection_accepts_aligned_hydration(self) -> None:
        projection = self.handoff_projection()

        self.assertEqual(
            projection.consumer,
            "adforge",
        )
        self.assertEqual(
            projection.hydration.organization_id,
            projection.organization_id,
        )
        self.assertEqual(
            projection.hydration.tenant_id,
            projection.tenant_id,
        )

    def test_consumer_handoff_projection_rejects_hydration_organization_mismatch(self) -> None:
        hydration = replace(
            self.hydration(),
            organization_id="org_00000000000000000000000000000002",
        )

        with self.assertRaises(ValueError):
            replace(
                self.handoff_projection(),
                hydration=hydration,
            )

    def test_consumer_handoff_projection_rejects_hydration_tenant_mismatch(self) -> None:
        hydration = replace(
            self.hydration(),
            tenant_id="tnt_00000000000000000000000000000002",
        )

        with self.assertRaises(ValueError):
            replace(
                self.handoff_projection(),
                hydration=hydration,
            )

    def test_consumer_handoff_projection_rejects_invalid_ids_and_versions(self) -> None:
        projection = self.handoff_projection()

        with self.assertRaises(ValueError):
            replace(
                projection,
                handoff_id="ses_00000000000000000000000000000001",
            )

        with self.assertRaises(ValueError):
            replace(
                projection,
                authorization_version=0,
            )

        with self.assertRaises(ValueError):
            replace(
                projection,
                entitlement_version=0,
            )

    def test_policy_label_is_not_authority_fact(self) -> None:
        binding = self.binding()
        relabelled = replace(
            binding,
            policy_version="diagnostic-label",
        )

        self.assertEqual(
            binding.agreement_digest(),
            relabelled.agreement_digest(),
        )

        assert_boundary_agreement(
            binding,
            relabelled,
        )


if __name__ == "__main__":
    unittest.main()
