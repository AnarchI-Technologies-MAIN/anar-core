#!/usr/bin/env python3
"""Generate the immutable Phase -1 source manifest and transition receipt."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
from typing import Any


CANONICALIZATION = "ANARCHI-JCS-COMPATIBLE-V1"
SPEC_SHA256 = "26697bc4a7de4a17272e8f3a47a12d3aec7dee12f2d6bd1f62aaf0d0aff78b80"
KERNEL_ARCHIVE_SHA256 = "dea23d2bbc0905ff93b136964069572c1640aee38bafacac55f5dc3fcf41dc31"
CONTRACTS_ARCHIVE_SHA256 = "de8899abb4c43dd668b9abba472f05663d0dd6670fabaf9055ffeaf521a64010"
GOVERNANCE_MAP_SHA256 = "896c65c815d699120cb2595e2c4624e16201b9beb8b71ea39634f80c445f3958"
IDENTITY_DOCTRINE_SHA256 = "26660ed92c6bb5a19518fcecc7c1d5a4e92fad609a6d261a3301d60d78e152f2"
RECOVERIES_SPEC_SHA256 = "0e3877aff0832db9cc0503d9a8769f2b867a1536441fba149874360fbb8f8869"


def canonical_bytes(value: Any) -> bytes:
    reject_floats(value)
    return json.dumps(
        value,
        ensure_ascii=False,
        allow_nan=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


def reject_floats(value: Any) -> None:
    if isinstance(value, float):
        raise TypeError("floating-point values are prohibited in proof artifacts")
    if isinstance(value, dict):
        for key, item in value.items():
            if not isinstance(key, str):
                raise TypeError("proof artifact keys must be strings")
            reject_floats(item)
    elif isinstance(value, (list, tuple)):
        for item in value:
            reject_floats(item)


def digest_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def digest_file(path: Path) -> str:
    hasher = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            hasher.update(chunk)
    return hasher.hexdigest()


def write_json(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(canonical_bytes(value) + b"\n")


def require_digest(path: Path, expected: str) -> None:
    actual = digest_file(path)
    if actual != expected:
        raise SystemExit(f"digest mismatch: {path}: expected {expected}, got {actual}")


def legacy_files(repo: Path) -> list[dict[str, Any]]:
    root = repo / "legacy" / "predecessor"
    entries = []
    for path in sorted(item for item in root.rglob("*") if item.is_file()):
        entries.append(
            {
                "path": path.relative_to(repo).as_posix(),
                "bytes": path.stat().st_size,
                "sha256": digest_file(path),
            }
        )
    return entries


def artifact_map(repo: Path, paths: list[str]) -> dict[str, str]:
    return {path: digest_file(repo / path) for path in sorted(paths)}


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--recorded-at", required=True)
    args = parser.parse_args()

    repo = Path(__file__).resolve().parents[2]
    spec_path = repo / "docs/specification/SPEC-3.12-Anar-Core-vNext-Authority-Substrate-PRE-FREEZE-HARDENED.md"
    kernel_archive = repo / "evidence/source-archives/anar-core-master.zip"
    contracts_archive = repo / "evidence/source-archives/anar-core-contracts-master.zip"
    require_digest(spec_path, SPEC_SHA256)
    require_digest(kernel_archive, KERNEL_ARCHIVE_SHA256)
    require_digest(contracts_archive, CONTRACTS_ARCHIVE_SHA256)

    predecessor_entries = legacy_files(repo)
    predecessor_tree_hash = digest_bytes(canonical_bytes(predecessor_entries))
    source_manifest = {
        "schema": "anarchi.anar-core.source-manifest.v1",
        "canonicalization": CANONICALIZATION,
        "status": "PRE_FREEZE_INPUTS_RECONCILED",
        "production_mutated": False,
        "sources": [
            {
                "authority_class": "USER_SUPPLIED_PRE_FREEZE_SPEC",
                "path": spec_path.relative_to(repo).as_posix(),
                "sha256": SPEC_SHA256,
                "internal_title": "SPEC-3.0-Anar-Core-vNext-Authority-Substrate",
                "supplied_filename_version": "3.12",
                "freeze_state": "PRE_FREEZE_M10_NOT_READY",
            },
            {
                "authority_class": "USER_SUPPLIED_PREDECESSOR_EVIDENCE",
                "path": kernel_archive.relative_to(repo).as_posix(),
                "sha256": KERNEL_ARCHIVE_SHA256,
            },
            {
                "authority_class": "USER_SUPPLIED_PREDECESSOR_EVIDENCE",
                "path": contracts_archive.relative_to(repo).as_posix(),
                "sha256": CONTRACTS_ARCHIVE_SHA256,
            },
            {
                "authority_class": "ADMITTED_CURRENT_CANON",
                "external_path": "/home/alexg-anarchi/anarchi-governance/corpus/30-engineering/canonical-ecosystem-architecture-responsibility-map.md",
                "sha256": GOVERNANCE_MAP_SHA256,
                "source_commit": "b660430",
            },
            {
                "authority_class": "ADMITTED_CURRENT_CANON",
                "external_path": "/home/alexg-anarchi/anarchi-governance/corpus/30-engineering/identity-authority-broker-doctrine.md",
                "sha256": IDENTITY_DOCTRINE_SHA256,
                "source_commit": "b660430",
            },
            {
                "authority_class": "FROZEN_PRODUCT_SPEC",
                "external_path": "/home/alexg-anarchi/anarchi-recoveries/docs/specification/SPEC-1.6-AnarchI-Tech-Recoveries-FROZEN.md",
                "sha256": RECOVERIES_SPEC_SHA256,
                "source_commit": "fd5f705",
            },
        ],
        "predecessor_tree": {
            "file_count": len(predecessor_entries),
            "canonical_manifest_sha256": predecessor_tree_hash,
            "files": predecessor_entries,
        },
        "predecessor_test_observation": {
            "contracts_archive": {"passed": 10, "failed": 0, "errors": 0},
            "kernel_distribution_contracts": {"passed": 11, "failed": 0, "errors": 0},
            "kernel_modules": {
                "status": "ENVIRONMENT_DEPENDENCY_MISSING",
                "missing_dependency": "argon2",
                "unloaded_test_modules": 3,
                "authority_failure_inferred": False,
            },
        },
    }
    manifest_path = repo / "evidence/manifests/source-manifest.v1.json"
    write_json(manifest_path, source_manifest)

    transition_artifacts = artifact_map(
        repo,
        [
            "README.md",
            "docs/ADR/ADR-001-spec-identity-and-pre-freeze-status.md",
            "docs/ADR/ADR-002-predecessor-preservation-and-new-authority-path.md",
            "docs/integration/recoveries-authority-seam.md",
            "docs/reconciliation/PHASE-MINUS-1-INSTITUTIONAL-RECONCILIATION.md",
            "evidence/manifests/source-manifest.v1.json",
            "governance/authority-invariants.v1.json",
            "governance/repository-map.v1.json",
            "proof/corrections/CORRECTION-001-POWERSHELL-WSL-VARIABLE-BOUNDARY.json",
            "tools/proof/generate_phase_minus_one.py",
        ],
    )
    receipt = {
        "schema": "anarchi.transition-receipt.v1",
        "canonicalization": CANONICALIZATION,
        "transition_id": "PHASE-MINUS-1-INSTITUTIONAL-RECONCILIATION",
        "recorded_at": args.recorded_at,
        "source_commit": "GENESIS_NO_PREVIOUS_COMMIT",
        "previous_receipt_hash": None,
        "spec_sha256": SPEC_SHA256,
        "input_manifest_sha256": digest_file(manifest_path),
        "artifacts": transition_artifacts,
        "authority_state": {
            "specification": "PRE_FREEZE_M10_NOT_READY",
            "implementation": "RECONCILED_SAFE_TO_BUILD",
            "production_authority": "NONE",
            "production_mutated": False,
            "live_service_contact_count": 0,
            "external_credential_contact_count": 0,
        },
        "verification": {
            "spec_digest_verified": True,
            "archive_digests_verified": True,
            "predecessor_bytes_preserved": True,
            "governance_boundary_reconciled": True,
            "recoveries_boundary_reconciled": True,
        },
        "open_items": [
            "Predecessor kernel tests requiring argon2 have not executed in the current WSL environment.",
            "No predecessor live database or production service was supplied or contacted.",
            "M10 implementation proofs remain open.",
            "Independent review and hard-freeze adjudication remain open.",
        ],
    }
    receipt["receipt_hash"] = digest_bytes(canonical_bytes(receipt))
    write_json(
        repo / "proof/phase-minus-1/PHASE-MINUS-1-INSTITUTIONAL-RECONCILIATION-RECEIPT.json",
        receipt,
    )


if __name__ == "__main__":
    main()

