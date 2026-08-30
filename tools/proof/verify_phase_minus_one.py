#!/usr/bin/env python3
"""Verify Phase -1 evidence without trusting the generator's runtime state."""

from __future__ import annotations

import hashlib
import json
import re
import subprocess
from pathlib import Path
from typing import Any


def canonical_bytes(value: Any) -> bytes:
    if isinstance(value, float):
        raise SystemExit("floating-point value found in proof artifact")
    if isinstance(value, dict):
        for key, item in value.items():
            if not isinstance(key, str):
                raise SystemExit("non-string proof key")
            canonical_bytes(item)
    elif isinstance(value, list):
        for item in value:
            canonical_bytes(item)
    return json.dumps(
        value,
        ensure_ascii=False,
        allow_nan=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


def git_bytes(repo: Path, commit: str, relative: str) -> bytes:
    if Path(relative).is_absolute() or ".." in Path(relative).parts:
        raise SystemExit(f"unsafe historical artifact path: {relative}")
    resolved = subprocess.run(
        ["git", "show", f"{commit}:{relative}"],
        cwd=repo,
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        check=False,
    )
    if resolved.returncode != 0:
        raise SystemExit(f"historical artifact unavailable: {commit}:{relative}")
    return resolved.stdout


def git_text(repo: Path, *args: str) -> str:
    resolved = subprocess.run(
        ["git", *args],
        cwd=repo,
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        check=False,
        text=True,
    )
    if resolved.returncode != 0:
        raise SystemExit(f"git verification failed: {' '.join(args)}")
    return resolved.stdout.strip()


def main() -> None:
    repo = Path(__file__).resolve().parents[2]
    receipt_path = repo / "proof/phase-minus-1/PHASE-MINUS-1-INSTITUTIONAL-RECONCILIATION-RECEIPT.json"
    correction_path = repo / "proof/corrections/CORRECTION-014-PHASE-MINUS-1-HISTORICAL-SNAPSHOT-BINDING.json"
    receipt_bytes = receipt_path.read_bytes()
    receipt = json.loads(receipt_path.read_text(encoding="utf-8"))
    correction = json.loads(correction_path.read_text(encoding="utf-8"))
    asserted_hash = receipt.pop("receipt_hash")
    actual_hash = hashlib.sha256(canonical_bytes(receipt)).hexdigest()
    if actual_hash != asserted_hash:
        raise SystemExit(f"receipt hash mismatch: {actual_hash} != {asserted_hash}")

    required_correction = {
        "schema": "anarchi.corrective-transition-receipt.v1",
        "correction_id": "CORRECTION-014",
        "original_receipt_path": "proof/phase-minus-1/PHASE-MINUS-1-INSTITUTIONAL-RECONCILIATION-RECEIPT.json",
        "original_receipt_hash": asserted_hash,
        "original_receipt_file_sha256": hashlib.sha256(receipt_bytes).hexdigest(),
        "original_source_commit_marker": "GENESIS_NO_PREVIOUS_COMMIT",
        "historical_source_commit": "31c9d1929a28617c712412d719c81107fda777b7",
        "historical_source_tree": "9627b610d6a4a0ba140d4d1e2edab0a7e0ef7750",
        "artifact_count": len(receipt["artifacts"]),
        "production_mutated": False,
        "historical_receipts_rewritten": False,
    }
    for key, expected in required_correction.items():
        if correction.get(key) != expected:
            raise SystemExit(f"correction binding mismatch: {key}")
    if receipt.get("source_commit") != correction["original_source_commit_marker"]:
        raise SystemExit("original source-commit marker mismatch")

    historical_commit = correction["historical_source_commit"]
    if not re.fullmatch(r"[0-9a-f]{40}", historical_commit):
        raise SystemExit("historical source commit format")
    if git_text(repo, "rev-parse", f"{historical_commit}^{{tree}}") != correction["historical_source_tree"]:
        raise SystemExit("historical source tree mismatch")
    if git_text(repo, "rev-list", "--parents", "-n", "1", historical_commit) != historical_commit:
        raise SystemExit("historical source commit is not the expected root transition")
    subprocess.run(
        ["git", "merge-base", "--is-ancestor", historical_commit, "HEAD"],
        cwd=repo,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        check=True,
    )
    historical_receipt = git_bytes(repo, historical_commit, correction["original_receipt_path"])
    if historical_receipt != receipt_bytes:
        raise SystemExit("historical receipt bytes differ from preserved receipt")

    for relative, expected in receipt["artifacts"].items():
        actual = hashlib.sha256(git_bytes(repo, historical_commit, relative)).hexdigest()
        if actual != expected:
            raise SystemExit(f"artifact hash mismatch: {relative}: {actual} != {expected}")
    if receipt["authority_state"]["production_mutated"]:
        raise SystemExit("Phase -1 cannot claim production mutation")
    print(
        json.dumps(
            {
                "result": "PASS",
                "transition_id": receipt["transition_id"],
                "receipt_hash": asserted_hash,
                "artifact_count": len(receipt["artifacts"]),
                "historical_source_commit": historical_commit,
                "historical_source_tree": correction["historical_source_tree"],
                "current_head_repository_map_not_substituted": True,
                "production_mutated": False,
            },
            sort_keys=True,
        )
    )


if __name__ == "__main__":
    main()
