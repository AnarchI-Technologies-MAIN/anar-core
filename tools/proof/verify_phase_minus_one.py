#!/usr/bin/env python3
"""Verify Phase -1 evidence without trusting the generator's runtime state."""

from __future__ import annotations

import hashlib
import json
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


def digest_file(path: Path) -> str:
    hasher = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            hasher.update(chunk)
    return hasher.hexdigest()


def main() -> None:
    repo = Path(__file__).resolve().parents[2]
    receipt_path = repo / "proof/phase-minus-1/PHASE-MINUS-1-INSTITUTIONAL-RECONCILIATION-RECEIPT.json"
    receipt = json.loads(receipt_path.read_text(encoding="utf-8"))
    asserted_hash = receipt.pop("receipt_hash")
    actual_hash = hashlib.sha256(canonical_bytes(receipt)).hexdigest()
    if actual_hash != asserted_hash:
        raise SystemExit(f"receipt hash mismatch: {actual_hash} != {asserted_hash}")
    for relative, expected in receipt["artifacts"].items():
        actual = digest_file(repo / relative)
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
                "production_mutated": False,
            },
            sort_keys=True,
        )
    )


if __name__ == "__main__":
    main()
