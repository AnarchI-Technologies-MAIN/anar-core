#!/usr/bin/env python3
"""Offline verifier for an Anar-Core authority evidence packet."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
from typing import Any


def canonical_bytes(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def sha256_file(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("packet_dir", type=Path)
    args = parser.parse_args()
    packet_dir = args.packet_dir.resolve()
    root = Path(__file__).resolve().parents[2]

    packet = json.loads((packet_dir / "authority-evidence-packet.json").read_text(encoding="utf-8"))
    receipt = json.loads((packet_dir / "transition-receipt.json").read_text(encoding="utf-8"))
    manifest = json.loads((packet_dir / "artifact-hashes.json").read_text(encoding="utf-8"))

    failures: list[str] = []
    for relative, expected in manifest["artifacts"].items():
        path = root / relative
        if not path.is_file() or sha256_file(path) != expected:
            failures.append(relative)

    receipt_hash = receipt.pop("receipt_hash_sha256")
    if hashlib.sha256(canonical_bytes(receipt)).hexdigest() != receipt_hash:
        failures.append("transition-receipt canonical hash")
    if packet["final_state"] != {
        "milestone": "M10_NOT_READY",
        "production_authority": "NONE",
        "production_mutated": False,
        "release_state": "HOLD_NOT_READY",
    }:
        failures.append("honest final state")
    if not packet["all_unknowns"]:
        failures.append("unknown preservation")

    report = {
        "schema": "anarchi.anar-core.evidence-verification.v1",
        "packet_dir": str(packet_dir),
        "artifact_count": len(manifest["artifacts"]),
        "receipt_hash_sha256": receipt_hash,
        "production_authority": packet["final_state"]["production_authority"],
        "failures": failures,
        "result": "PASS" if not failures else "FAIL",
    }
    print(json.dumps(report, indent=2, sort_keys=True))
    return 0 if not failures else 1


if __name__ == "__main__":
    raise SystemExit(main())

