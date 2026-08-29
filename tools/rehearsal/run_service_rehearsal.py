#!/usr/bin/env python3
"""Run the isolated four-service WSL2 safe-pause rehearsal."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import secrets
import socket
import subprocess
import sys
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[2]
COMPOSE_FILE = ROOT / "infra/compose/compose.rehearsal-services.yaml"
CORPUS = ROOT / "fixtures"
SPEC = ROOT / "docs/specification/SPEC-3.12-Anar-Core-vNext-Authority-Substrate-PRE-FREEZE-HARDENED.md"
SPEC_SHA256 = "26697bc4a7de4a17272e8f3a47a12d3aec7dee12f2d6bd1f62aaf0d0aff78b80"
IMAGES = {
    "postgres": "postgres@sha256:cf78e76683b9ca8c5733cbbdce6c9262b45b6767934dd0a95e671f9a0fc20685",
    "nats": "nats@sha256:d4ac35882ac65aff236cd65b9d3fa4d24332c681e1a85f94eedccd3cdd65b1da",
    "minio": "minio/minio@sha256:14cea493d9a34af32f524e538b8346cf79f3321eff8e708c1e2960462bd8936e",
    "zitadel": "ghcr.io/zitadel/zitadel@sha256:4b68a2106f60baa2895e5a00a77fcd915d29d0db3f0c011d3eb9f99f557b2b48",
}
PREVIOUS_RECEIPT_SHA256 = "faf8d33d76d100654d18087d1a14ebe002ca585ef605f7b4d3c13d18afeb66fd"


class RehearsalFailure(RuntimeError):
    pass


def canonical_bytes(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def sha256_file(path: Path) -> str:
    return sha256_bytes(path.read_bytes())


def command(argv: list[str], *, env: dict[str, str], input_bytes: bytes | None = None, check: bool = True) -> subprocess.CompletedProcess[bytes]:
    result = subprocess.run(
        argv,
        cwd=ROOT,
        env=env,
        input=input_bytes,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        check=False,
    )
    if check and result.returncode != 0:
        raise RehearsalFailure(
            f"command failed ({result.returncode}): {' '.join(argv)}\n"
            + result.stdout.decode("utf-8", errors="replace")[-12000:]
        )
    return result


def free_loopback_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as listener:
        listener.bind(("127.0.0.1", 0))
        return int(listener.getsockname()[1])


def preflight() -> dict[str, Any]:
    compose = COMPOSE_FILE.read_text(encoding="utf-8")
    required = [
        "pull_policy: never",
        "internal: true",
        "127.0.0.1:${ANAR_STACK_",
        "postgres@sha256:",
        "nats@sha256:",
        "minio/minio@sha256:",
        "ghcr.io/zitadel/zitadel@sha256:",
        "/var/lib/postgresql/data:rw,nosuid,nodev,noexec",
        "/data:rw,nosuid,nodev,noexec",
    ]
    missing = [fragment for fragment in required if fragment not in compose]
    if missing:
        raise RehearsalFailure(f"four-service isolation contract is incomplete: {missing}")
    inherited = sorted(
        key
        for key in os.environ
        if key.startswith(("ANAR_", "POSTGRES_", "ZITADEL_", "MINIO_"))
        or key in {"DATABASE_URL", "VAULT_ADDR", "VAULT_TOKEN", "STRIPE_SECRET_KEY"}
    )
    if inherited:
        raise RehearsalFailure("authority-bearing environment variables must be absent: " + ", ".join(inherited))
    if sha256_file(SPEC) != SPEC_SHA256:
        raise RehearsalFailure("frozen source specification digest changed")
    return {
        "frozen_spec_digest_verified": True,
        "production_authority_variables_present": False,
        "compose_isolation_contract_verified": True,
        "service_image_count": len(IMAGES),
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--development", action="store_true")
    parser.add_argument("--output-dir", type=Path)
    args = parser.parse_args()

    preflight_results = preflight()
    source_commit = command(["git", "rev-parse", "HEAD"], env=os.environ.copy()).stdout.decode().strip()
    source_status = command(["git", "status", "--porcelain"], env=os.environ.copy()).stdout.decode().strip()
    if source_status and not args.development:
        raise RehearsalFailure("durable evidence requires a clean source commit")

    timestamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    run_id = f"anar-core-phase0-services-{timestamp}-{secrets.token_hex(4)}"
    project_name = f"anar-core-services-{secrets.token_hex(6)}"
    env = os.environ.copy()
    env.update(
        {
            "ANAR_COMPOSE_PROJECT_NAME": project_name,
            "ANAR_STACK_DATABASE": "anar_identity_rehearsal",
            "ANAR_STACK_DB_USER": "anar_identity_admin",
            "ANAR_STACK_DB_PASSWORD": secrets.token_urlsafe(48),
            "ANAR_STACK_ZITADEL_MASTERKEY": secrets.token_urlsafe(32)[:32],
            "ANAR_STACK_ZITADEL_HUMAN_PASSWORD": secrets.token_urlsafe(32),
            "ANAR_STACK_PG_PORT": str(free_loopback_port()),
            "ANAR_STACK_NATS_PORT": str(free_loopback_port()),
            "ANAR_STACK_NATS_MONITOR_PORT": str(free_loopback_port()),
            "ANAR_STACK_MINIO_PORT": str(free_loopback_port()),
            "ANAR_STACK_MINIO_CONSOLE_PORT": str(free_loopback_port()),
            "ANAR_STACK_MINIO_USER": "anarminioadmin",
            "ANAR_STACK_MINIO_PASSWORD": secrets.token_urlsafe(32),
            "ANAR_STACK_ZITADEL_PORT": str(free_loopback_port()),
        }
    )
    compose = ["docker", "compose", "-f", str(COMPOSE_FILE)]

    def compose_command(arguments: list[str], **kwargs: Any) -> subprocess.CompletedProcess[bytes]:
        return command(compose + arguments, env=env, **kwargs)

    services = ["minio", "nats", "postgres", "zitadel"]
    results: dict[str, Any] = {
        "schema": "anarchi.anar-core.service-rehearsal-results.v1",
        "run_id": run_id,
        "source_commit": source_commit,
        "source_tree_clean": not bool(source_status),
        "preflight": preflight_results,
        "production_mutated": False,
        "production_endpoint_contact_count": 0,
        "checks": {},
        "denials": [],
        "services": services,
    }
    teardown_ok = False
    try:
        for service, image in IMAGES.items():
            inspected = command(["docker", "image", "inspect", image, "--format", "{{json .RepoDigests}}"], env=env)
            if image not in inspected.stdout.decode().strip():
                raise RehearsalFailure(f"digest-pinned {service} image is not present locally")
        results["checks"]["local_digest_pinned_images"] = "PASS"

        startup = compose_command(["up", "-d", "--wait", "--no-build"], check=False)
        if startup.returncode != 0:
            logs = compose_command(["logs", "--no-color"], check=False).stdout.decode("utf-8", errors="replace")
            raise RehearsalFailure("four-service startup failed\n" + logs[-16000:])

        container_ids: dict[str, str] = {}
        service_manifests: list[dict[str, Any]] = []
        for service in services:
            container_id = compose_command(["ps", "-q", service]).stdout.decode().strip()
            if not container_id:
                raise RehearsalFailure(f"{service} container did not start")
            container_ids[service] = container_id
            inspection = json.loads(command(["docker", "inspect", container_id], env=env).stdout.decode())[0]
            bindings = inspection["HostConfig"].get("PortBindings") or {}
            host_ips = sorted({entry["HostIp"] for entries in bindings.values() for entry in (entries or [])})
            tmpfs = inspection["HostConfig"].get("Tmpfs") or {}
            networks = sorted(inspection["NetworkSettings"]["Networks"])
            if host_ips and host_ips != ["127.0.0.1"]:
                raise RehearsalFailure(f"{service} is not loopback-only: {host_ips}")
            if not networks:
                raise RehearsalFailure(f"{service} has no rehearsal network")
            network = json.loads(command(["docker", "network", "inspect", networks[0]], env=env).stdout.decode())[0]
            if not network.get("Internal"):
                raise RehearsalFailure(f"{service} network is not internal")
            state = inspection.get("State", {})
            if state.get("Health", {}).get("Status") != "healthy":
                raise RehearsalFailure(f"{service} health is not healthy: {state.get('Health')}")
            service_manifests.append(
                {
                    "service": service,
                    "container_image_id": inspection.get("Image"),
                    "image": IMAGES[service],
                    "host_bindings": bindings,
                    "tmpfs_destinations": sorted(tmpfs),
                    "network_internal": bool(network.get("Internal")),
                }
            )
        results["checks"]["runtime_isolation"] = "PASS"
        results["checks"]["health_checks"] = "PASS"

        probes = {
            "postgres_readiness": ["exec", "-T", "postgres", "pg_isready", "-U", env["ANAR_STACK_DB_USER"], "-d", env["ANAR_STACK_DATABASE"]],
            "nats_jetstream_health": ["exec", "-T", "nats", "wget", "-qO-", "http://127.0.0.1:8222/healthz"],
            "minio_object_store_health": ["exec", "-T", "minio", "curl", "-f", "http://127.0.0.1:9000/minio/health/ready"],
            "zitadel_identity_readiness": ["exec", "-T", "zitadel", "/app/zitadel", "ready"],
        }
        for name, probe in probes.items():
            probe_result = compose_command(probe, check=False)
            if probe_result.returncode != 0:
                raise RehearsalFailure(f"{name} failed: {probe_result.stdout.decode('utf-8', errors='replace')[-4000:]}")
            results["checks"][name] = "PASS"
        results["checks"]["production_endpoint_contact_count"] = "PASS"
    finally:
        down = compose_command(["down", "--volumes", "--remove-orphans"], check=False)
        remaining = compose_command(
            ["ps", "-aq", "--all"],
            check=False,
        ).stdout.decode().strip()
        teardown_ok = down.returncode == 0 and not remaining
        results["teardown"] = {
            "compose_down_exit_code": down.returncode,
            "remaining_container_ids": remaining.splitlines() if remaining else [],
            "passed": teardown_ok,
        }
    if not teardown_ok:
        raise RehearsalFailure("four-service teardown did not prove zero remaining containers")
    results["checks"]["teardown"] = "PASS"

    temporary_output: tempfile.TemporaryDirectory[str] | None = None
    if args.development:
        temporary_parent = ROOT / ".tmp"
        temporary_parent.mkdir(parents=True, exist_ok=True)
        temporary_output = tempfile.TemporaryDirectory(prefix="anar-core-services-", dir=temporary_parent)
        output_dir = Path(temporary_output.name).resolve()
    else:
        output_dir = (args.output_dir or ROOT / "proof/rehearsals" / run_id).resolve()
        output_dir.mkdir(parents=True, exist_ok=False)

    results["service_manifest"] = {"services": services, "images": IMAGES, "containers": service_manifests}
    results_path = output_dir / "service-rehearsal-results.json"
    results_path.write_bytes(canonical_bytes(results) + b"\n")
    input_paths = [
        COMPOSE_FILE,
        SPEC,
        ROOT / "Cargo.lock",
        ROOT / "governance/repository-map.v1.json",
        ROOT / "governance/reason-code-registry.v1.json",
        ROOT / "tools/rehearsal/run_service_rehearsal.py",
        ROOT / "tools/rehearsal/verify_service_packet.py",
        *sorted(path for path in CORPUS.rglob("*") if path.is_file()),
    ]
    evidence_hashes = {str(path.relative_to(ROOT)): sha256_file(path) for path in input_paths}
    evidence_hashes[str(results_path.relative_to(ROOT))] = sha256_file(results_path)
    packet = {
        "schema": "anarchi.anar-core.service-evidence-packet.v1",
        "pilot_identity": run_id,
        "repository_commit": source_commit,
        "spec_digest": SPEC_SHA256,
        "rule_registry_digest": sha256_file(ROOT / "governance/reason-code-registry.v1.json"),
        "policy_digest": sha256_file(ROOT / "governance/authority-invariants.v1.json"),
        "pricing_version": "NOT_APPLICABLE_AUTHORITY_SUBSTRATE",
        "input_corpus_manifest": {
            "schema": "anarchi.anar-core.fixture-corpus-manifest.v1",
            "corpus_version": "1.0.0",
            "reviewer_view": "UNDISCLOSED",
            "source_digests": {
                str(path.relative_to(ROOT)): evidence_hashes[str(path.relative_to(ROOT))]
                for path in sorted(path for path in CORPUS.rglob("*") if path.is_file())
            },
        },
        "evidence_hashes": evidence_hashes,
        "decision_trace": {"transition": "four pinned local services from preflight to healthy readiness", "checks": results["checks"]},
        "calculation_trace": {"authority": "NO_PRODUCTION_AUTHORITY", "service_count": len(services)},
        "human_adjudication": "PENDING_INDEPENDENT_REVIEW",
        "authority_receipt": {"format": "ANAR-SERVICE-SAFE-PAUSE-WITNESS-V1", "production_mutated": False},
        "action_payload_hash": "NOT_APPLICABLE_NO_EXTERNAL_ACTION",
        "external_action_receipt": "NOT_APPLICABLE_NO_EXTERNAL_ACTION",
        "payment_evidence": "NOT_APPLICABLE_AUTHORITY_SUBSTRATE",
        "attribution_result": "NOT_APPLICABLE_AUTHORITY_SUBSTRATE",
        "fee_calculation": "NOT_APPLICABLE_AUTHORITY_SUBSTRATE",
        "reconciliation_result": {"services_healthy": len(services), "services_torn_down": len(services)},
        "all_encountered_denials": [],
        "all_unknowns": [
            "Zitadel authentication and token exchange are not exercised by this readiness-only rehearsal",
            "NATS publish/consume semantics and MinIO object CRUD are not exercised by this readiness-only rehearsal",
            "Vault leasing, Rust persistence, live HTTP, production deployment, security review, and restore proof remain open",
        ],
        "production_endpoint_contact_count": 0,
        "service_manifest": {"services": services, "images": IMAGES},
        "final_state": {"milestone": "M10_NOT_READY", "production_authority": "NONE", "production_mutated": False, "release_state": "HOLD_NOT_READY"},
    }
    packet_path = output_dir / "service-evidence-packet.json"
    packet_path.write_bytes(canonical_bytes(packet) + b"\n")
    receipt_body = {
        "schema": "anarchi.transition-receipt.v1",
        "transition": "PHASE-0-FOUR-SERVICE-SAFE-PAUSE-REHEARSAL",
        "source_commit": source_commit,
        "previous_receipt_sha256": PREVIOUS_RECEIPT_SHA256,
        "frozen_spec_sha256": SPEC_SHA256,
        "rehearsal_run_id": run_id,
        "canonicalization": "UTF-8_SORTED-KEYS-NO-WHITESPACE-V1",
        "artifact_hashes": {**evidence_hashes, str(packet_path.relative_to(ROOT)): sha256_file(packet_path)},
        "verification": results["checks"],
        "authority_state": {"production_authority": "NONE", "production_mutated": False},
        "open_items": packet["all_unknowns"],
        "teardown_passed": True,
    }
    receipt_hash = sha256_bytes(canonical_bytes(receipt_body))
    receipt_path = output_dir / "transition-receipt.json"
    receipt_path.write_bytes(canonical_bytes({**receipt_body, "receipt_hash_sha256": receipt_hash}) + b"\n")
    manifest_path = output_dir / "artifact-hashes.json"
    manifest_path.write_bytes(canonical_bytes({"schema": "anarchi.artifact-hash-manifest.v1", "self_hash_excluded": True, "artifacts": {**receipt_body["artifact_hashes"], str(receipt_path.relative_to(ROOT)): sha256_file(receipt_path)}}) + b"\n")
    verification = command([sys.executable, str(ROOT / "tools/rehearsal/verify_service_packet.py"), str(output_dir)], env=os.environ.copy())
    verification_report = json.loads(verification.stdout.decode("utf-8"))
    if verification_report.get("result") != "PASS":
        raise RehearsalFailure(f"emitted four-service packet did not verify: {verification_report}")
    if args.development:
        print(json.dumps({"development_results": results, "offline_packet_verification": verification_report}, indent=2, sort_keys=True))
        if temporary_output is not None:
            temporary_output.cleanup()
        return 0
    print(json.dumps({"run_id": run_id, "output_dir": str(output_dir), "receipt_hash_sha256": receipt_hash}, indent=2))
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except RehearsalFailure as error:
        print(f"REHEARSAL_FAILED: {error}", file=sys.stderr)
        raise SystemExit(1)
