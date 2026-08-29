#!/usr/bin/env python3
"""Run the isolated Anar-Core PostgreSQL authority rehearsal.

The runner uses only the already-present, digest-pinned image. It never pulls,
never consumes a production URL or credential, and always tears the project
down before it emits a successful evidence package.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import secrets
import socket
import subprocess
import sys
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[2]
COMPOSE_FILE = ROOT / "infra/compose/compose.rehearsal.yaml"
MIGRATIONS = ROOT / "infra/postgres/migrations"
FIXTURES = ROOT / "fixtures/postgres"
CORPUS = ROOT / "fixtures"
SPEC = ROOT / "docs/specification/SPEC-3.12-Anar-Core-vNext-Authority-Substrate-PRE-FREEZE-HARDENED.md"
SPEC_SHA256 = "26697bc4a7de4a17272e8f3a47a12d3aec7dee12f2d6bd1f62aaf0d0aff78b80"
IMAGE_DIGEST = "postgres@sha256:cf78e76683b9ca8c5733cbbdce6c9262b45b6767934dd0a95e671f9a0fc20685"
PREVIOUS_RECEIPT_SHA256 = "e08281c2b4fdf2db7f5a6d543b7eeac52e7d1735d0ba632bc72ffd1e263f1ecd"


class RehearsalFailure(RuntimeError):
    pass


def canonical_bytes(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def sha256_file(path: Path) -> str:
    return sha256_bytes(path.read_bytes())


def command(
    argv: list[str],
    *,
    env: dict[str, str],
    input_bytes: bytes | None = None,
    check: bool = True,
) -> subprocess.CompletedProcess[bytes]:
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
        output = result.stdout.decode("utf-8", errors="replace")
        raise RehearsalFailure(f"command failed ({result.returncode}): {' '.join(argv)}\n{output}")
    return result


def free_loopback_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as listener:
        listener.bind(("127.0.0.1", 0))
        return int(listener.getsockname()[1])


def preflight() -> dict[str, Any]:
    compose = COMPOSE_FILE.read_text(encoding="utf-8")
    required_fragments = [
        f"image: {IMAGE_DIGEST}",
        'pull_policy: never',
        '127.0.0.1:${ANAR_PG_PORT',
        'internal: true',
        '/var/lib/postgresql/data:rw,nosuid,nodev,noexec,size=512m,mode=0700,uid=70,gid=70',
    ]
    missing = [fragment for fragment in required_fragments if fragment not in compose]
    if missing:
        raise RehearsalFailure(f"compose isolation contract is incomplete: {missing}")

    inherited_authority_variables = sorted(
        key
        for key in os.environ
        if key.startswith(("ANAR_", "POSTGRES_"))
        or key in {"DATABASE_URL", "VAULT_ADDR", "VAULT_TOKEN", "STRIPE_SECRET_KEY"}
    )
    if inherited_authority_variables:
        raise RehearsalFailure(
            "authority-bearing environment variables must be absent before rehearsal: "
            + ", ".join(inherited_authority_variables)
        )

    advisory_occurrences: list[str] = []
    for migration in sorted(MIGRATIONS.glob("*.sql")):
        for line_number, line in enumerate(migration.read_text(encoding="utf-8").splitlines(), 1):
            if re.search(r"\bpg_(?:try_)?advisory_(?:xact_)?lock\b", line, flags=re.IGNORECASE):
                advisory_occurrences.append(f"{migration.name}:{line_number}")
    if advisory_occurrences:
        raise RehearsalFailure(f"advisory locks are forbidden: {advisory_occurrences}")

    if sha256_file(SPEC) != SPEC_SHA256:
        raise RehearsalFailure("frozen source specification digest changed")

    return {
        "frozen_spec_digest_verified": True,
        "production_authority_variables_present": False,
        "advisory_lock_occurrences": 0,
        "compose_isolation_contract_verified": True,
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--development", action="store_true", help="allow a dirty source tree and omit durable proof output")
    parser.add_argument("--output-dir", type=Path)
    args = parser.parse_args()

    preflight_results = preflight()
    source_commit = command(
        ["git", "rev-parse", "HEAD"], env=os.environ.copy()
    ).stdout.decode().strip()
    source_status = command(
        ["git", "status", "--porcelain"], env=os.environ.copy()
    ).stdout.decode().strip()
    if source_status and not args.development:
        raise RehearsalFailure("durable evidence requires a clean source commit")

    timestamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    run_id = f"anar-core-phase0-postgres-{timestamp}-{secrets.token_hex(4)}"
    project_name = f"anar-core-rehearsal-{secrets.token_hex(6)}"
    database = "anar_core_rehearsal"
    admin_user = "anar_rehearsal_admin"
    env = os.environ.copy()
    env.update(
        {
            "ANAR_COMPOSE_PROJECT_NAME": project_name,
            "ANAR_PG_DATABASE": database,
            "ANAR_PG_ADMIN_USER": admin_user,
            "ANAR_PG_ADMIN_PASSWORD": secrets.token_urlsafe(48),
            "ANAR_PG_PORT": str(free_loopback_port()),
        }
    )
    compose = ["docker", "compose", "-f", str(COMPOSE_FILE)]

    def compose_command(arguments: list[str], **kwargs: Any) -> subprocess.CompletedProcess[bytes]:
        return command(compose + arguments, env=env, **kwargs)

    def psql_bytes(content: bytes, *, check: bool = True, quiet: bool = False) -> subprocess.CompletedProcess[bytes]:
        psql = compose + [
            "exec", "-T", "postgres", "psql", "-X", "-v", "ON_ERROR_STOP=1",
            "-U", admin_user, "-d", database,
        ]
        if quiet:
            psql.extend(["-A", "-t", "-q"])
        return command(psql, env=env, input_bytes=content, check=check)

    results: dict[str, Any] = {
        "schema": "anarchi.anar-core.postgres-rehearsal-results.v1",
        "run_id": run_id,
        "source_commit": source_commit,
        "source_tree_clean": not bool(source_status),
        "preflight": preflight_results,
        "production_mutated": False,
        "production_endpoint_contact_count": 0,
        "checks": {},
        "denials": [],
    }
    teardown_ok = False
    try:
        local_image = command(
            ["docker", "image", "inspect", IMAGE_DIGEST, "--format", "{{json .RepoDigests}}"],
            env=env,
        ).stdout.decode().strip()
        if IMAGE_DIGEST not in local_image:
            raise RehearsalFailure("digest-pinned Postgres image is not already present locally")
        results["checks"]["local_digest_pinned_image"] = "PASS"

        startup = compose_command(["up", "-d", "--wait", "--no-build"], check=False)
        if startup.returncode != 0:
            service_log = compose_command(["logs", "--no-color", "postgres"], check=False).stdout.decode(
                "utf-8", errors="replace"
            )
            raise RehearsalFailure(
                "Postgres startup failed before migrations\n"
                + startup.stdout.decode("utf-8", errors="replace")
                + "\nSERVICE LOG:\n"
                + service_log[-12000:]
            )
        container_id = compose_command(["ps", "-q", "postgres"]).stdout.decode().strip()
        if not container_id:
            raise RehearsalFailure("Postgres container did not start")

        inspection = json.loads(
            command(["docker", "inspect", container_id], env=env).stdout.decode("utf-8")
        )[0]
        port_binding = inspection["HostConfig"]["PortBindings"]["5432/tcp"][0]
        mounts = {mount["Destination"]: mount["Type"] for mount in inspection["Mounts"]}
        tmpfs_contract = inspection["HostConfig"].get("Tmpfs") or {}
        network_names = sorted(inspection["NetworkSettings"]["Networks"])
        network_inspect = json.loads(
            command(["docker", "network", "inspect", network_names[0]], env=env).stdout.decode("utf-8")
        )[0]
        if port_binding["HostIp"] != "127.0.0.1":
            raise RehearsalFailure("database port is not loopback-only")
        if "/var/lib/postgresql/data" not in tmpfs_contract:
            raise RehearsalFailure(
                f"database state is not recorded as tmpfs: mounts={mounts}, host_tmpfs={tmpfs_contract}"
            )
        if not network_inspect.get("Internal"):
            raise RehearsalFailure("rehearsal network is not internal")
        results["service_manifest"] = {
            "image": IMAGE_DIGEST,
            "container_image_id": inspection["Image"],
            "port_host_ip": port_binding["HostIp"],
            "published_port": int(port_binding["HostPort"]),
            "mount_types": mounts,
            "tmpfs_destinations": sorted(tmpfs_contract),
            "network_internal": True,
        }
        results["checks"]["runtime_isolation"] = "PASS"

        for migration in sorted(MIGRATIONS.glob("*.sql")):
            psql_bytes(migration.read_bytes())
        results["checks"]["migrations"] = "PASS"

        psql_bytes((FIXTURES / "seed.sql").read_bytes())
        serial_output = psql_bytes((FIXTURES / "serial-proof.sql").read_bytes(), quiet=True).stdout.decode(
            "utf-8", errors="replace"
        )
        witness_match = re.search(r"([0-9a-f]{64})\|f", serial_output)
        if witness_match is None:
            raise RehearsalFailure(f"serial proof did not emit a witness hash: {serial_output}")
        witness_sha256 = witness_match.group(1)
        witness_output = psql_bytes(
            b"SELECT canonical_receipt::text FROM anar_core.decision_receipts WHERE receipt_id='80000000-0000-4000-8000-000000000001';",
            quiet=True,
        ).stdout.decode("utf-8", errors="replace")
        witness_lines = [line for line in witness_output.splitlines() if line.startswith("{")]
        if len(witness_lines) != 1:
            raise RehearsalFailure(f"durable finalization witness could not be read back: {witness_output}")
        primary_witness = json.loads(witness_lines[0])
        results["checks"].update(
            {
                "atomic_finalization": "PASS",
                "exact_idempotent_replay": "PASS",
                "changed_input_conflict": "PASS",
                "dependency_revalidation": "PASS",
                "wrong_tenant_denial": "PASS",
                "sequence_exhaustion": "PASS",
                "witness_byte_hash_match": "PASS",
                "payload_mutation_denial": "PASS",
                "immutable_request_binding_denial": "PASS",
            }
        )
        results["primary_witness_sha256"] = witness_sha256
        results["primary_finalization_witness"] = primary_witness
        results["denials"].extend(
            [
                "IDEMPOTENCY_CONFLICT",
                "STALE_AUTHORITY_RETRY_REQUIRED",
                "AUTHORITY_BINDING_DENIED_WRONG_TENANT",
                "SEQUENCE_EXHAUSTED",
                "MUTATION_TARGET_DIGEST_MISMATCH",
                "IMMUTABLE_REQUEST_BINDING_DENIED",
            ]
        )

        def rls_count(table: str, organization_id: str | None) -> int:
            if table not in {"organizations", "entitlement_bindings"}:
                raise RehearsalFailure(f"unregistered RLS proof table: {table}")
            setting = "" if organization_id is None else f"SET LOCAL anar.organization_id = '{organization_id}';"
            sql = (
                "BEGIN; SET LOCAL ROLE anar_core_runtime; "
                + setting
                + f" SELECT count(*) FROM anar_core.{table}; ROLLBACK;"
            )
            output = psql_bytes(sql.encode(), quiet=True).stdout.decode().strip().splitlines()
            numeric = [line for line in output if line.strip().isdigit()]
            if len(numeric) != 1:
                raise RehearsalFailure(f"unexpected RLS count output: {output}")
            return int(numeric[0])

        if rls_count("organizations", None) != 0 or rls_count(
            "organizations", "20000000-0000-4000-8000-000000000001"
        ) != 1:
            raise RehearsalFailure("RLS did not fail closed for absent or selected organization")
        if rls_count("organizations", "20000000-0000-4000-8000-000000000002") != 1:
            raise RehearsalFailure("RLS selected-organization projection is incorrect")
        if rls_count("entitlement_bindings", None) != 0:
            raise RehearsalFailure("entitlement RLS did not fail closed without tenant context")
        if rls_count("entitlement_bindings", "20000000-0000-4000-8000-000000000001") != 1:
            raise RehearsalFailure("entitlement RLS leaked or omitted tenant state")
        results["checks"]["tenant_rls"] = "PASS"

        unauthorized = psql_bytes(
            b"BEGIN; SET LOCAL ROLE anar_core_runtime; SET LOCAL anar.organization_id = '20000000-0000-4000-8000-000000000001'; UPDATE anar_core.organizations SET status='REVOKED'; ROLLBACK;",
            check=False,
            quiet=True,
        )
        if unauthorized.returncode == 0 or "permission denied" not in unauthorized.stdout.decode().lower():
            raise RehearsalFailure("runtime role unexpectedly obtained direct write authority")
        results["checks"]["direct_write_denied"] = "PASS"
        results["denials"].append("DIRECT_WRITE_AUTHORITY_DENIED")

        mutation_commands: list[list[str]] = []
        for fixture_name in ("mutation-call-a.sql", "mutation-call-b.sql"):
            mutation_commands.append(
                compose
                + [
                    "exec", "-T", "postgres", "psql", "-X", "-v", "ON_ERROR_STOP=1",
                    "-U", admin_user, "-d", database,
                ]
            )
        processes = [
            subprocess.Popen(
                argv,
                cwd=ROOT,
                env=env,
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
            )
            for argv in mutation_commands
        ]
        concurrency_outputs: list[tuple[int, str]] = []
        for process, fixture_name in zip(processes, ("mutation-call-a.sql", "mutation-call-b.sql"), strict=True):
            stdout, _ = process.communicate((FIXTURES / fixture_name).read_bytes(), timeout=30)
            concurrency_outputs.append((process.returncode, stdout.decode("utf-8", errors="replace")))
        winners = [entry for entry in concurrency_outputs if entry[0] == 0]
        losers = [entry for entry in concurrency_outputs if entry[0] != 0]
        if len(winners) != 1 or len(losers) != 1 or "AR003" not in losers[0][1]:
            raise RehearsalFailure(f"one-shot concurrency result was not one winner/one denial: {concurrency_outputs}")
        results["checks"]["one_shot_concurrent_mutation"] = "PASS"
        results["denials"].append("CONCURRENT_MUTATION_GRANT_REUSE_DENIED")

        post_output = psql_bytes((FIXTURES / "post-concurrency-proof.sql").read_bytes(), quiet=True).stdout.decode(
            "utf-8", errors="replace"
        )
        json_lines = [line for line in post_output.splitlines() if line.startswith("{")]
        if len(json_lines) != 1:
            raise RehearsalFailure(f"post-concurrency proof did not emit state: {post_output}")
        results["final_database_state"] = json.loads(json_lines[0])
        results["checks"]["mutation_event_atomicity"] = "PASS"
    finally:
        down = compose_command(["down", "--volumes", "--remove-orphans"], check=False)
        remaining = command(
            ["docker", "ps", "-a", "--filter", f"label=com.docker.compose.project={project_name}", "--format", "{{.ID}}"],
            env=env,
            check=False,
        ).stdout.decode().strip()
        teardown_ok = down.returncode == 0 and not remaining
        results["teardown"] = {
            "compose_down_exit_code": down.returncode,
            "remaining_container_ids": remaining.splitlines() if remaining else [],
            "passed": teardown_ok,
        }

    if not teardown_ok:
        raise RehearsalFailure("rehearsal teardown did not prove zero remaining containers")
    results["checks"]["teardown"] = "PASS"

    temporary_output: tempfile.TemporaryDirectory[str] | None = None
    if args.development:
        temporary_parent = ROOT / ".tmp"
        temporary_parent.mkdir(parents=True, exist_ok=True)
        temporary_output = tempfile.TemporaryDirectory(prefix="anar-core-rehearsal-", dir=temporary_parent)
        output_dir = Path(temporary_output.name).resolve()
    else:
        output_dir = (args.output_dir or ROOT / "proof/rehearsals" / run_id).resolve()
        output_dir.mkdir(parents=True, exist_ok=False)
    results_path = output_dir / "database-proof-results.json"
    results_path.write_bytes(canonical_bytes(results) + b"\n")

    input_paths = [
        COMPOSE_FILE,
        SPEC,
        ROOT / "Cargo.lock",
        ROOT / "governance/authority-invariants.v1.json",
        ROOT / "governance/reason-code-registry.v1.json",
        ROOT / "governance/repository-map.v1.json",
        ROOT / "governance/sqlstate-registry.v1.json",
        ROOT / "tools/rehearsal/run_postgres_rehearsal.py",
        ROOT / "tools/rehearsal/verify_evidence_packet.py",
        ROOT / "docs/ADR/ADR-004-corpus-manifest-and-undisclosed-adjudication.md",
        ROOT / "proof/corrections/CORRECTION-012-CORPUS-MANIFEST-COVERAGE.json",
        *sorted(MIGRATIONS.glob("*.sql")),
        *sorted(path for path in CORPUS.rglob("*") if path.is_file()),
    ]
    evidence_hashes = {str(path.relative_to(ROOT)): sha256_file(path) for path in input_paths}
    evidence_hashes[str(results_path.relative_to(ROOT))] = sha256_file(results_path)

    action_payload = {
        "action": "REVOKE_MEMBERSHIP",
        "actor_principal_id": "10000000-0000-4000-8000-000000000001",
        "organization_id": "20000000-0000-4000-8000-000000000001",
        "target_membership_id": "30000000-0000-4000-8000-000000000001",
        "target_digest": "61" * 32,
        "purpose_code": "authority.membership.revoke",
        "effect_scope_hash": "62" * 32,
        "mutation_grant_id": "a0000000-0000-4000-8000-000000000001",
    }
    action_payload_sha256 = sha256_bytes(canonical_bytes(action_payload))
    packet = {
        "schema": "anarchi.anar-core.authority-evidence-packet.v1",
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
            "case_ids": [
                "legitimate-entitled-approved",
                "formatted-evidence-untrusted-issuer",
                "commercial-entitlement-absent",
                "effective-revocation-present",
                "revocation-snapshot-incomplete",
            ],
            "source_digests": {
                str(path.relative_to(ROOT)): evidence_hashes[str(path.relative_to(ROOT))]
                for path in sorted(path for path in CORPUS.rglob("*") if path.is_file())
            },
        },
        "evidence_hashes": evidence_hashes,
        "decision_trace": {
            "transition": "immutable evaluation candidate to same-transaction database finalization witness",
            "checks": results["checks"],
            "why_permitted": {
                "outcome": results["primary_finalization_witness"]["outcome"],
                "reason_codes": results["primary_finalization_witness"]["reason_codes"],
                "dependency_bundle_hash": results["primary_finalization_witness"]["dependency_bundle_hash"],
                "evaluation_snapshot_hash": results["primary_finalization_witness"]["evaluation_snapshot_hash"],
                "policy_bundle_hash": results["primary_finalization_witness"]["policy_bundle_hash"],
            },
        },
        "calculation_trace": {
            "money": "NOT_APPLICABLE_AUTHORITY_SUBSTRATE",
            "sequence_rule": "checked current + 1; fail closed at 9223372036854775806",
        },
        "human_adjudication": "PENDING_INDEPENDENT_REVIEW",
        "authority_receipt": {
            "format": "ANAR-POSTGRES-FINALIZATION-WITNESS-V1",
            "sha256": results["primary_witness_sha256"],
            "witness": results["primary_finalization_witness"],
            "cross_language_decision_receipt": "NOT_YET_PROVEN",
        },
        "action_payload": action_payload,
        "action_payload_hash": action_payload_sha256,
        "action_integrity": {
            "payload_hash_algorithm": "lowercase SHA-256 over UTF-8 sorted-key no-whitespace JSON",
            "grant_target_digest_compared_under_row_lock": True,
            "grant_effect_scope_hash_compared_under_row_lock": True,
            "mutated_payload_denied": True,
            "concurrent_grant_reuse_denied": True,
        },
        "external_action_receipt": "NOT_APPLICABLE_NO_EXTERNAL_ACTION",
        "payment_evidence": "NOT_APPLICABLE_AUTHORITY_SUBSTRATE",
        "attribution_result": "NOT_APPLICABLE_AUTHORITY_SUBSTRATE",
        "fee_calculation": "NOT_APPLICABLE_AUTHORITY_SUBSTRATE",
        "reconciliation_result": results["final_database_state"],
        "all_encountered_denials": sorted(results["denials"]),
        "all_unknowns": [
            "same SQLx transaction using the production Rust persistence adapter is not yet proven",
            "Rust receipt bytes and PostgreSQL durable receipt bytes are not yet cross-language identical",
            "live Vault lease acquisition and pool rotation are not contacted or proven",
            "production deployment, security review, restore proof, and live HTTP proof remain open",
        ],
        "final_state": {
            "milestone": "M10_NOT_READY",
            "production_authority": "NONE",
            "production_mutated": False,
            "release_state": "HOLD_NOT_READY",
        },
    }
    packet_path = output_dir / "authority-evidence-packet.json"
    packet_path.write_bytes(canonical_bytes(packet) + b"\n")

    receipt_body = {
        "schema": "anarchi.transition-receipt.v1",
        "transition": "PHASE-0-POSTGRES-SAFE-PAUSE-REHEARSAL",
        "source_commit": source_commit,
        "previous_receipt_sha256": PREVIOUS_RECEIPT_SHA256,
        "frozen_spec_sha256": SPEC_SHA256,
        "rehearsal_run_id": run_id,
        "canonicalization": "UTF-8_SORTED-KEYS-NO-WHITESPACE-V1",
        "artifact_hashes": {
            **evidence_hashes,
            str(packet_path.relative_to(ROOT)): sha256_file(packet_path),
        },
        "verification": results["checks"],
        "authority_state": {"production_authority": "NONE", "production_mutated": False},
        "open_items": packet["all_unknowns"],
        "teardown_passed": True,
    }
    receipt_hash = sha256_bytes(canonical_bytes(receipt_body))
    receipt = {**receipt_body, "receipt_hash_sha256": receipt_hash}
    receipt_path = output_dir / "transition-receipt.json"
    receipt_path.write_bytes(canonical_bytes(receipt) + b"\n")

    artifact_manifest = {
        "schema": "anarchi.artifact-hash-manifest.v1",
        "self_hash_excluded": True,
        "artifacts": {
            **receipt_body["artifact_hashes"],
            str(receipt_path.relative_to(ROOT)): sha256_file(receipt_path),
        },
    }
    manifest_path = output_dir / "artifact-hashes.json"
    manifest_path.write_bytes(canonical_bytes(artifact_manifest) + b"\n")
    verification = command(
        [sys.executable, str(ROOT / "tools/rehearsal/verify_evidence_packet.py"), str(output_dir)],
        env=os.environ.copy(),
    )
    verification_report = json.loads(verification.stdout.decode("utf-8"))
    if verification_report.get("result") != "PASS":
        raise RehearsalFailure(f"emitted evidence packet did not verify: {verification_report}")
    if args.development:
        print(
            json.dumps(
                {
                    "development_results": results,
                    "packet_construction": "PASS",
                    "offline_packet_verification": verification_report,
                },
                indent=2,
                sort_keys=True,
            )
        )
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
