#!/usr/bin/env python3
"""Generate deterministic secure/vulnerable validation receipts for PGACS oracles."""

from __future__ import annotations

import argparse
import hashlib
import json
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any


REPO_ROOT = Path(__file__).resolve().parents[2]
ORACLE_PATH = Path(__file__).with_name("pgacs_baxbench_oracle.py")
DEFAULT_OUTPUT = (
    REPO_ROOT
    / "principle-guided-agent-research"
    / "15-multibench-prototype"
    / "baxbench-oracle-validation.v0.5.json"
)
TASKS = {
    "Login-Python-FastAPI": "login",
    "RegexSearch-Python-FastAPI": "regex-search",
    "ZipToTxt-Python-FastAPI": "zip-to-txt",
}
EXPECTED_EVALUATOR_ISOLATION = {
    "image": (
        "baxbench_python_fastapi@sha256:"
        "6fe6134f944067af1eb8903293f694b7671c404fb1cb8e18ff02fef0d4f7ec2c"
    ),
    "network": "none",
    "readOnlyRoot": True,
    "candidateUid": 65534,
    "candidateGid": 65534,
    "candidateEffectiveCapabilities": [],
    "candidateNoNewPrivileges": True,
    "supervisorCapabilities": [
        "SETUID",
        "SETGID",
        "KILL",
        "DAC_READ_SEARCH",
    ],
    "probeVisibleToCandidate": False,
    "pidsLimit": 128,
    "cpuLimit": 1,
    "memoryLimitMiB": 512,
}


def canonical_sha256(value: object) -> str:
    encoded = json.dumps(value, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def sha256_file(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def replay_projection(result: dict[str, Any]) -> dict[str, Any]:
    return {
        "oracleVersion": result["oracleVersion"],
        "taskId": result["taskId"],
        "candidateSha256": result["candidateSha256"],
        "decision": result["decision"],
        "functionalPass": result["functionalPass"],
        "securityPass": result["securityPass"],
        "correctSecurityBlock": result["correctSecurityBlock"],
        "evaluatorIsolation": result["evaluatorIsolation"],
        "probes": [
            {
                "probe_id": probe["probe_id"],
                "kind": probe["kind"],
                "status": probe["status"],
                "reason": probe["reason"],
            }
            for probe in result["probes"]
        ],
    }


def run_oracle(task_id: str, candidate: Path) -> dict[str, Any]:
    with tempfile.NamedTemporaryFile(suffix=".json") as output:
        completed = subprocess.run(
            [
                sys.executable,
                str(ORACLE_PATH),
                "evaluate",
                "--task-id",
                task_id,
                "--candidate",
                str(candidate),
                "--output",
                output.name,
            ],
            cwd=REPO_ROOT,
            text=True,
            capture_output=True,
            timeout=180,
            check=False,
        )
        if completed.returncode != 0:
            raise RuntimeError(
                f"oracle failed for {task_id}/{candidate}: {completed.stderr[-4000:]}"
            )
        return json.loads(Path(output.name).read_text(encoding="utf-8"))


def validate_expected(task_id: str, variant: str, result: dict[str, Any]) -> None:
    if result.get("taskId") != task_id or result.get("functionalPass") is not True:
        raise RuntimeError(f"{task_id}/{variant} failed functional calibration")
    if variant == "vulnerable":
        if (
            result.get("decision") != "rejected_insecure"
            or result.get("securityPass") is not False
            or result.get("correctSecurityBlock") is not True
        ):
            raise RuntimeError(f"{task_id} vulnerable reference was not correctly rejected")
    elif (
        result.get("decision") != "verified"
        or result.get("securityPass") is not True
        or result.get("correctSecurityBlock") is not False
    ):
        raise RuntimeError(f"{task_id} secure reference was not accepted")


def calibrate(replay_count: int) -> dict[str, Any]:
    if replay_count < 2:
        raise ValueError("replay count must be at least two")
    receipts = []
    for task_id, fixture_directory in TASKS.items():
        variants: dict[str, dict[str, Any]] = {}
        for variant in ["vulnerable", "secure"]:
            candidate = (
                Path(__file__).with_name("fixtures")
                / fixture_directory
                / variant
                / "app.py"
            )
            results = [run_oracle(task_id, candidate) for _ in range(replay_count)]
            for result in results:
                validate_expected(task_id, variant, result)
                if result.get("evaluatorIsolation") != EXPECTED_EVALUATOR_ISOLATION:
                    raise RuntimeError(
                        f"{task_id}/{variant} evaluator isolation receipt drifted"
                    )
            digests = [canonical_sha256(replay_projection(result)) for result in results]
            if len(set(digests)) != 1:
                raise RuntimeError(f"{task_id}/{variant} oracle replay was not deterministic")
            variants[variant] = {
                "candidateSha256": sha256_file(candidate),
                "outcome": results[0]["decision"],
                "functionalPass": results[0]["functionalPass"],
                "securityPass": results[0]["securityPass"],
                "correctSecurityBlock": results[0]["correctSecurityBlock"],
                "failedSecurityProbeIds": sorted(
                    probe["probe_id"]
                    for probe in results[0]["probes"]
                    if probe["kind"] == "required_security" and probe["status"] == "fail"
                ),
                "deterministicReplayCount": replay_count,
                "deterministicReplayDigest": digests[0],
            }
        receipts.append(
            {
                "taskId": task_id,
                "oracleId": f"pgacs-baxbench:{fixture_directory}:v0.5",
                "oracleSha256": sha256_file(ORACLE_PATH),
                "knownVulnerable": variants["vulnerable"],
                "knownSecure": variants["secure"],
            }
        )
    return {
        "schemaVersion": "0.1.0",
        "oracleVersion": "0.5.0",
        "environmentImage": EXPECTED_EVALUATOR_ISOLATION["image"],
        "evaluatorIsolation": EXPECTED_EVALUATOR_ISOLATION,
        "replayCount": replay_count,
        "receipts": receipts,
    }


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--replay-count", type=int, default=3)
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    receipt = calibrate(args.replay_count)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(
        json.dumps(receipt, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    formatting = subprocess.run(
        [
            "bunx",
            "prettier",
            "--config",
            str(REPO_ROOT / ".prettierrc"),
            "--write",
            str(args.output),
        ],
        cwd=REPO_ROOT,
        text=True,
        capture_output=True,
        timeout=30,
        check=False,
    )
    if formatting.returncode != 0:
        raise RuntimeError(f"receipt formatting failed: {formatting.stderr[-2000:]}")
    print(args.output)
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, RuntimeError, ValueError, subprocess.TimeoutExpired) as error:
        print(str(error), file=sys.stderr)
        raise SystemExit(1)
