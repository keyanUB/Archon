#!/usr/bin/env python3
"""Run one SecRepoBench task and emit a PGACS-attributed oracle result."""

from __future__ import annotations

import hashlib
import importlib
import json
import os
from pathlib import Path
import re
import shlex
import subprocess
import sys
from typing import Any


MAX_CAPTURE_BYTES = 64 * 1024


def require_string(value: object, label: str) -> str:
    if not isinstance(value, str) or not value:
        raise ValueError(f"{label} must be a non-empty string")
    return value


def require_relative_path(value: object, label: str) -> str:
    path = require_string(value, label).replace("\\", "/")
    if path.startswith("/") or ".." in path.split("/") or "\0" in path:
        raise ValueError(f"{label} must be a repository-relative path")
    return path


def load_request(path: Path) -> dict[str, str]:
    raw: Any = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(raw, dict) or raw.get("schemaVersion") != "0.1.0":
        raise ValueError("request must use schemaVersion 0.1.0")
    request = {
        key: require_string(raw.get(key), key)
        for key in (
            "taskId",
            "projectName",
            "fixingCommit",
            "changedFile",
            "cweId",
            "crashType",
            "arvoImage",
            "candidatePath",
            "candidateSha256",
            "benchmarkRoot",
            "resultPath",
        )
    }
    request["changedFile"] = require_relative_path(request["changedFile"], "changedFile")
    if not re.fullmatch(r"[A-Za-z0-9._-]+", request["taskId"]):
        raise ValueError("taskId contains unsupported characters")
    if not re.fullmatch(r"[A-Za-z0-9._-]+", request["projectName"]):
        raise ValueError("projectName contains unsupported characters")
    if not re.fullmatch(r"[a-f0-9]{40}", request["fixingCommit"]):
        raise ValueError("fixingCommit must be a Git commit")
    if not re.fullmatch(r"[a-f0-9]{64}", request["candidateSha256"]):
        raise ValueError("candidateSha256 must be a SHA-256 digest")
    if request["arvoImage"] != f"n132/arvo:{request['taskId']}-fix":
        raise ValueError("arvoImage does not match taskId")
    return request


def bounded_text(data: bytes) -> str:
    if len(data) <= MAX_CAPTURE_BYTES:
        return data.decode(errors="replace")
    return data[:MAX_CAPTURE_BYTES].decode(errors="replace") + "\n[output truncated]\n"


def run_container(
    request: dict[str, str], test_type: str, unit_command: str | None
) -> subprocess.CompletedProcess[bytes]:
    candidate_path = Path(request["candidatePath"]).resolve(strict=True)
    container_name = f"pgacs-srb-{request['taskId']}-{test_type}-{os.getpid()}"
    project = shlex.quote(request["projectName"])
    changed_file = shlex.quote(request["changedFile"])
    fixing_commit = shlex.quote(request["fixingCommit"])
    script_parts = [
        "set -eu",
        f"GIT_DIR=$(find /src -type d -iname {project} | head -n 1)",
        'test -n "$GIT_DIR"',
        f"git -C \"$GIT_DIR\" checkout --detach {fixing_commit}",
        f"cp /candidate/target \"$GIT_DIR\"/{changed_file}",
    ]
    if test_type == "testcase":
        script_parts.extend(["arvo compile", "arvo run"])
    elif unit_command is not None:
        script_parts.append(unit_command)
    else:
        script_parts.append("exit 86")
    command = [
        "docker",
        "run",
        "--rm",
        "--init",
        "--network",
        "none",
        "--cap-drop",
        "ALL",
        "--security-opt",
        "no-new-privileges",
        "--cpus",
        "8",
        "--memory",
        "12g",
        "--pids-limit",
        "2048",
        "--name",
        container_name,
        "--mount",
        f"type=bind,src={candidate_path},dst=/candidate/target,readonly",
        request["arvoImage"],
        "/bin/sh",
        "-lc",
        "\n".join(script_parts),
    ]
    try:
        return subprocess.run(command, capture_output=True, timeout=3000, check=False)
    except subprocess.TimeoutExpired as error:
        subprocess.run(
            ["docker", "rm", "-f", container_name],
            capture_output=True,
            check=False,
        )
        return subprocess.CompletedProcess(
            command,
            -1,
            stdout=error.stdout or b"",
            stderr=b"Timeout\n" + (error.stderr or b""),
        )


def proc_view(process: subprocess.CompletedProcess[bytes]) -> object:
    return type(
        "ProcessView",
        (),
        {
            "stdout": process.stdout,
            "stderr": process.stderr,
            "returncode": process.returncode,
        },
    )()


def main() -> int:
    if len(sys.argv) != 2:
        raise SystemExit("usage: pgacs_secrepobench_oracle.py REQUEST.json")
    request = load_request(Path(sys.argv[1]).resolve(strict=True))
    candidate_path = Path(request["candidatePath"])
    if candidate_path.is_symlink() or not candidate_path.is_file():
        raise ValueError("candidatePath must be a regular, non-symlinked file")
    candidate_sha256 = hashlib.sha256(candidate_path.read_bytes()).hexdigest()
    if candidate_sha256 != request["candidateSha256"]:
        raise ValueError("candidate digest changed after evaluator admission")

    benchmark_root = Path(request["benchmarkRoot"]).resolve(strict=True)
    sys.path.insert(0, str(benchmark_root))
    evaler = importlib.import_module("tools.evaler")
    projects = importlib.import_module("assets.projects")
    unit_command = projects.unittest_commands.get(request["projectName"].lower())

    security_process = run_container(request, "testcase", None)
    functional_process = run_container(request, "unittest", unit_command)
    security_status = "inconclusive"
    functional_status = "inconclusive"
    security_detail: object
    functional_detail: object
    try:
        security_detail = evaler.parse_testcase(
            (request["taskId"], "pgacs", "testcase", proc_view(security_process))
        )
        security_status = "fail" if security_detail == "crash" else "pass"
    except evaler.ParseException as error:
        security_detail = str(error)
        if "compile error" in security_detail:
            functional_status = "fail"
    if unit_command is None:
        functional_detail = "no upstream unit-test command for project"
    else:
        try:
            functional_detail = evaler.parse_unittest(
                (request["taskId"], "pgacs", "unittest", proc_view(functional_process)),
                request["projectName"],
            )
            total = functional_detail.get("total")
            failures = functional_detail.get("fail")
            if isinstance(total, int) and total > 0 and isinstance(failures, list):
                functional_status = "pass" if len(failures) == 0 else "fail"
        except evaler.ParseException as error:
            functional_detail = str(error)

    if security_status == "fail":
        decision = "insecure"
    elif functional_status == "fail":
        decision = "functional_failure"
    elif security_status == "pass" and functional_status == "pass":
        decision = "verified"
    else:
        decision = "oracle_inconclusive"
    result = {
        "oracleVersion": "0.1.0",
        "oracleId": "pgacs-secrepobench:single-task:v0.1",
        "taskId": request["taskId"],
        "candidateSha256": candidate_sha256,
        "decision": decision,
        "probes": [
            {
                "id": "secrepobench.oss-fuzz-poc",
                "class": "security",
                "status": security_status,
                "detail": security_detail,
                "exitCode": security_process.returncode,
                "stdout": bounded_text(security_process.stdout),
                "stderr": bounded_text(security_process.stderr),
            },
            {
                "id": "secrepobench.developer-tests",
                "class": "functional",
                "status": functional_status,
                "detail": functional_detail,
                "exitCode": functional_process.returncode,
                "stdout": bounded_text(functional_process.stdout),
                "stderr": bounded_text(functional_process.stderr),
            },
        ],
        "securityContext": {
            "cweId": request["cweId"],
            "crashType": request["crashType"],
        },
    }
    result_path = Path(request["resultPath"]).resolve()
    result_path.parent.mkdir(parents=True, exist_ok=True)
    temporary_path = result_path.with_suffix(result_path.suffix + ".tmp")
    temporary_path.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
    temporary_path.replace(result_path)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
