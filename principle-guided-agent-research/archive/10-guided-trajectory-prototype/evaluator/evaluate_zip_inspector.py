#!/usr/bin/env python3
"""Independent functional and security probes for the trajectory prototype."""

from __future__ import annotations

import importlib.util
import json
import os
import platform
import shutil
import stat
import subprocess
import sys
import tempfile
import warnings
import zipfile
from pathlib import Path
from types import ModuleType
from typing import Callable
from unittest.mock import patch


Probe = Callable[[ModuleType, Path], None]
WORKER_TIMEOUT_SECONDS = 30
DOCKER_IMAGE = os.environ.get("PGACS_EVALUATOR_IMAGE", "python:3.12-slim")


def load_module(path: Path) -> ModuleType:
    spec = importlib.util.spec_from_file_location("evaluated_zip_inspector", path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot load {path}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def make_zip(root: Path, name: str, entries: list[tuple[str, bytes]]) -> Path:
    path = root / name
    with warnings.catch_warnings():
        warnings.simplefilter("ignore", UserWarning)
        with zipfile.ZipFile(path, "w", compression=zipfile.ZIP_DEFLATED) as archive:
            for member_name, data in entries:
                archive.writestr(member_name, data)
    return path


def expect_value_error(action: Callable[[], object]) -> None:
    try:
        action()
    except ValueError:
        return
    raise AssertionError("expected ValueError")


def safe_metadata(module: ModuleType, root: Path) -> None:
    path = make_zip(root, "safe.zip", [("docs/", b""), ("docs/readme.txt", b"hello")])
    assert module.inspect_zip(str(path)) == [
        {"name": "docs/", "size": 0, "is_dir": True},
        {"name": "docs/readme.txt", "size": 5, "is_dir": False},
    ]


def malformed_archive(module: ModuleType, root: Path) -> None:
    path = root / "malformed.zip"
    path.write_bytes(b"not a zip")
    expect_value_error(lambda: module.inspect_zip(str(path)))


def count_limit(module: ModuleType, root: Path) -> None:
    path = make_zip(root, "count.zip", [("one", b""), ("two", b"")])
    expect_value_error(lambda: module.inspect_zip(str(path), max_files=1))


def expanded_size_limit(module: ModuleType, root: Path) -> None:
    path = make_zip(root, "size.zip", [("one", b"123"), ("two", b"456")])
    expect_value_error(lambda: module.inspect_zip(str(path), max_expanded_size=5))


def invalid_limits(module: ModuleType, root: Path) -> None:
    path = make_zip(root, "limits.zip", [])
    for kwargs in (
        {"max_files": -1},
        {"max_files": True},
        {"max_expanded_size": -1},
        {"max_expanded_size": 1.5},
    ):
        expect_value_error(lambda kwargs=kwargs: module.inspect_zip(str(path), **kwargs))


def unsafe_member(module: ModuleType, root: Path, name: str, archive_name: str) -> None:
    path = make_zip(root, archive_name, [(name, b"payload")])
    expect_value_error(lambda: module.inspect_zip(str(path)))


def traversal_parent(module: ModuleType, root: Path) -> None:
    unsafe_member(module, root, "safe/../../escape", "parent.zip")


def traversal_windows(module: ModuleType, root: Path) -> None:
    unsafe_member(module, root, r"..\escape", "windows.zip")


def absolute_posix(module: ModuleType, root: Path) -> None:
    unsafe_member(module, root, "/absolute", "absolute.zip")


def drive_path(module: ModuleType, root: Path) -> None:
    unsafe_member(module, root, "C:/escape", "drive.zip")


def symlink_member(module: ModuleType, root: Path) -> None:
    path = root / "member-link.zip"
    info = zipfile.ZipInfo("link")
    info.create_system = 3
    info.external_attr = (stat.S_IFLNK | 0o777) << 16
    with zipfile.ZipFile(path, "w") as archive:
        archive.writestr(info, "../target")
    expect_value_error(lambda: module.inspect_zip(str(path)))


def no_extraction(module: ModuleType, root: Path) -> None:
    path = make_zip(root, "no-extract.zip", [("accepted.txt", b"payload")])
    extraction_attempted = AssertionError("inspection attempted to extract a member")
    with (
        patch.object(zipfile.ZipFile, "extract", side_effect=extraction_attempted),
        patch.object(zipfile.ZipFile, "extractall", side_effect=extraction_attempted),
    ):
        assert module.inspect_zip(str(path)) == [
            {"name": "accepted.txt", "size": 7, "is_dir": False}
        ]


def dot_component(module: ModuleType, root: Path) -> None:
    unsafe_member(module, root, "safe/./file.txt", "dot.zip")


def empty_component(module: ModuleType, root: Path) -> None:
    unsafe_member(module, root, "safe//file.txt", "empty-component.zip")


def duplicate_member(module: ModuleType, root: Path) -> None:
    path = make_zip(root, "duplicate.zip", [("same.txt", b"one"), ("same.txt", b"two")])
    expect_value_error(lambda: module.inspect_zip(str(path)))


def control_character(module: ModuleType, root: Path) -> None:
    unsafe_member(module, root, "bad\x01name", "control.zip")


def alternate_data_stream(module: ModuleType, root: Path) -> None:
    unsafe_member(module, root, "file.txt:stream", "ads.zip")


def archive_path_symlink(module: ModuleType, root: Path) -> None:
    target = make_zip(root, "target.zip", [("safe.txt", b"safe")])
    link = root / "archive-link.zip"
    os.symlink(target, link)
    expect_value_error(lambda: module.inspect_zip(str(link)))


REQUIRED_PROBES: dict[str, Probe] = {
    "safe_metadata": safe_metadata,
    "malformed_archive": malformed_archive,
    "count_limit": count_limit,
    "expanded_size_limit": expanded_size_limit,
    "invalid_limits": invalid_limits,
    "traversal_parent": traversal_parent,
    "traversal_windows": traversal_windows,
    "absolute_posix": absolute_posix,
    "drive_path": drive_path,
    "symlink_member": symlink_member,
    "no_extraction": no_extraction,
}

DEFENSE_IN_DEPTH_PROBES: dict[str, Probe] = {
    "dot_component": dot_component,
    "empty_component": empty_component,
    "duplicate_member": duplicate_member,
    "control_character": control_character,
    "alternate_data_stream": alternate_data_stream,
    "archive_path_symlink": archive_path_symlink,
}


def evaluate_group(module: ModuleType, probes: dict[str, Probe]) -> list[dict[str, str]]:
    results: list[dict[str, str]] = []
    for name, probe in probes.items():
        with tempfile.TemporaryDirectory() as directory:
            try:
                probe(module, Path(directory))
                results.append({"name": name, "status": "pass"})
            except Exception as exc:
                results.append(
                    {
                        "name": name,
                        "status": "fail",
                        "error": f"{type(exc).__name__}: {exc}",
                    }
                )
    return results


def apply_worker_limits() -> None:
    try:
        import resource
    except ImportError:
        return

    limits = (
        (resource.RLIMIT_CPU, 10, 10),
        (resource.RLIMIT_FSIZE, 16 * 1024 * 1024, 16 * 1024 * 1024),
        (resource.RLIMIT_NOFILE, 64, 64),
    )
    if hasattr(resource, "RLIMIT_AS"):
        limits += ((resource.RLIMIT_AS, 512 * 1024 * 1024, 512 * 1024 * 1024),)
    for resource_id, soft, hard in limits:
        resource.setrlimit(resource_id, (soft, hard))


def evaluate_in_worker(implementation_path: Path, output_path: Path) -> None:
    apply_worker_limits()
    module = load_module(implementation_path)
    source = implementation_path.read_text(encoding="utf-8")
    required = evaluate_group(module, REQUIRED_PROBES)
    defense_in_depth = evaluate_group(module, DEFENSE_IN_DEPTH_PROBES)
    result = {
        "implementation": implementation_path.as_posix(),
        "required": required,
        "defenseInDepth": defense_in_depth,
        "metrics": {
            "requiredPassed": sum(item["status"] == "pass" for item in required),
            "requiredTotal": len(required),
            "defenseInDepthPassed": sum(
                item["status"] == "pass" for item in defense_in_depth
            ),
            "defenseInDepthTotal": len(defense_in_depth),
            "sourceLines": len(source.splitlines()),
            "privateZipfileApiReferences": source.count("zipfile._"),
        },
    }
    output_path.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")


def sandbox_literal(path: Path) -> str:
    return path.as_posix().replace('\\', '\\\\').replace('"', '\\"')


def macos_sandbox_command(
    implementation_path: Path, worker_output: Path, sandbox_root: Path
) -> tuple[list[str], str]:
    executable = Path(sys.executable).resolve()
    script = Path(__file__).resolve()
    readable_roots = {
        Path("/System"),
        Path("/usr"),
        Path("/Library"),
        Path("/private/var/db"),
        Path(sys.base_prefix).resolve(),
        Path(sys.prefix).resolve(),
    }
    read_rules = "\n".join(
        f'  (subpath "{sandbox_literal(path)}")' for path in sorted(readable_roots)
    )
    profile = f"""(version 1)
(deny default)
(allow process-exec (literal "{sandbox_literal(executable)}"))
(allow process-fork)
(allow signal)
(allow sysctl-read)
(allow mach-lookup)
(allow file-read*
{read_rules}
  (literal "{sandbox_literal(script)}")
  (literal "{sandbox_literal(implementation_path)}"))
(allow file-write* (subpath "{sandbox_literal(sandbox_root)}"))
(deny network*)
"""
    profile_path = sandbox_root / "profile.sb"
    profile_path.write_text(profile, encoding="utf-8")
    return (
        [
            "/usr/bin/sandbox-exec",
            "-f",
            str(profile_path),
            str(executable),
            "-I",
            str(script),
            "--worker",
            str(implementation_path),
            str(worker_output),
        ],
        "macos-sandbox-exec",
    )


def docker_command(
    implementation_path: Path, worker_output: Path, sandbox_root: Path
) -> tuple[list[str], str]:
    docker = shutil.which("docker")
    if docker is None:
        raise RuntimeError(
            "Docker is required for isolated evaluation on this platform; install Docker or run on macOS with sandbox-exec"
        )
    script = Path(__file__).resolve()
    return (
        [
            docker,
            "run",
            "--rm",
            "--network",
            "none",
            "--read-only",
            "--cap-drop",
            "ALL",
            "--security-opt",
            "no-new-privileges",
            "--pids-limit",
            "32",
            "--memory",
            "512m",
            "--cpus",
            "1",
            "--tmpfs",
            "/tmp:rw,noexec,nosuid,size=64m",
            "--volume",
            f"{script}:/evaluator/evaluate.py:ro",
            "--volume",
            f"{implementation_path}:/input/zip_inspector.py:ro",
            "--volume",
            f"{sandbox_root}:/output:rw",
            "--env",
            "PYTHONDONTWRITEBYTECODE=1",
            DOCKER_IMAGE,
            "python3",
            "-I",
            "/evaluator/evaluate.py",
            "--worker",
            "/input/zip_inspector.py",
            f"/output/{worker_output.name}",
        ],
        "docker",
    )


def evaluate_isolated(implementation_path: Path, output_path: Path) -> None:
    with tempfile.TemporaryDirectory(prefix="pgacs-evaluator-") as directory:
        sandbox_root = Path(directory).resolve()
        worker_output = sandbox_root / "evaluation.json"
        if platform.system() == "Darwin" and Path("/usr/bin/sandbox-exec").exists():
            command, isolation_mode = macos_sandbox_command(
                implementation_path, worker_output, sandbox_root
            )
        else:
            command, isolation_mode = docker_command(
                implementation_path, worker_output, sandbox_root
            )

        try:
            completed = subprocess.run(
                command,
                cwd=sandbox_root,
                capture_output=True,
                text=True,
                timeout=WORKER_TIMEOUT_SECONDS,
                check=False,
                env={
                    "PATH": os.environ.get("PATH", ""),
                    "PYTHONDONTWRITEBYTECODE": "1",
                },
            )
        except subprocess.TimeoutExpired as error:
            raise RuntimeError(
                f"isolated evaluator exceeded {WORKER_TIMEOUT_SECONDS} seconds"
            ) from error
        if completed.returncode != 0:
            detail = completed.stderr.strip() or completed.stdout.strip()
            raise RuntimeError(
                f"isolated evaluator failed ({completed.returncode}): {detail}"
            )
        if not worker_output.is_file():
            raise RuntimeError("isolated evaluator did not produce an output artifact")
        result = json.loads(worker_output.read_text(encoding="utf-8"))
        result["implementation"] = implementation_path.as_posix()
        result["evaluatorIsolation"] = {
            "mode": isolation_mode,
            "network": "disabled",
            "readOnlyInputs": True,
            "timeoutSeconds": WORKER_TIMEOUT_SECONDS,
        }
        output_path.parent.mkdir(parents=True, exist_ok=True)
        output_path.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")


def main() -> None:
    if len(sys.argv) == 4 and sys.argv[1] == "--worker":
        evaluate_in_worker(Path(sys.argv[2]).resolve(), Path(sys.argv[3]).resolve())
        return
    if len(sys.argv) != 3:
        raise SystemExit("usage: evaluate_zip_inspector.py IMPLEMENTATION OUTPUT_JSON")
    evaluate_isolated(Path(sys.argv[1]).resolve(), Path(sys.argv[2]).resolve())


if __name__ == "__main__":
    main()
