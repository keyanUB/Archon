#!/usr/bin/env python3
"""Focused tests for the host-side PGACS evaluator isolation boundary."""

from __future__ import annotations

import importlib.util
import platform
import subprocess
import tempfile
import unittest
from pathlib import Path
from types import ModuleType


EVALUATOR_PATH = Path(__file__).with_name("evaluate_zip_inspector.py")


def load_evaluator() -> ModuleType:
    spec = importlib.util.spec_from_file_location("pgacs_zip_evaluator", EVALUATOR_PATH)
    if spec is None or spec.loader is None:
        raise RuntimeError("cannot load evaluator")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def sandbox_exec_available() -> bool:
    if platform.system() != "Darwin" or not Path("/usr/bin/sandbox-exec").exists():
        return False
    completed = subprocess.run(
        [
            "/usr/bin/sandbox-exec",
            "-p",
            "(version 1) (allow default)",
            "/usr/bin/true",
        ],
        capture_output=True,
        check=False,
    )
    return completed.returncode == 0


class EvaluatorPolicyTest(unittest.TestCase):
    def test_macos_profile_denies_network_and_limits_writes(self) -> None:
        evaluator = load_evaluator()
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            implementation = root / "zip_inspector.py"
            implementation.write_text("", encoding="utf-8")
            sandbox_root = root / "sandbox"
            sandbox_root.mkdir()

            _, mode = evaluator.macos_sandbox_command(
                implementation, sandbox_root / "result.json", sandbox_root
            )
            profile = (sandbox_root / "profile.sb").read_text(encoding="utf-8")

            self.assertEqual(mode, "macos-sandbox-exec")
            self.assertIn("(deny default)", profile)
            self.assertIn("(deny network*)", profile)
            self.assertIn(f'(literal "{implementation.as_posix()}")', profile)
            self.assertIn(f'(allow file-write* (subpath "{sandbox_root.as_posix()}"))', profile)


@unittest.skipUnless(
    sandbox_exec_available(),
    "macOS rejected nested sandbox-exec in this environment",
)
class EvaluatorIsolationTest(unittest.TestCase):
    def test_generated_module_cannot_write_beside_its_input(self) -> None:
        evaluator = load_evaluator()
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            implementation = root / "zip_inspector.py"
            escaped = root / "escaped.txt"
            implementation.write_text(
                "from pathlib import Path\n"
                "Path(__file__).with_name('escaped.txt').write_text('escaped')\n",
                encoding="utf-8",
            )

            with self.assertRaisesRegex(RuntimeError, "isolated evaluator failed"):
                evaluator.evaluate_isolated(implementation, root / "result.json")
            self.assertFalse(escaped.exists())

    def test_hanging_generated_module_is_terminated(self) -> None:
        evaluator = load_evaluator()
        evaluator.WORKER_TIMEOUT_SECONDS = 1
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            implementation = root / "zip_inspector.py"
            implementation.write_text("while True:\n    pass\n", encoding="utf-8")

            with self.assertRaisesRegex(RuntimeError, "exceeded 1 seconds"):
                evaluator.evaluate_isolated(implementation, root / "result.json")


if __name__ == "__main__":
    unittest.main()
