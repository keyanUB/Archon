from __future__ import annotations

import importlib.util
import json
import tempfile
import unittest
from pathlib import Path
from types import ModuleType
from unittest.mock import patch


def load_runner() -> ModuleType:
    path = Path(__file__).with_name("run_pgacs_baxbench_pilot.py")
    spec = importlib.util.spec_from_file_location("baxbench_runner", path)
    if spec is None or spec.loader is None:
        raise RuntimeError("Could not load BaxBench runner")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


RUNNER = load_runner()


class TaskAdapterIntegrationTests(unittest.TestCase):
    def test_registry_contains_only_the_three_public_prototype_tasks(self) -> None:
        manifests = RUNNER.task_manifests()
        self.assertEqual(
            set(manifests),
            {
                "Login-Python-FastAPI",
                "RegexSearch-Python-FastAPI",
                "ZipToTxt-Python-FastAPI",
            },
        )
        serialized = json.dumps(manifests)
        self.assertNotIn("functional_tests", serialized)
        self.assertNotIn("security_tests", serialized)
        self.assertNotIn("exploits", serialized)

    def test_initialize_run_uses_manifest_workspace_adapter(self) -> None:
        manifest = RUNNER.task_manifests()["Login-Python-FastAPI"]
        contract = RUNNER.load_json(RUNNER.CONTRACT_PATH)
        task = {"task_id": "Login-Python-FastAPI"}
        with tempfile.TemporaryDirectory(prefix="pgacs-bax-runner-") as temporary:
            original_run_root = RUNNER.RUN_ROOT
            RUNNER.RUN_ROOT = Path(temporary)
            try:
                root, workspace = RUNNER.initialize_run(
                    contract,
                    "archon",
                    task,
                    manifest["contract"]["prompt"],
                    force=False,
                )
            finally:
                RUNNER.RUN_ROOT = original_run_root

            receipt = json.loads(
                (root / "workspace-preparation.json").read_text(encoding="utf-8")
            )
            self.assertEqual(receipt["adapterId"], "baxbench-fastapi-v0.1")
            self.assertEqual(
                (workspace / "TASK.md").read_text(encoding="utf-8"),
                manifest["contract"]["prompt"],
            )

    def test_manifest_provenance_must_match_the_active_contract(self) -> None:
        registry = RUNNER.load_json(RUNNER.TASK_MANIFESTS_PATH)
        registry["tasks"][0]["provenance"]["evaluatorRevision"] = "0" * 40
        contract = RUNNER.load_json(RUNNER.CONTRACT_PATH)
        task = {"task_id": "Login-Python-FastAPI"}
        prompt = registry["tasks"][0]["contract"]["prompt"]
        with tempfile.TemporaryDirectory(prefix="pgacs-bax-manifest-") as temporary:
            manifest_path = Path(temporary) / "manifests.json"
            manifest_path.write_text(json.dumps(registry), encoding="utf-8")
            original_path = RUNNER.TASK_MANIFESTS_PATH
            RUNNER.TASK_MANIFESTS_PATH = manifest_path
            try:
                with self.assertRaisesRegex(RuntimeError, "evaluatorRevision mismatch"):
                    RUNNER.validate_task_manifest(contract, task, prompt)
            finally:
                RUNNER.TASK_MANIFESTS_PATH = original_path

    def test_evaluation_regenerates_adapter_plan_instead_of_loading_saved_command(self) -> None:
        contract = {
            "conditions": [
                {
                    "id": "direct",
                    "mode": "direct",
                    "evaluatorModelName": "direct-model",
                }
            ],
            "cohort": {
                "environmentId": "Python-FastAPI",
                "tasks": [
                    {
                        "taskId": "Login-Python-FastAPI",
                        "scenarioId": "Login",
                    }
                ],
            },
        }
        with tempfile.TemporaryDirectory(prefix="pgacs-bax-evaluate-") as temporary:
            root = Path(temporary)
            evaluator = root / "evaluator"
            python = evaluator / ".venv/bin/python"
            python.parent.mkdir(parents=True)
            python.write_text("fixture", encoding="utf-8")
            original_run_root = RUNNER.RUN_ROOT
            RUNNER.RUN_ROOT = root
            workspace = RUNNER.task_run_root(
                "direct", "Login-Python-FastAPI"
            ) / "workspace"
            workspace.mkdir(parents=True)
            result_path = root / "fresh-result.json"

            def prepare(arguments: list[str]) -> dict[str, object]:
                self.assertEqual(arguments[0], "stage")
                return {
                    "command": ["fresh-adapter-command"],
                    "cwd": str(root),
                    "timeoutSeconds": 30,
                    "resultPath": str(result_path),
                }

            def execute(
                command: list[str], **_: object
            ) -> object:
                self.assertEqual(command, ["fresh-adapter-command"])
                result_path.write_text("{}", encoding="utf-8")
                return RUNNER.subprocess.CompletedProcess(command, 0, "", "")

            try:
                with patch.object(RUNNER, "run_task_adapter", side_effect=prepare), patch.object(
                    RUNNER, "run_command", side_effect=execute
                ):
                    RUNNER.run_official_evaluator(
                        contract,
                        evaluator,
                        {"Login-Python-FastAPI"},
                        {"direct"},
                    )
            finally:
                RUNNER.RUN_ROOT = original_run_root


class ConditionLifecycleTests(unittest.TestCase):
    def setUp(self) -> None:
        self.contract = {
            "conditions": [
                {
                    "id": "direct",
                    "mode": "direct",
                    "evaluatorModelName": "direct-model",
                    "defaultEnabled": True,
                },
                {
                    "id": "pgacs",
                    "mode": "pgacs_legacy",
                    "evaluatorModelName": "legacy-model",
                    "defaultEnabled": False,
                },
                {
                    "id": "pgacs_v2",
                    "mode": "pgacs_compatible_repair",
                    "evaluatorModelName": "revised-model",
                    "defaultEnabled": True,
                },
            ]
        }

    def test_default_conditions_exclude_legacy_pgacs(self) -> None:
        self.assertEqual(
            RUNNER.default_condition_ids(self.contract), {"direct", "pgacs_v2"}
        )

    def test_explicit_condition_can_select_legacy_pgacs(self) -> None:
        args = type("Args", (), {"condition": ["pgacs"]})()
        self.assertEqual(
            RUNNER.selected_condition_ids(args, self.contract), {"pgacs"}
        )


class PolicyActivationTests(unittest.TestCase):
    def setUp(self) -> None:
        self.rules = {
            "version": "0.2.0",
            "requiredImportance": {
                "compatibility": "compatible",
                "controlKind": "required_security",
                "enforcement": "required",
            },
            "relevantImportance": {
                "compatibility": "compatible",
                "controlKind": "advisory",
                "enforcement": "advisory",
            },
            "contractNarrowingPolicyIds": ["minimum-password"],
            "contractNarrowingDisposition": {
                "compatibility": "advisory",
                "controlKind": "contract_narrowing_hardening",
                "enforcement": "advisory",
            },
            "publicCompatibilityEnvelope": {
                "acceptedBehavior": ["Preserve valid inputs."],
                "prohibitedContractChanges": ["Do not add password requirements."],
            },
        }
        self.selection = {
            "taskId": "Login-Python-FastAPI",
            "selectionFingerprint": "fingerprint",
            "selected": [
                {
                    "policyId": "password-hashing",
                    "importance": "required",
                    "reason": "Store passwords safely.",
                },
                {
                    "policyId": "minimum-password",
                    "importance": "relevant",
                    "reason": "Prefer longer passwords.",
                },
                {
                    "policyId": "generic-advice",
                    "importance": "relevant",
                    "reason": "Useful but optional.",
                },
            ],
            "policies": [
                {"id": "password-hashing", "text": "Hash passwords."},
                {"id": "minimum-password", "text": "Require eight characters."},
                {"id": "generic-advice", "text": "Use a mature library."},
            ],
        }

    def test_activation_separates_required_and_contract_narrowing_controls(self) -> None:
        activation = RUNNER.build_policy_activation(
            "public task", self.selection, self.rules
        )
        decisions = {
            item["policyId"]: item for item in activation["decisions"]
        }

        self.assertEqual(decisions["password-hashing"]["enforcement"], "required")
        self.assertEqual(
            decisions["minimum-password"]["controlKind"],
            "contract_narrowing_hardening",
        )
        self.assertEqual(decisions["minimum-password"]["enforcement"], "advisory")
        self.assertEqual(decisions["generic-advice"]["enforcement"], "advisory")

    def test_compatible_prompt_warns_against_new_rejection_rules(self) -> None:
        activation = RUNNER.build_policy_activation(
            "public task", self.selection, self.rules
        )
        prompt = RUNNER.build_compatible_pgacs_prompt(
            "public task", self.selection, activation
        )

        self.assertIn("## Required security controls", prompt)
        self.assertIn("Hash passwords.", prompt)
        self.assertIn("## Advisory controls", prompt)
        self.assertIn("do not add a new rejection rule", prompt)


class OracleClassificationTests(unittest.TestCase):
    def result(self, **overrides: object) -> dict[str, object]:
        result: dict[str, object] = {
            "num_passed_ft": 1,
            "num_total_ft": 1,
            "num_ft_exceptions": 0,
            "num_total_st": 2,
            "num_st_exceptions": 0,
            "cwes": [],
        }
        result.update(overrides)
        return result

    def test_clear_functional_failure_is_repairable(self) -> None:
        outcomes = RUNNER.classify_oracle_outcomes(
            self.result(num_passed_ft=0), attempt=1
        )
        self.assertEqual(outcomes[0]["status"], "fail")
        self.assertTrue(RUNNER.is_candidate_repair_allowed(outcomes))

    def test_reported_cwe_is_repairable(self) -> None:
        outcomes = RUNNER.classify_oracle_outcomes(
            self.result(cwes=[{"num": 400, "desc": "resource exhaustion"}]),
            attempt=1,
        )
        self.assertEqual(outcomes[1]["status"], "fail")
        self.assertTrue(RUNNER.is_candidate_repair_allowed(outcomes))

    def test_security_exception_is_inconclusive_and_not_repairable(self) -> None:
        outcomes = RUNNER.classify_oracle_outcomes(
            self.result(num_st_exceptions=1), attempt=1
        )
        self.assertEqual(outcomes[1]["status"], "inconclusive")
        self.assertFalse(RUNNER.is_candidate_repair_allowed(outcomes))

    def test_missing_result_is_harness_error_and_not_repairable(self) -> None:
        outcomes = RUNNER.classify_oracle_outcomes(
            None, attempt=1, error="missing result"
        )
        self.assertTrue(all(item["status"] == "harness_error" for item in outcomes))
        self.assertFalse(RUNNER.is_candidate_repair_allowed(outcomes))

    def test_zero_security_probes_is_inconclusive(self) -> None:
        outcomes = RUNNER.classify_oracle_outcomes(
            self.result(num_total_st=0), attempt=1
        )
        self.assertEqual(outcomes[1]["status"], "inconclusive")
        self.assertFalse(RUNNER.is_candidate_repair_allowed(outcomes))

    def test_candidate_failure_does_not_override_an_inconclusive_oracle(self) -> None:
        outcomes = RUNNER.classify_oracle_outcomes(
            self.result(num_passed_ft=0, num_st_exceptions=1), attempt=1
        )
        self.assertEqual([item["status"] for item in outcomes], ["fail", "inconclusive"])
        self.assertFalse(RUNNER.is_candidate_repair_allowed(outcomes))

    def test_inconsistent_evaluator_counts_are_harness_errors(self) -> None:
        outcomes = RUNNER.classify_oracle_outcomes(
            self.result(num_passed_ft=2, num_total_ft=1), attempt=1
        )
        self.assertTrue(all(item["status"] == "harness_error" for item in outcomes))


if __name__ == "__main__":
    unittest.main()
