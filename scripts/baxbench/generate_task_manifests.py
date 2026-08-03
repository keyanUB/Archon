#!/usr/bin/env python3
"""Generate the three frozen BaxBench task manifests from source-pinned inputs."""

from __future__ import annotations

import hashlib
import importlib.util
import json
import subprocess
from pathlib import Path
from typing import Any

import pyarrow.parquet as pq


REPO_ROOT = Path(__file__).resolve().parents[2]
PILOT_PATH = (
    REPO_ROOT
    / "principle-guided-agent-research"
    / "14-baxbench-pilot"
    / "pilot-v0.2.json"
)
SELECTION_PATH = PILOT_PATH.with_name("semantic-selection.v0.1.json")
RULES_PATH = PILOT_PATH.with_name("activation-rules.v0.2.json")
CORPUS_PATH = (
    REPO_ROOT / ".archon/data/research/pgacs/principle-corpus.expanded.json"
)
DATASET_PATH = REPO_ROOT / ".pgacs-baxbench/inputs/test-00000-of-00001.parquet"
OUTPUT_PATH = Path(__file__).with_name("task-manifests.v0.1.json")
SELECTED_TASK_IDS = (
    "Login-Python-FastAPI",
    "RegexSearch-Python-FastAPI",
    "ZipToTxt-Python-FastAPI",
)


def load_json(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def sha256_text(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def load_runner() -> Any:
    path = Path(__file__).with_name("run_pgacs_baxbench_pilot.py")
    spec = importlib.util.spec_from_file_location("pgacs_baxbench_runner", path)
    if spec is None or spec.loader is None:
        raise RuntimeError("Could not load the BaxBench pilot runner")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def build_obligations(
    selected: list[dict[str, Any]],
    policies: dict[str, dict[str, Any]],
    narrowing_ids: set[str],
) -> list[dict[str, Any]]:
    obligations = []
    for item in selected:
        policy_id = item["policyId"]
        policy = policies.get(policy_id)
        if policy is None or not policy.get("selectable"):
            raise RuntimeError(f"Missing selectable policy {policy_id}")
        if policy_id in narrowing_ids:
            control_kind = "contract_narrowing_hardening"
            enforcement = "advisory"
            relation = "narrows"
        elif item["importance"] == "required":
            control_kind = "required_security"
            enforcement = "required"
            relation = "preserves"
        else:
            control_kind = "advisory"
            enforcement = "advisory"
            relation = "preserves"
        obligations.append(
            {
                "policyId": policy_id,
                "obligationId": f"{policy_id}:{item['importance']}",
                "guidance": policy["text"],
                "controlKind": control_kind,
                "contractRelation": relation,
                "requestedEnforcement": enforcement,
                "evidenceRefs": ["baxbench:security"],
                "publicRequirementRefs": [],
            }
        )
    return obligations


def main() -> None:
    pilot = load_json(PILOT_PATH)
    selection = load_json(SELECTION_PATH)
    rules = load_json(RULES_PATH)
    corpus = load_json(CORPUS_PATH)
    expected_dataset_sha256 = pilot["benchmark"]["datasetSha256"]
    actual_dataset_sha256 = sha256_file(DATASET_PATH)
    if actual_dataset_sha256 != expected_dataset_sha256:
        raise RuntimeError(
            "Pinned BaxBench dataset hash mismatch: "
            f"expected={expected_dataset_sha256} actual={actual_dataset_sha256}"
        )
    if sha256_file(SELECTION_PATH) != pilot["policySelection"]["sha256"]:
        raise RuntimeError("Frozen semantic-selection hash mismatch")
    if sha256_file(RULES_PATH) != pilot["activationRules"]["sha256"]:
        raise RuntimeError("Frozen activation-rule hash mismatch")

    rows = {
        row["task_id"]: row
        for row in pq.read_table(DATASET_PATH).to_pylist()
        if row["task_id"] in SELECTED_TASK_IDS
    }
    selections = {item["taskId"]: item for item in selection["tasks"]}
    policies = {item["id"]: item for item in corpus["records"]}
    runner = load_runner()
    manifests = []
    for task_id in SELECTED_TASK_IDS:
        task = rows.get(task_id)
        task_selection = selections.get(task_id)
        if task is None or task_selection is None:
            raise RuntimeError(f"Missing frozen BaxBench input for {task_id}")
        prompt = runner.build_prompt(task)
        manifests.append(
            {
                "schemaVersion": "0.2.0",
                "id": f"baxbench:{task_id}",
                "revision": f"baxbench:{expected_dataset_sha256}:{task_id}",
                "taskKind": "repository_code_generation",
                "provenance": {
                    "sourceType": "benchmark",
                    "benchmark": "BaxBench",
                    "sourceTaskId": task_id,
                    "datasetSha256": expected_dataset_sha256,
                    "evaluatorRevision": pilot["benchmark"]["evaluatorCommit"],
                    "policySelectionSha256": pilot["policySelection"]["sha256"],
                    "activationRulesSha256": pilot["activationRules"]["sha256"],
                    "corpusSha256": sha256_file(CORPUS_PATH),
                },
                "contract": {
                    "prompt": prompt,
                    "promptSha256": sha256_text(prompt),
                    "acceptedBehavior": rules["publicCompatibilityEnvelope"][
                        "acceptedBehavior"
                    ],
                    "prohibitedContractChanges": rules[
                        "publicCompatibilityEnvelope"
                    ]["prohibitedContractChanges"],
                },
                "workspace": {
                    "adapterId": "baxbench-fastapi-v0.1",
                    "root": "workspace",
                    "implementationPath": "workspace/app.py",
                    "auxiliaryPaths": [],
                    "allowedMutationPaths": ["workspace/app.py"],
                },
                "evaluator": {
                    "adapterId": "baxbench-official-v0.1",
                    "sourcePath": "src/main.py",
                    "requiredProbeIds": [
                        "baxbench:functional",
                        "baxbench:security",
                    ],
                    "defenseInDepthProbeIds": [],
                    "idempotent": False,
                    "timeoutSeconds": 14400,
                    "native": {
                        "scenarioId": task["scenario_id"],
                        "environmentId": task["env_id"],
                        "specType": "openapi",
                        "safetyPrompt": "none",
                        "temperature": 0.2,
                        "sampleId": "sample0",
                        "outputVariant": "temp0.2-openapi-none",
                    },
                },
                "obligations": build_obligations(
                    task_selection["selected"],
                    policies,
                    set(rules["contractNarrowingPolicyIds"]),
                ),
            }
        )

    payload = {
        "schemaVersion": "0.1.0",
        "sourceManifest": str(PILOT_PATH.relative_to(REPO_ROOT)),
        "generator": str(Path(__file__).relative_to(REPO_ROOT)),
        "tasks": manifests,
    }
    OUTPUT_PATH.write_text(
        json.dumps(payload, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    subprocess.run(
        ["bunx", "prettier", "--write", str(OUTPUT_PATH)],
        cwd=REPO_ROOT,
        check=True,
        capture_output=True,
        text=True,
    )


if __name__ == "__main__":
    main()
