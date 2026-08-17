#!/usr/bin/env python3
"""Summarize paired Codex JSONL trajectories and external evaluations."""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any


def load_json(path: Path) -> dict[str, Any]:
    with path.open(encoding="utf-8") as handle:
        value = json.load(handle)
    if not isinstance(value, dict):
        raise ValueError(f"{path} must contain a JSON object")
    return value


def summarize_condition(artifact_dir: Path) -> dict[str, Any]:
    counts = {
        "agentMessages": 0,
        "commandExecutions": 0,
        "failedCommands": 0,
        "fileChangeEvents": 0,
        "changedFiles": set(),
    }
    usage: dict[str, int] = {}

    with (artifact_dir / "trajectory.jsonl").open(encoding="utf-8") as handle:
        for line_number, line in enumerate(handle, start=1):
            try:
                event = json.loads(line)
            except json.JSONDecodeError as error:
                raise ValueError(
                    f"invalid JSON on line {line_number} of {artifact_dir / 'trajectory.jsonl'}"
                ) from error

            if event.get("type") == "item.completed":
                item = event.get("item", {})
                item_type = item.get("type")
                if item_type == "agent_message":
                    counts["agentMessages"] += 1
                elif item_type == "command_execution":
                    counts["commandExecutions"] += 1
                    if item.get("exit_code") not in (0, None):
                        counts["failedCommands"] += 1
                elif item_type == "file_change":
                    counts["fileChangeEvents"] += 1
                    for change in item.get("changes", []):
                        path = change.get("path")
                        if isinstance(path, str):
                            counts["changedFiles"].add(Path(path).name)
            elif event.get("type") == "turn.completed":
                raw_usage = event.get("usage", {})
                usage = {
                    key: value
                    for key, value in raw_usage.items()
                    if isinstance(key, str) and isinstance(value, int)
                }

    evaluation = load_json(artifact_dir / "external-evaluation.json")
    metrics = evaluation.get("metrics", {})
    return {
        "trajectory": {
            "agentMessages": counts["agentMessages"],
            "commandExecutions": counts["commandExecutions"],
            "failedCommands": counts["failedCommands"],
            "fileChangeEvents": counts["fileChangeEvents"],
            "changedFileCount": len(counts["changedFiles"]),
        },
        "usage": usage,
        "evaluation": metrics,
    }


def main() -> int:
    if len(sys.argv) != 3:
        print(
            "usage: summarize_trajectories.py ARTIFACTS_DIR OUTPUT_JSON",
            file=sys.stderr,
        )
        return 2

    artifacts_dir = Path(sys.argv[1]).resolve()
    output_path = Path(sys.argv[2]).resolve()
    summary = {
        "baseline": summarize_condition(artifacts_dir / "baseline"),
        "guided": summarize_condition(artifacts_dir / "guided"),
    }

    baseline_usage = summary["baseline"]["usage"]
    guided_usage = summary["guided"]["usage"]
    summary["comparison"] = {
        "inputTokenRatioGuidedToBaseline": round(
            guided_usage["input_tokens"] / baseline_usage["input_tokens"], 3
        ),
        "outputTokenRatioGuidedToBaseline": round(
            guided_usage["output_tokens"] / baseline_usage["output_tokens"], 3
        ),
        "sourceLineDelta": (
            summary["guided"]["evaluation"]["sourceLines"]
            - summary["baseline"]["evaluation"]["sourceLines"]
        ),
        "defenseInDepthPassDelta": (
            summary["guided"]["evaluation"]["defenseInDepthPassed"]
            - summary["baseline"]["evaluation"]["defenseInDepthPassed"]
        ),
    }

    output_path.parent.mkdir(parents=True, exist_ok=True)
    with output_path.open("w", encoding="utf-8") as handle:
        json.dump(summary, handle, indent=2)
        handle.write("\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
