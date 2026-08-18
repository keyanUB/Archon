from __future__ import annotations

import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from pgacs_secrepobench_agent import (
    HUGGING_FACE_OPENAI_BASE_URL,
    _build_and_run,
    _configure_isolated_openhands_home,
    _resolve_cost_accounting,
    _resolve_api_key,
    _resolve_base_url,
)
from pgacs_workspace_policy import PgacsWorkspacePolicy, WorkspacePolicyError


class PgacsWorkspacePolicyTest(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary_directory = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary_directory.name)
        (self.root / "src").mkdir()
        (self.root / "src" / "target.py").write_text("MARKER\n", encoding="utf-8")
        (self.root / "src" / "context.py").write_text("TOKEN = 1\n", encoding="utf-8")
        self.policy = PgacsWorkspacePolicy(str(self.root), "src/target.py")

    def tearDown(self) -> None:
        self.temporary_directory.cleanup()

    def test_reads_and_searches_only_repository_files(self) -> None:
        self.assertIn("TOKEN = 1", self.policy.read("src/context.py").text)
        self.assertIn("src/context.py:1", self.policy.search("TOKEN").text)
        with self.assertRaisesRegex(WorkspacePolicyError, "invalid segment"):
            self.policy.read("../outside")

    def test_rejects_symlink_escape(self) -> None:
        outside = self.root.parent / "pgacs-policy-outside.txt"
        outside.write_text("secret", encoding="utf-8")
        link = self.root / "src" / "outside.txt"
        link.symlink_to(outside)
        try:
            with self.assertRaisesRegex(WorkspacePolicyError, "escapes"):
                self.policy.read("src/outside.txt")
        finally:
            outside.unlink(missing_ok=True)

    def test_rejects_off_target_write_and_file_creation(self) -> None:
        with self.assertRaisesRegex(WorkspacePolicyError, "permitted only"):
            self.policy.write("src/context.py", "changed\n")
        with self.assertRaisesRegex(WorkspacePolicyError, "permitted only"):
            self.policy.write("src/new.py", "new\n")
        self.assertEqual((self.root / "src" / "context.py").read_text(), "TOKEN = 1\n")

    def test_applies_unique_target_replacement(self) -> None:
        result = self.policy.replace("src/target.py", "MARKER", "secure_value = 1")
        self.assertTrue(result.changed)
        self.assertEqual(
            (self.root / "src" / "target.py").read_text(), "secure_value = 1\n"
        )
        with self.assertRaisesRegex(WorkspacePolicyError, "exactly once"):
            self.policy.replace("src/target.py", "missing", "value")

    def test_resolves_provider_specific_keys_without_cross_provider_fallback(self) -> None:
        with patch.dict("os.environ", {"OPENROUTER_API_KEY": "router-key"}, clear=True):
            self.assertEqual(_resolve_api_key("openrouter/qwen/qwen3-coder"), "router-key")
        with patch.dict("os.environ", {"OPENAI_API_KEY": "openai-key"}, clear=True):
            with self.assertRaisesRegex(ValueError, "OPENROUTER_API_KEY"):
                _resolve_api_key("openrouter/qwen/qwen3-coder")

    def test_resolves_hugging_face_openai_route_without_openai_key_fallback(self) -> None:
        model = "openai/Qwen/Qwen3.6-35B-A3B"
        with patch.dict("os.environ", {"HF_TOKEN": "hf-key"}, clear=True):
            self.assertEqual(_resolve_api_key(model), "hf-key")
            self.assertEqual(_resolve_base_url(model), HUGGING_FACE_OPENAI_BASE_URL)
        with patch.dict("os.environ", {"OPENAI_API_KEY": "openai-key"}, clear=True):
            with self.assertRaisesRegex(ValueError, "HF_TOKEN"):
                _resolve_api_key(model)

    def test_distinguishes_mapped_and_unmapped_cost_accounting(self) -> None:
        def model_info(model: str) -> dict[str, float]:
            if model == "openai/gpt-4.1-mini":
                return {
                    "input_cost_per_token": 0.000001,
                    "output_cost_per_token": 0.000002,
                }
            raise ValueError("unmapped fixture model")

        with (
            patch("litellm.get_model_info", side_effect=model_info),
            patch.dict("os.environ", {}, clear=True),
        ):
            mapped = _resolve_cost_accounting("openai/gpt-4.1-mini")
            unmapped = _resolve_cost_accounting("openai/Qwen/Qwen3.6-35B-A3B")
        self.assertTrue(mapped["available"])
        self.assertEqual(mapped["source"], "litellm_model_map")
        self.assertFalse(unmapped["available"])
        self.assertEqual(unmapped["source"], "unavailable")

    def test_accepts_only_complete_explicit_cost_configuration(self) -> None:
        variables = {
            "LLM_INPUT_COST_PER_TOKEN_USD": "0.000001",
            "LLM_OUTPUT_COST_PER_TOKEN_USD": "0.000002",
        }
        with patch.dict("os.environ", variables, clear=True):
            accounting = _resolve_cost_accounting("openai/Qwen/Qwen3.6-35B-A3B")
        self.assertTrue(accounting["available"])
        self.assertEqual(accounting["source"], "explicit")
        self.assertEqual(accounting["inputCostPerTokenUsd"], 0.000001)
        self.assertEqual(accounting["outputCostPerTokenUsd"], 0.000002)
        with patch.dict(
            "os.environ", {"LLM_INPUT_COST_PER_TOKEN_USD": "0.000001"}, clear=True
        ):
            with self.assertRaisesRegex(ValueError, "configured together"):
                _resolve_cost_accounting("openai/Qwen/Qwen3.6-35B-A3B")

    def test_allows_explicit_openai_compatible_base_url_override(self) -> None:
        with patch.dict(
            "os.environ",
            {
                "LLM_API_KEY": "dedicated-key",
                "LLM_BASE_URL": "https://dedicated.example/v1",
            },
            clear=True,
        ):
            self.assertEqual(
                _resolve_base_url("openai/Qwen/Qwen3.6-35B-A3B"),
                "https://dedicated.example/v1",
            )
            self.assertEqual(
                _resolve_api_key("openai/Qwen/Qwen3.6-35B-A3B"),
                "dedicated-key",
            )

    def test_rejects_hugging_face_token_for_custom_endpoint(self) -> None:
        with patch.dict(
            "os.environ",
            {
                "HF_TOKEN": "hf-key",
                "LLM_BASE_URL": "https://untrusted.example/v1",
            },
            clear=True,
        ):
            with self.assertRaisesRegex(ValueError, "LLM_API_KEY"):
                _resolve_api_key("openai/Qwen/Qwen3.6-35B-A3B")

    def test_uses_process_owned_home_for_implicit_openhands_state(self) -> None:
        original_home = os.environ.get("HOME")
        try:
            isolated_home = _configure_isolated_openhands_home()
            self.assertEqual(os.environ["HOME"], isolated_home)
            self.assertTrue(Path(isolated_home).is_dir())
            self.assertFalse(Path(isolated_home).is_relative_to(self.root))
        finally:
            if original_home is None:
                os.environ.pop("HOME", None)
            else:
                os.environ["HOME"] = original_home

    def test_openhands_conversation_completes_restricted_edit(self) -> None:
        _configure_isolated_openhands_home()
        from openhands.sdk.llm import Message, MessageToolCall, TextContent
        from openhands.sdk.testing import TestLLM

        workspace = self.root / "smoke"
        workspace.mkdir()
        (workspace / "context.py").write_text("OFFSET = 0\n", encoding="utf-8")
        target = workspace / "target.py"
        target.write_text(
            "def secure_add(left: int, right: int) -> int:\n"
            "    # <PGACS_COMPLETION>\n",
            encoding="utf-8",
        )
        tool_calls = [
            ("read", {"operation": "read", "path": "context.py"}),
            ("read", {"operation": "read", "path": "target.py"}),
            (
                "replace",
                {
                    "operation": "replace",
                    "path": "target.py",
                    "old_text": "    # <PGACS_COMPLETION>",
                    "new_text": "    return left + right",
                },
            ),
            ("finish", {"message": "Candidate complete."}),
        ]
        messages = [
            Message(
                role="assistant",
                content=[TextContent(text="")],
                tool_calls=[
                    MessageToolCall(
                        id=f"call_{index}",
                        name="finish" if name == "finish" else "pgacs_workspace",
                        arguments=json.dumps(arguments),
                        origin="completion",
                    )
                ],
            )
            for index, (name, arguments) in enumerate(tool_calls, start=1)
        ]
        llm = TestLLM.from_messages(messages, model="test/pgacs-smoke")
        request = {
                "protocolVersion": "1.2",
                "workspaceRoot": str(workspace),
                "targetPath": "target.py",
                "prompt": "Inspect context.py and implement secure_add.",
                "condition": "C3",
                "model": "test/pgacs-smoke",
                "maxTurns": 8,
                "maxBudgetUsd": 0.25,
                "guidance": "Preserve the function contract.",
                "preActionControl": {
                    "schemaVersion": "0.1.0",
                    "mechanismVersion": "0.6.0",
                    "enabled": True,
                    "requiredEvidence": [
                        "target-read",
                        "repository-context-read",
                    ],
                    "guidance": (
                        "Inspect the target and one repository context path before writing."
                    ),
                },
            }
        with patch.dict("os.environ", {}, clear=True):
            result = _build_and_run(request, llm_override=llm)

        self.assertTrue(result["submitted"], result.get("reason"))
        self.assertEqual(
            target.read_text(encoding="utf-8"),
            "def secure_add(left: int, right: int) -> int:\n"
            "    return left + right\n",
        )
        self.assertEqual(
            [event["kind"] for event in result["observedEvents"]],
            ["file_read", "file_read", "file_write_attempt", "file_write_result"],
        )
        self.assertTrue(result["runtimeReceipt"]["preActionConditioning"])
        self.assertEqual(result["runtimeReceipt"]["costAccounting"], "unavailable")
        self.assertFalse(result["runtimeReceipt"]["monetaryBudgetEnforced"])
        self.assertNotIn("totalCostUsd", result)

    def test_openhands_c3_denies_premature_write_then_accepts_informed_retry(self) -> None:
        _configure_isolated_openhands_home()
        from openhands.sdk.llm import Message, MessageToolCall, TextContent
        from openhands.sdk.testing import TestLLM

        workspace = self.root / "controlled-retry"
        workspace.mkdir()
        (workspace / "context.py").write_text("OFFSET = 0\n", encoding="utf-8")
        target = workspace / "target.py"
        target.write_text("def secure_add():\n    # <MASK>\n", encoding="utf-8")
        actions = [
            {
                "operation": "replace",
                "path": "target.py",
                "old_text": "    # <MASK>",
                "new_text": "    return 1",
            },
            {"operation": "read", "path": "target.py"},
            {"operation": "read", "path": "context.py"},
            {
                "operation": "replace",
                "path": "target.py",
                "old_text": "    # <MASK>",
                "new_text": "    return 1",
            },
        ]
        messages = [
            Message(
                role="assistant",
                content=[TextContent(text="")],
                tool_calls=[
                    MessageToolCall(
                        id=f"call_{index}",
                        name="pgacs_workspace",
                        arguments=json.dumps(action),
                        origin="completion",
                    )
                ],
            )
            for index, action in enumerate(actions, start=1)
        ]
        messages.append(
            Message(
                role="assistant",
                content=[TextContent(text="")],
                tool_calls=[
                    MessageToolCall(
                        id="call_finish",
                        name="finish",
                        arguments=json.dumps({"message": "Candidate complete."}),
                        origin="completion",
                    )
                ],
            )
        )
        request = {
                "protocolVersion": "1.2",
                "workspaceRoot": str(workspace),
                "targetPath": "target.py",
                "prompt": "Implement the target.",
                "condition": "C3",
                "model": "test/pgacs-control",
                "maxTurns": 10,
                "maxBudgetUsd": 0.25,
                "guidance": "Preserve the contract.",
                "preActionControl": {
                    "schemaVersion": "0.1.0",
                    "mechanismVersion": "0.6.0",
                    "enabled": True,
                    "requiredEvidence": [
                        "target-read",
                        "repository-context-read",
                    ],
                    "guidance": "Inspect required context before writing.",
                },
            }
        llm = TestLLM.from_messages(messages, model="test/pgacs-control")
        with patch.dict("os.environ", {}, clear=True):
            result = _build_and_run(request, llm_override=llm)

        self.assertTrue(result["submitted"], result.get("reason"))
        self.assertEqual(target.read_text(encoding="utf-8"), "def secure_add():\n    return 1\n")
        write_results = [
            event
            for event in result["observedEvents"]
            if event["kind"] == "file_write_result"
        ]
        self.assertEqual([event["applied"] for event in write_results], [False, True])


if __name__ == "__main__":
    unittest.main()
