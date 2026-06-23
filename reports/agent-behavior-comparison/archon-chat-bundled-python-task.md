# Archon Chat Observation: Bundled Behavior on Small Python Task

Date: 2026-06-22

## Goal

Observe what Archon itself does when asked to generate a small Python script, without manually selecting or creating a workflow.

## Target Repo

Fresh throwaway repo:

`/private/tmp/archon-procedure-demo/archon-bundled-task`

Baseline files:

- `README.md`
- `tests/.gitkeep`

No project-specific `.archon/workflows/` or `.archon/commands/` files were added.

## User Request to Archon

The task was sent through Archon's chat/orchestrator path, not `workflow run <name>`:

```bash
bun /Users/keyanguo/Documents/GitHub/Agents/Archon/packages/cli/src/cli.ts chat \
  "For project word-stats-bundled, generate word_stats.py and unittest coverage according to README.md. Please make the code changes and run the relevant tests."
```

No workflow name was provided by the caller.

## Important Observation

Archon did **not** invoke a bundled workflow for this small task.

Instead, the orchestrator handled it directly in chat. It acted like a normal coding agent with tools, using a TDD procedure:

1. Examined the project.
2. Decided to use TDD.
3. Wrote tests first.
4. Ran tests and observed the expected failure because `word_stats.py` did not exist.
5. Implemented `word_stats.py`.
6. Ran tests again.
7. Refactored the line-count expression.
8. Ran/confirmed tests and CLI behavior.

Archon's final response said:

```text
Built `word_stats.py` and its test suite for word-stats-bundled using TDD
(tests written first, watched fail, then implemented).
```

## Generated Files

- `/private/tmp/archon-procedure-demo/archon-bundled-task/word_stats.py`
- `/private/tmp/archon-procedure-demo/archon-bundled-task/tests/test_word_stats.py`

## Validation

External verification after Archon completed:

```bash
python -m unittest discover -s tests -v
```

Result:

```text
Ran 6 tests in 0.020s
OK
```

## Difference From Direct Codex

For this small task, the practical behavior was very similar to a normal coding agent:

| Aspect                      | Direct Codex | Archon Chat                   |
| --------------------------- | ------------ | ----------------------------- |
| Workflow chosen by caller   | No           | No                            |
| Custom workflow used        | No           | No                            |
| Bundled workflow invoked    | No           | No                            |
| Agent edited files directly | Yes          | Yes                           |
| Tests run                   | Yes          | Yes                           |
| Procedure                   | Agent-chosen | Orchestrator/agent-chosen     |
| Extra Archon state          | No           | Conversation/project DB state |

The main Archon-specific behavior in this corrected observation was before code generation:

- Archon required project context from its registered project database.
- A previous chat request without explicit project targeting used the earlier registered `archon-task` project, not the shell `cwd`.
- After registering `word-stats-bundled`, Archon worked on the intended project.

## Takeaway

If the request is small and no specific workflow is selected, Archon may simply behave like a coding-agent chat wrapper. The big workflow-harness differences only appear when Archon routes to or is asked to run a workflow such as `archon-idea-to-pr`, `archon-fix-github-issue`, or another multi-node workflow.

So the corrected comparison is:

- **Direct Codex:** coding agent directly performs the task.
- **Archon chat, no workflow selected:** Archon orchestrator may still let the coding agent directly perform the task.
- **Archon workflow run:** Archon enforces phases, artifacts, validation nodes, fresh context, and workflow logs.
