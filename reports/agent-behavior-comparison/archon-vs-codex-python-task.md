# Archon vs Direct Codex: Small Python Code Generation Task

Date: 2026-06-22

## Task

Generate a Python script named `word_stats.py` that reads a text file and prints JSON with:

- `line_count`
- `word_count`
- `char_count`
- `top_words`

Requirements:

- Python standard library only.
- Case-insensitive word counting.
- Strip punctuation around words.
- CLI: `python word_stats.py input.txt --top 3`.
- Unit tests with `unittest`.

## Test Repositories

Two identical throwaway git repos were created from the same baseline:

- Direct Codex run: `/private/tmp/archon-procedure-demo/manual-task`
- Archon run: `/private/tmp/archon-procedure-demo/archon-task`

Both repos started with only:

- `README.md`
- `tests/.gitkeep`

## Direct Codex Run

Behavior observed:

1. Read `README.md`.
2. Listed existing files.
3. Created `word_stats.py`.
4. Created `tests/test_word_stats.py`.
5. Ran `python -m unittest -v`; result: no tests discovered.
6. Ran `python -m unittest discover -s tests -v`; result: 4 tests passed.
7. Checked status/diff.

Generated files:

- `/private/tmp/archon-procedure-demo/manual-task/word_stats.py`
- `/private/tmp/archon-procedure-demo/manual-task/tests/test_word_stats.py`

Direct run behavior characteristics:

- One assistant turn controlled the whole procedure.
- Planning was implicit in the assistant's reasoning, not persisted as an artifact.
- Validation happened because the assistant chose to run it.
- The assistant adjusted validation after `python -m unittest -v` discovered no tests.
- No workflow run record, node graph, phase boundary, or artifact handoff existed.

Manual behavior log:

- `/private/tmp/archon-procedure-demo/logs/manual-codex-behavior.md`

## Archon Run

Custom local workflow added to the Archon test repo:

- `/private/tmp/archon-procedure-demo/archon-task/.archon/workflows/word-stats-codegen.yaml`

Workflow:

```yaml
nodes:
  - id: plan
    command: word-stats-plan
    context: fresh

  - id: implement
    command: word-stats-implement
    depends_on: [plan]
    context: fresh

  - id: validate
    bash: python -m unittest discover -s tests -v
    depends_on: [implement]

  - id: summarize
    command: word-stats-summarize
    depends_on: [validate]
    context: fresh
```

Invocation:

```bash
bun --cwd packages/cli src/cli.ts \
  --cwd /private/tmp/archon-procedure-demo/archon-task \
  workflow run word-stats-codegen \
  --no-worktree \
  "Generate word_stats.py and unittest coverage according to README.md"
```

Initial observations before node execution:

- First sandboxed attempt failed before execution: Archon could not write `~/.archon/archon.db`.
- Rerun with elevated filesystem permissions reached execution.
- Archon auto-registered the local repo under `~/.archon/workspaces/_local/archon-task/source`.
- Archon created workflow run ID `5c91e8674e260aa2030dd58e4b1ae018`.
- Archon logged a default-branch detection warning because the throwaway repo had no remote, but the workflow continued because this local workflow did not need `$BASE_BRANCH`.

Node behavior observed:

1. `plan` node started.
   - Coding agent read README/repo layout.
   - Wrote only `.archon/artifacts/runs/5c91e8674e260aa2030dd58e4b1ae018/plan.md`.
   - Explicitly avoided implementation edits.
   - Duration: 40s.

2. `implement` node started with fresh context.
   - Coding agent read README and `plan.md`.
   - Created `word_stats.py`.
   - Created `tests/test_word_stats.py`.
   - Ran `python -m unittest discover -s tests`.
   - Wrote `implementation.md`.
   - Removed generated Python cache directories before finishing.
   - Duration: 1m28s.

3. `validate` bash node ran.
   - Deterministic command: `python -m unittest discover -s tests -v`.
   - Result: 6 tests passed.
   - Duration: 66ms.

4. `summarize` node started with fresh context.
   - Read `plan.md` and `implementation.md`.
   - Inspected git status and generated source/tests.
   - Wrote `summary.md`.
   - Duration: 48.2s.

Archon generated files:

- `/private/tmp/archon-procedure-demo/archon-task/word_stats.py`
- `/private/tmp/archon-procedure-demo/archon-task/tests/test_word_stats.py`

Archon artifacts:

- `/private/tmp/archon-procedure-demo/archon-task/.archon/artifacts/runs/5c91e8674e260aa2030dd58e4b1ae018/plan.md`
- `/private/tmp/archon-procedure-demo/archon-task/.archon/artifacts/runs/5c91e8674e260aa2030dd58e4b1ae018/implementation.md`
- `/private/tmp/archon-procedure-demo/archon-task/.archon/artifacts/runs/5c91e8674e260aa2030dd58e4b1ae018/summary.md`
- `/private/tmp/archon-procedure-demo/archon-task/.archon/logs/5c91e8674e260aa2030dd58e4b1ae018.jsonl`

Final Archon validation rerun:

```text
Ran 6 tests in 0.024s
OK
```

## What Changed Procedurally

| Aspect                  | Direct Codex                                | Archon                                               |
| ----------------------- | ------------------------------------------- | ---------------------------------------------------- |
| First recipient         | This Codex session                          | Archon CLI/workflow executor, then provider per node |
| Planning                | Implicit                                    | Explicit `plan` node and `plan.md` artifact          |
| Implementation          | Same agent turn                             | Separate `implement` node, fresh context             |
| Validation              | Agent-chosen shell command                  | Dedicated deterministic bash node                    |
| Summary                 | Final assistant answer only                 | Dedicated `summarize` node and `summary.md` artifact |
| State                   | Conversation + filesystem                   | DB workflow run + JSONL log + artifacts + filesystem |
| Control                 | Agent decided sequence                      | YAML DAG decided sequence                            |
| Test command correction | Agent noticed and corrected discovery issue | Workflow had validation command pre-encoded          |

## Concrete Takeaway

Both runs generated working Python code.

The direct Codex run was shorter and simpler, but the procedure was implicit: the assistant decided what to inspect, when to write, and how to validate.

The Archon run added overhead, but made the procedure observable and enforceable:

- It split the task into named phases.
- It persisted handoff artifacts.
- It forced fresh-context boundaries.
- It ran validation as a workflow-controlled node.
- It produced a replayable JSONL event log.

For a tiny script, Archon is heavier than necessary. For larger coding work, the same mechanisms are what make behavior repeatable across runs and agents.
