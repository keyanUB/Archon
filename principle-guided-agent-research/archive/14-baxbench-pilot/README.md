# BaxBench Ten-Task PGACS Pilot

## Purpose

This pilot evaluates four coding-agent execution conditions on ten prompt-only
BaxBench backend-generation tasks:

1. `direct`: the base Claude Code agent;
2. `archon`: the same provider and model through an ordinary one-node Archon
   workflow;
3. `pgacs`: the frozen legacy prompt-guided PGACS ablation; and
4. `pgacs_v2`: a compatibility-aware pre-C2 engineering condition with typed
   outcomes and one candidate-only repair.

`pgacs_v2` is the only active BaxBench PGACS engineering condition. The runner excludes legacy
`pgacs` by default; it remains available only through an explicit
`--condition pgacs` request so the original evidence stays reproducible.

The pilot is an engineering and mechanism study. With one sample per cell and
one framework, it does not support population-level or causal claims.

## Frozen Scope

The active machine-readable contract is [`pilot-v0.2.json`](./pilot-v0.2.json).
The original [`pilot-v0.1.json`](./pilot-v0.1.json) is frozen and must not be
used for new prototype development. The
cohort holds the language and framework constant at Python/FastAPI and varies
the security surface across ten scenarios. `Calculator` and `FileSearch` are
development tasks; the other eight are the frozen evaluation subset.

The benchmark dataset and official evaluator are pinned by SHA-256 and Git
commit. The agent and automatic selector never receive BaxBench
`potential_cwes`, functional tests, security tests, or exploits.
The no-tools semantic selections are frozen separately in
[`semantic-selection.v0.1.json`](./semantic-selection.v0.1.json) and bound to
the task-only selector view and policy corpus by content hashes.

The Login, RegexSearch, and ZipToTxt development tasks additionally have exact
public prompts and provenance frozen in
[`../../scripts/baxbench/task-manifests.v0.1.json`](../../../scripts/baxbench/task-manifests.v0.1.json).
Their workspaces and evaluator exports are routed through the shared typed
adapters in
[`../../scripts/pgacs-task-adapters.ts`](../../../scripts/pgacs-task-adapters.ts).
The evaluator adapter verifies the official Git revision and a clean tracked
checkout, stages only `app.py`, and returns the exact native result path.

## Interpretation Boundaries

- The direct and Archon conditions use the same neutral BaxBench prompt.
- Active PGACS separates selection from compatibility-aware activation,
  validates the generated artifact, routes typed evaluator outcomes, and
  permits one policy-preserving repair only for a candidate failure.
- The generic BaxBench adapter still relies on terminal benchmark probes; it
  does not yet implement continuous runtime monitoring or intervention during
  generation.
- `pgacs_v2` does not use the ZIP C2 runtime reducer or deterministic write-scope
  gate and must not be reported as the full multi-benchmark C2 condition.
- Official BaxBench tests run outside the agent workspace in Docker.
- The Docker build environment is not yet image-digest pinned, and deterministic
  evaluator replay has not been recorded. The evaluator adapter is therefore
  non-idempotent and these tasks remain `selected`, not `adapter_ready` or
  `runnable`.
- Agent execution and hidden evaluator assets are not separated by an OS
  boundary. Same-user path traversal is therefore a contamination risk even
  though evaluator-only fields are omitted from prompts and manifests.
- Agent-authored tests are trajectory evidence only and have no oracle
  authority.
- Because Archon provides an agentic tool loop, results are described as a
  BaxBench-derived agentic evaluation and are not directly comparable to the
  standard completion-only leaderboard.

## Commands

Prepare and verify inputs:

```bash
/Users/keyanguo/anaconda3/bin/python3.12 scripts/baxbench/run_pgacs_baxbench_pilot.py prepare
```

Regenerate and validate the three shared task manifests:

```bash
/Users/keyanguo/anaconda3/bin/python3 scripts/baxbench/generate_task_manifests.py
bun test ./scripts/pgacs-task-adapters.test.ts
/Users/keyanguo/anaconda3/bin/python3 -m unittest scripts/baxbench/test_run_pgacs_baxbench_pilot.py
```

Run one task in the default active comparison (`direct`, `archon`, and
`pgacs_v2`):

```bash
/Users/keyanguo/anaconda3/bin/python3.12 scripts/baxbench/run_pgacs_baxbench_pilot.py run \
  --task-id Calculator-Python-FastAPI
```

Run the complete cohort and export code into the official evaluator layout:

```bash
/Users/keyanguo/anaconda3/bin/python3.12 scripts/baxbench/run_pgacs_baxbench_pilot.py run
/Users/keyanguo/anaconda3/bin/python3.12 scripts/baxbench/run_pgacs_baxbench_pilot.py export
/Users/keyanguo/anaconda3/bin/python3.12 scripts/baxbench/run_pgacs_baxbench_pilot.py evaluate
```

Run the bounded revised-PGACS repair after the initial evaluation, then export
and evaluate again:

```bash
/Users/keyanguo/anaconda3/bin/python3.12 scripts/baxbench/run_pgacs_baxbench_pilot.py repair
/Users/keyanguo/anaconda3/bin/python3.12 scripts/baxbench/run_pgacs_baxbench_pilot.py export
/Users/keyanguo/anaconda3/bin/python3.12 scripts/baxbench/run_pgacs_baxbench_pilot.py evaluate
```

Finally:

```bash
/Users/keyanguo/anaconda3/bin/python3.12 scripts/baxbench/run_pgacs_baxbench_pilot.py summarize
```

Generated trajectories and evaluator workspaces are written under
`.pgacs-baxbench/` and are intentionally not committed.

To reproduce the legacy ablation, opt in explicitly and pin its original
contract where appropriate:

```bash
/Users/keyanguo/anaconda3/bin/python3.12 scripts/baxbench/run_pgacs_baxbench_pilot.py run \
  --condition pgacs
```

## Current Results

The frozen v0.1 study completed 10 tasks and 30 cells. Its conservative
comparison and design implications are retained in [`results.md`](./results.md)
as legacy evidence. The active v0.2 study is in progress and must not be
presented as a completed result until all ten initial cells, admissible repairs,
and final evaluations finish.
