# Benchmark and Oracle Readiness Protocol

## Purpose

This protocol defines when a benchmark task may contribute evidence about
PGACS. It separates source availability, evaluator execution, and validated
security evidence. A benchmark's reputation or native success command is not
sufficient oracle authority.

## Task Admission

A task must have:

1. a pinned source revision and prompt digest;
2. a public task contract with evaluator-only fields excluded from agent
   context;
3. an explicit mutation boundary;
4. a bounded functional claim;
5. a bounded required-security claim;
6. a reproducible workspace adapter;
7. independently executable functional and security oracles; and
8. a deterministic artifact and outcome record.

## Oracle Validation

Probe contracts distinguish three evidence classes:

- `functional` probes gate functional correctness;
- `required_security` probes gate security and may authorize C2 repair; and
- `advisory_security` probes are reported but cannot repair, block, or create
  security-success credit.

Every activated required obligation must have at least one frozen
`required_security` probe binding. Admission fails if the set of binding keys
differs from the set of activated required obligations, or if a bound probe is
missing or advisory.

Each oracle requires a receipt with this conceptual shape:

```ts
interface OracleValidationReceipt {
  taskId: string;
  oracleId: string;
  evaluatorRevision: string;
  evaluatorSha256: string;
  environmentDigest: string;
  knownVulnerableCandidateSha256: string;
  knownVulnerableOutcome: 'fail';
  knownSecureCandidateSha256: string;
  knownSecureOutcome: 'pass';
  deterministicReplayCount: number;
  deterministicReplayDigest: string;
  isolationReceipt: string;
  createdAt: string;
}
```

Reference candidates and exploit bodies remain evaluator-only. The receipt may
contain hashes and outcomes but must not expose them to the coding agent or
semantic selector.

The current BaxBench receipt is
[`baxbench-oracle-validation.v0.5.json`](./baxbench-oracle-validation.v0.5.json).
It records three deterministic executions of one known-secure and one
known-vulnerable candidate for each task under the digest-pinned evaluator.

## Readiness States

- `selected`: the task is in the development cohort but one or more adapter,
  oracle, isolation, or calibration components are incomplete.
- `adapter_ready`: the task has executable adapters and oracles plus an
  implemented leakage boundary, but a listed operational verification may
  still prevent model execution.
- `runnable`: every conjunctive gate below is satisfied and no blocker remains.

## Runnable Gate

A task is `runnable` only if all statements are true:

```text
source pinned
AND workspace adapter implemented
AND functional oracle executed
AND security oracle executed
AND known-vulnerable candidate rejected
AND known-secure candidate accepted
AND deterministic replay recorded
AND evaluator isolation implemented
AND agent/evaluator leakage boundary implemented
AND agent-backed boundary validation recorded
AND blocker list empty
```

The gate is intentionally conjunctive. Missing evidence produces a blocked or
inconclusive study cell, never a security pass.

The experiment runner enforces this state rather than treating the registry as
documentation: no filtered or complete model run starts unless all three
active BaxBench tasks are `runnable`. It also requires the admitted boundary
receipt's Claude version and Archon commit to match the executing host. Each
run archives that receipt and the admitted registry for analyzer revalidation.

An oracle may be marked `implemented` after its executable and focused logic
tests exist. This is an engineering milestone only. It does not satisfy the
`executed` runnable gate and does not establish that the oracle is sound for a
native benchmark environment.

Likewise, an agent leakage boundary is `implemented` when the runner encodes
safe mode, project-only settings, fail-closed OS sandboxing, external-network
denial, and explicit repository/control-path denial. Before runnable promotion,
an agent-backed smoke must prove that both direct Claude and Archon-mediated
execution honor those controls in the installed runtime versions.

The current
[`agent-boundary-validation.v0.1.json`](./agent-boundary-validation.v0.1.json)
records passing B0, C0, and C2 checks for Claude Code 2.1.220, exact runtime
model `claude-sonnet-5`, and Archon commit `d65383ed`. Its verifier, experiment
contract, and runner hashes match the current frozen inputs, so the three
BaxBench tasks satisfy the live boundary gate and are `runnable`.

The historical
[`agent-boundary-validation.pre-fixture-fix.v0.1.json`](./agent-boundary-validation.pre-fixture-fix.v0.1.json)
records passing B0, C0, and C2 checks for Claude Code 2.1.220 and the earlier
frozen Archon/provider control path. It proves the qualification mechanism was
exercised, but it is not admitted for the current corrected runner because its
runner and experiment-contract hashes differ.

Experiment execution must use previously absent external output roots and
task-condition directories. Task/condition filters and the provenance-recording
merger are development-diagnostic utilities only. A partial run or any final
harness-error cell is not admissible for the v0.1 effectiveness analysis. After
infrastructure remediation, execute the complete frozen schedule in a new root;
stale workspaces are never reused.

## Benchmark-Specific Requirements

### BaxBench

- Keep functional tests, security tests, potential CWEs, and exploit bodies out
  of agent and selector context.
- Record validation receipts for the official evaluator rather than relying
  only on prior agent runs.
- Distinguish candidate failures from evaluator exceptions.
- Attribute candidate startup and local request failures to the candidate;
  attribute Docker launch, malformed output, and isolation-receipt failures to
  the harness.
- Treat the bounded catastrophic-regex check as advisory for the current Regex
  task because the frozen public contract does not require a regex time bound.

### SWE-bench Verified

- Treat FAIL_TO_PASS and PASS_TO_PASS as functional evidence only.
- Implement an independently reviewed PGACS security oracle for each selected
  issue.
- Validate the security oracle against pre-fix and fixed repository revisions.
- Reject patches that satisfy a UI check while leaving the server-side security
  property violated.

### SetupBench

- Treat the native success command as functional evidence only.
- Construct a functional but insecure reference configuration.
- Require the security oracle to reject unsafe host-key handling, key
  permissions, bind scope, or supervision despite functional connectivity.
- Execute configuration checks in an isolated disposable environment.

## Study Boundary

The current cohort is entirely development data. It may be used to revise
adapters, policy activation, probes, and repair behavior. It cannot support an
unqualified general-effectiveness claim.

After the prototype stabilizes, a held-out cohort must be selected under a new
version before model execution. No task observed during this phase may be moved
into that cohort.
