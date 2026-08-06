# PGACS SecRepoBench Customization

## 1. Scope

This branch adapts PGACS v0.3 to SecRepoBench's repository-level C/C++ code
completion tasks. It does not replace the generic harness or revise the claims
from the completed BaxBench experiment. The first target is a three-task
feasibility study, followed by a controlled B0/C0/C1/C2 comparison if source,
oracle, and agent-boundary qualification succeeds.

Upstream identities are frozen independently:

- benchmark implementation: `ai-sec-lab/SecRepoBench` at
  `7ca5c4a7e908f8013e7b9ae624ba0d96f8c6ec76`;
- public dataset: `ai-sec-lab/SecRepoBench`, `code_completion` split;
- evaluator environment: task-specific `n132/arvo:<task-id>-fix` image;
- PGACS parent: the v0.3 state at `9e397f0a`.

SecRepoBench contains masked regions in real C/C++ repositories. Correctness is
measured with developer tests and security with an OSS-Fuzz triggering input.
The benchmark's native tests remain authoritative; PGACS only stages candidates,
normalizes evidence, controls repair, and makes the terminal decision.

## 2. System Design

```mermaid
flowchart LR
    D["Frozen neutral task and masked repository"] --> S["Surface extraction"]
    S --> P["Policy selection without evaluator labels"]
    P --> A["Prompt guidance"]
    A --> G["Coding agent edits one target file"]
    G --> M["Mutation and masked-region checks"]
    M --> E["Pinned SecRepoBench evaluator"]
    E --> U["Developer tests"]
    E --> F["OSS-Fuzz PoC"]
    U --> L["Typed evidence ledger"]
    F --> L
    L --> R["One obligation-specific repair or terminal gate"]
```

### 2.1 Frozen Task Contract

Manifest schema `0.3.0` adds `evaluator.secRepoBench` with:

- task ID, project name, fixing commit, and changed file;
- evaluator-only CWE and crash-type labels;
- the exact completion marker and masked-file digest;
- the task-specific ARVO image identity.

The parser requires the benchmark task ID to match provenance, the changed file
to match the only implementation path, and the ARVO image to match the task ID.
The workspace adapter admits only a regular file with the frozen digest and
exactly one completion marker.

### 2.2 Information-Flow Boundary

The following fields are hidden from B0, C0, C1, C2 generation and repair:

- `CWE_ID` and crash type;
- vulnerable and fixing code;
- OSS-Fuzz input and evaluator output before generation;
- developer-test identities and expected outputs;
- benchmark `security_policy` prompts.

C2 selects policies from the neutral task prompt and repository state visible to
the base agent. Using `CWE_ID` for main-condition selection would leak the oracle
label and invalidate the effectiveness comparison. A CWE-informed condition may
be run only as an explicitly named human-oracle upper bound.

### 2.3 Workspace and Mutation Control

The agent receives a repository at the benchmark-defined revision with one
masked region. The harness permits mutation only to `changed_file`. Before the
oracle runs, PGACS must establish:

1. all other tracked paths are byte-identical to the admitted workspace;
2. the target remains a regular file inside the workspace;
3. the completion marker has been removed exactly once;
4. code outside the original masked region is unchanged;
5. the candidate digest is bound to the evaluator request.

Items 3 and 4 are **TBD in implementation**. The current adapter enforces the
pre-generation one-marker digest and whole-target mutation path, but it does not
yet parse the post-generation region boundaries.

### 2.4 Single-Task Evaluator

`scripts/secrepobench/pgacs_secrepobench_oracle.py` evaluates one admitted
candidate instead of invoking the upstream full-dataset driver. It:

- imports test commands and result parsers from the pinned upstream checkout;
- starts separate developer-test and OSS-Fuzz containers;
- disables networking, drops Linux capabilities, enables no-new-privileges,
  and binds the candidate read-only;
- checks the candidate digest again immediately before execution;
- reports functional failure, insecurity, and oracle inconclusiveness as
  distinct outcomes.

The wrapper does not turn a crash parser error, missing unit-test command,
timeout, Docker failure, or compilation ambiguity into a security pass.

The wrapper implementation exists, but its result schema, isolation receipt,
ephemeral clean evaluator snapshot, and known-secure/known-vulnerable
calibration remain **TBD before admission**. A tracked-clean upstream checkout
is insufficient because untracked Python modules or cached outputs could affect
evaluation; admitted runs must materialize a fresh snapshot and bind its tree
digest.

## 3. Policy Customization

The SecRepoBench pack specializes enforcement for C/C++ repository completion:

- validate lengths, indices, integer conversions, and allocation arithmetic;
- initialize values on every reachable path before use;
- preserve ownership, lifetime, cleanup, and error-path invariants;
- use repository-native checked helpers and error conventions;
- avoid weakening existing assertions, bounds checks, or sanitizer-relevant
  behavior;
- preserve ABI, caller-visible return semantics, and relevant unit behavior.

Policy activation must be evidence-backed. Surface signals include pointer and
buffer operations, parser/decoder roles, externally controlled lengths, index
arithmetic, allocation and free sites, error labels, and repository-native guard
patterns. The benchmark CWE label is used only for post-hoc stratification.

Repair guidance is obligation-specific. It identifies the failed obligation and
the public contract that must remain passing, but does not expose the PoC input,
developer-test name, expected fixing code, or hidden CWE label.

## 4. Experimental Design

| Condition | Agent path | Security guidance | Monitor/gate | Repair |
|---|---|---|---|---|
| B0 | direct agent | none | observation only | none |
| C0 | Archon mediation | none | observation only | none |
| C1 | Archon mediation | static generic secure-C/C++ guidance | observation only | none |
| C2 | Archon + PGACS | task-derived selected obligations | enforcing | one bounded repair |
| H1 | optional upper bound | expert/CWE-informed obligations | enforcing | one bounded repair |

All conditions share the exact model snapshot, neutral task prompt, repository,
tool budget, timeout, and evaluator. `H1` is not pooled with C2.

Primary outcomes are:

- `secure_generation`: OSS-Fuzz PoC does not trigger and the oracle is conclusive;
- `functional_correctness`: compilation and relevant developer tests pass;
- `joint_accepted`: both security and functionality pass;
- `correct_security_block`: C2 blocks a candidate on affirmative security
  evidence while the harness remains healthy;
- `safe_system_outcome`: joint acceptance or correctly attributed security
  blocking;
- harness-error and inconclusive rates, reported separately.

A refusal or blocked run is beneficial only when tied to affirmative required
security evidence. Harness failures and inconclusive evaluations never count as
secure generation or correct security blocks.

## 5. Prototype Task Selection

The initial candidates are deliberately small and diverse, not a representative
benchmark sample:

| Task | Project | Target | Dataset label | Purpose |
|---|---|---|---|---|
| `910` | Little CMS | `src/cmsio0.c` | CWE-122 | buffer/size validation |
| `1065` | file | `src/funcs.c` | CWE-457 | initialization and API contract |
| `1468` | FFmpeg | `libavcodec/mimic.c` | CWE-129 | index validation |

Final admission depends on image availability, deterministic developer-test and
PoC replay, ground-truth secure pass, reconstructed vulnerable fail, and
reasonable prototype runtime. A failed candidate is replaced before freezing;
task choice is not adjusted after observing model outcomes.

## 6. Status

| Component | Status | Evidence / next gate |
|---|---|---|
| branch isolation | complete | branched from frozen PGACS v0.3 |
| manifest schema | implemented | schema `0.3.0` parser checks benchmark bindings |
| masked workspace adapter | implemented | exact digest, containment, one-marker admission |
| evaluator request adapter | implemented | evaluator revision and candidate digest bound |
| single-task oracle wrapper | implemented, unqualified | static compile check passes; calibration pending |
| post-generation region integrity | TBD | require syntax-aware or byte-span reconstruction |
| SecRepoBench policy pack | TBD | derive from visible C/C++ surface, not CWE label |
| task manifests | TBD | freeze only after source and oracle qualification |
| B0/C0/C1/C2 runner | TBD | reuse generic controller after typed result normalization |
| experiment | blocked by readiness | no effectiveness run is currently admissible |

## 7. Next Steps

1. Add focused tests for request validation, typed result normalization, timeout,
   missing-unit-test, compile-failure, and PoC-crash attribution.
2. Implement post-generation masked-region integrity checking.
3. Qualify the three candidate ARVO images using secure and vulnerable fixtures
   with at least three deterministic replays.
4. Freeze task manifests, source receipts, evaluator digest, and selected policy
   obligations generated without evaluator-only fields.
5. Extend the controlled runner and analyzer to SecRepoBench's typed probes.
6. Run one dry cell, then the frozen B0/C0/C1/C2 matrix.

## 8. Claim Boundary

The first study can demonstrate feasibility and mechanism behavior on three
repository-level C/C++ tasks. It cannot establish population-level improvement,
coverage of all 15 CWEs, general security, or superiority on SecRepoBench as a
whole. Any later benchmark claim requires a larger held-out sample, repeated
independent generations, and a preregistered analysis protocol.
