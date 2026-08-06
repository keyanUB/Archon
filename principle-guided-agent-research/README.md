# Principle-Guided Agent Research

This folder collects the research design artifacts for the project:

```text
Use software engineering and security principles as executable policies that
guide coding-agent behavior toward secure and correct code generation.
```

## Status at a Glance

The repository separates six kinds of material:

- **Target architecture:** the event/intervention bus, capability-aware adapters,
  three enforcement layers, evidence ledger, and deterministic terminal gate;
- **Implemented deterministic core:** an 84-policy domain registry plus three
  core fallback policies, uncertainty-aware task surfaces, explainable selection,
  and reproducible generated artifacts;
- **Implemented generic C2 mechanism:** one controller now supports three frozen
  BaxBench code-generation tasks with compatibility-adjudicated obligations,
  common Claude OS sandboxing, phase-attributed trajectory evidence, cumulative
  scope enforcement, independent typed probes, one bounded repair, a
  hash-chained ledger, and a deterministic terminal gate;
- **Historical experiments:** the frozen 12-task selector studies and one paired
  ZIP trajectory run, retained with their limitations and exact artifacts;
- **Completed prompt-only pilot:** all 10 frozen BaxBench Python/FastAPI tasks
  and 30 agent cells evaluated across direct Claude, ordinary Archon, and
  semantic policy-guided Archon; conservative joint success was 3/10, 5/10,
  and 4/10 respectively;
- **Next C2 experiment:** the three BaxBench tasks are adapter-ready after
  secure/vulnerable oracle calibration and deterministic replay, but require
  renewed live agent-boundary qualification for the corrected frozen hashes.
  Then run the frozen B0/C0/C1/C2 comparison and
  integrity-check its results. The six SWE-bench Verified and SetupBench tasks
  remain future integrations gated on adapters and/or independent security
  oracles.

The preserved July 2026 semantic-selector metrics are historical evidence. That
run received task-family metadata from the silver-label artifact, so it must be
rerun without that field before supporting claims about classification-independent
semantic selection. The current selector code now excludes task-family metadata
and binds selections and adjudications to content hashes. The BaxBench pilot's
ten-task selection is frozen against a task-only input view and contains no
benchmark CWE labels, tests, or exploits.

## Reading Order

0. [Team Proposal / Pitch](00-pitch/security-by-design-agents-proposal.md)
   - The persuasive entry point: motivation (agentic coding shifts authorship to
     people without secure-coding knowledge), the evidence that agent-generated
     code is measurably insecure, the idea (an automatic security harness that
     binds principles to each intervention point), the design choices with
     rationales, why build on Archon, risks, and the first milestone to fund.

1. [Research Foundation](01-foundation/research-foundation.md)
   - Defines the project idea, the two core research questions, available
     principle/policy resources, BaxBench behavior taxonomy, and initial
     method architecture.

2. [Expert Proposals](02-expert-proposals/)
   - Five role-specific methodology proposals:
     - software architecture;
     - software security;
     - machine learning;
     - AI agent security;
     - empirical evaluation.

3. [Five-Agent Synthesis](03-synthesis/five-agent-methodology-synthesis.md)
   - Integrates the first round of expert discussion into a coherent method
     direction.

4. [Review and Scoring](04-review/proposal-review-and-evaluation.md)
   - Reviews the five detailed proposals, scores them, identifies strengths
     and weaknesses, and recommends how to combine them.

5. [Final Method](05-final-method/policy-guided-agent-harness.md)
   - The recommended conceptual design: **Policy-Guided Agent Harness (PGAH)**.

6. Implementable Method: **Policy-Guided Agent Control System (PGACS)**.
   Re-architects PGAH to be agent/LLM-agnostic (event/intervention bus +
   capability-declaring adapters), separates policy data from three enforcement
   layers (proactive prompt / detective monitoring / corrective loop
   conditioning), makes dynamic policy selection touch all three layers, and
   extends to new task families via plug-in packs. Two documents:
   - [Milestone 1: Policy Registry and Task-Surface Extraction](06-implementable-method/01-policy-registry-and-task-surface.md)
     — the first implementation step: normalize the policy corpus and the task
     surface so selection has a stable input.
   - [Milestone 1 Validation](06-implementable-method/02-milestone-1-validation.md)
     — the first validation pass: check representative task families and the
     expected registry/surface behavior.
   - [Milestone 2: Explainable Policy Selection](06-implementable-method/03-policy-selection.md)
     — deterministic safety rules plus budgeted ranking, optional LLM proposals,
     replayable decisions, and monotonic dynamic adoption.
   - [Milestone 2.1: Generic Security Floor and Implementation Record](06-implementable-method/04-generic-security-floor-and-implementation-plan.md)
     — prevents sparse or failed surface extraction from producing an empty
     security decision through explicit surface status, a three-policy core
     fallback floor, reassessment triggers, and focused tests.
   - [Prototype Policy-Selection Evaluation](07-prototype-evaluation/README.md)
     — independent subagent-generated silver labels for 12 cross-family tasks,
     reproducible metrics, observed limitations, and the next minimal update.
   - [Expanded Principle Corpus](08-expanded-principle-corpus/README.md)
     — a compact, provenance-preserving catalog of all 367 prepared records,
     with 298 granular principles/policies available for semantic selection.
   - [LLM Semantic Selector Prototype](09-semantic-selector-evaluation/README.md)
     — a tool-less, schema-constrained semantic selector, its historical
     task-family-confounded 12-task run, and the corrected hash-bound input and
     adjudication path.
   - [Policy-Guided Coding Trajectory Prototype](10-guided-trajectory-prototype/README.md)
     — a paired Codex experiment on one untrusted-file task, with raw
     trajectories and independent required-versus-hardening probes showing both
     the added defenses and the cost/maintainability tradeoffs of policy
     injection.
   - [Comprehensive Prototype Report and Roadmap](11-prototype-report-and-roadmap/README.md)
     — consolidates the implemented prototype, all selector and trajectory
     experiments, supported and unsupported claims, threats to validity, and
     the controlled cross-task plan for prompt-only versus minimal-harness
     evaluation.
   - [Archon C2 Security-Harness Prototype](12-archon-c2-prototype/README.md)
     — the first actual Archon workflow combining frozen policies, isolated
     deterministic evidence, one bounded repair, and a terminal gate.
   - [C2 As-Built Technical Design](12-archon-c2-prototype/technical-design.md)
     — implementation-level architecture, contracts, control flow, evaluator
     isolation, evidence semantics, threat model, failure modes, and decisions.
   - [Superseded Smoke Dataset](13-smoke-dataset/README.md)
     — a superseded historical cohort retained only for provenance; it is not
     part of the active benchmark plan.
   - [Ten-Task BaxBench Pilot](14-baxbench-pilot/README.md)
     — the source-pinned prompt-only backend-generation comparison across a
     direct agent, ordinary Archon, and semantic policy-guided Archon, with
     official functional tests and security exploits.
   - [Small Multi-Benchmark Prototype](15-multibench-prototype/README.md)
     — the active nine-task development registry across BaxBench, SWE-bench
     Verified, and SetupBench, with readiness and leakage gates.
   - [SecRepoBench Customization](16-secrepobench-customization/README.md)
     — an experimental branch extension for masked C/C++ repository completion,
     ARVO/OSS-Fuzz evaluation, evaluator-label isolation, and a three-task
     feasibility study.
   - [Method overview](06-implementable-method/policy-guided-agent-control-system.md)
     — the design at pitch/overview altitude.
   - [Detailed design & decision record](06-implementable-method/pgacs-detailed-design.md)
     — the build-from engineering spec: full interfaces, runtime control flow,
     failure modes, harness threat model, and 19 systematic decision records
     (ADRs) with rationale.

   The Archon-root prototype for this step lives in:
   - `scripts/generate-pgacs-research-artifacts.ts`
   - `scripts/pgacs-policy-registry.ts`
   - `scripts/pgacs-task-surface.ts`
   - `.archon/data/research/pgacs/`

## Supporting External Inputs

These documents are referenced by the research artifacts but live outside this
folder:

- `reports/baxbench_agent_behavior_codex.md`
- `reports/grasp-secure-coding/workflow-comparison.md`
- `reports/secure-environment-setup/docker-comparison.md`
- `reports/agent-behavior-comparison/swebench-django-sonnet-vs-archon.md`
- `.archon/data/research/grasp-secure-coding/owasp-scp.md`
- `.archon/data/research/grasp-secure-coding/scp-graph.json`
- `.archon/data/research/secure-environment-setup/setup-environment-policies.json`

## Core Output

The current recommended method is the implementable design:

[Policy-Guided Agent Control System](06-implementable-method/policy-guided-agent-control-system.md)
(PGACS), which re-architects the earlier conceptual design
[Policy-Guided Agent Harness](05-final-method/policy-guided-agent-harness.md)
(PGAH) for buildability and agent-agnosticism.

The active executable prototype is the generic PGACS C2 runner documented in
[`15-multibench-prototype/README.md`](15-multibench-prototype/README.md) and
[`15-multibench-prototype/technical-design.md`](15-multibench-prototype/technical-design.md).
It separates policy selection from compatibility-aware activation, enforces a
frozen obligation/probe contract, uses typed oracle outcomes, and permits one
candidate-only repair. The fixed ZIP workflow remains an implementation record;
the prompt-only BaxBench v0.1 results remain a legacy ablation.

The same folder contains the source-pinned nine-task integration roadmap across
BaxBench, SWE-bench Verified, and SetupBench, with explicit adapter and
oracle-validation gates before any task may
contribute effectiveness evidence.

In one sentence:

```text
PGACS converts principles into Policy objects that each carry a prompt fragment,
runtime monitors, and repair invariants; selects a compact policy set from task
surface, activates a compact generic security floor when specific matching is
not supported, and adapts policy state dynamically across the trajectory;
enforces it through three graceful-degrading layers (proactive prompt,
detective monitoring/probing, corrective loop conditioning) driven by an
event/intervention bus that any agent joins via a capability-declaring adapter;
keeps enforcement deterministic while using LLMs only to propose and supply
evidence; and extends to new task families via plug-in packs over a fixed
surface vocabulary.
```
