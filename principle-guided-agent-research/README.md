# Principle-Guided Agent Research

This folder collects the research design artifacts for the project:

```text
Use software engineering and security principles as executable policies that
guide coding-agent behavior toward secure and correct code generation.
```

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
   - [Method overview](06-implementable-method/policy-guided-agent-control-system.md)
     — the design at pitch/overview altitude.
   - [Detailed design & decision record](06-implementable-method/pgacs-detailed-design.md)
     — the build-from engineering spec: full interfaces, runtime control flow,
     failure modes, harness threat model, and 13 systematic decision records
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

In one sentence:

```text
PGACS converts principles into Policy objects that each carry a prompt fragment,
runtime monitors, and repair invariants; selects a compact policy set from task
surface and adapts it dynamically across the trajectory; enforces it through
three graceful-degrading layers (proactive prompt, detective monitoring/probing,
corrective loop conditioning) driven by an event/intervention bus that any agent
joins via a capability-declaring adapter; keeps enforcement deterministic while
using LLMs only to propose and supply evidence; and extends to new task families
via plug-in packs over a fixed surface vocabulary.
```
