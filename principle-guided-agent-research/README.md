# Principle-Guided Agent Research

This folder collects the research design artifacts for the project:

```text
Use software engineering and security principles as executable policies that
guide coding-agent behavior toward secure and correct code generation.
```

## Reading Order

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
   - The recommended ultimate design: **Policy-Guided Agent Harness (PGAH)**.

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

The current final method is:

[Policy-Guided Agent Harness](05-final-method/policy-guided-agent-harness.md)

In one sentence:

```text
PGAH converts human-readable principles into executable policies, selects and
distributes them across coding-agent behavior phases, enforces them through a
harness, dynamically hardens policy state as risks appear, and evaluates both
trajectory changes and final correctness/security outcomes.
```
