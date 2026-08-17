# Proposal Review and Evaluation

Date: 2026-07-09

Reviewer stance: assistant professor researcher evaluating methodology
proposals for a security research project.

## Reviewed Proposals

| ID  | Proposal                                                            | Role                                                         |
| --- | ------------------------------------------------------------------- | ------------------------------------------------------------ |
| P1  | `../02-expert-proposals/01-software-architecture-policy-harness.md` | Senior software architecture expert                          |
| P2  | `../02-expert-proposals/02-software-security-policy-controls.md`    | Software security expert                                     |
| P3  | `../02-expert-proposals/03-ml-policy-selection-dynamic-adoption.md` | Machine learning expert                                      |
| P4  | `../02-expert-proposals/04-ai-agent-security-policy-harness.md`     | AI agent security expert                                     |
| P5  | `../02-expert-proposals/05-empirical-evaluation-methodology.md`     | Empirical software engineering / benchmark evaluation expert |

The review uses the rubric in:

`principle-guided-agent-research/archive/04-review/review-rubric.md`

## Executive Assessment

The five proposals are highly complementary. None should be used alone.

The most promising final research method should combine:

- P1's architecture and artifact/state-machine design;
- P2's security-control and fail-safe enforcement model;
- P3's constrained hybrid policy-selection and dynamic-adoption model;
- P4's agent-process security controls, tool broker, evidence integrity, and
  plugin trust model;
- P5's empirical evaluation protocol, ablations, metrics, and statistical
  framing.

The strongest common insight is that the research should not be framed as
"better security prompting." It should be framed as:

```text
policy-guided trajectory control for coding agents
```

That means principles are converted into executable policy objects, selected
for a task, distributed across behavior phases, enforced by a harness, updated
during the trajectory, and evaluated through both trajectory and outcome
metrics.

## Score Summary

Scores are 1-5.

| Criterion                     | P1 Architecture | P2 Security |   P3 ML | P4 Agent Security | P5 Evaluation |
| ----------------------------- | --------------: | ----------: | ------: | ----------------: | ------------: |
| Research fit                  |               5 |           5 |       5 |                 5 |             5 |
| Policy-harness design         |               5 |           4 |       4 |                 5 |             4 |
| Trajectory-level control      |               5 |           5 |       5 |                 5 |             5 |
| Dynamic selection/adoption    |               5 |           4 |       5 |                 5 |             4 |
| Security enforcement/evidence |               4 |           5 |       4 |                 5 |             4 |
| Cross-task extensibility      |               5 |           4 |       5 |                 4 |             5 |
| Evaluation readiness          |               4 |           4 |       4 |                 4 |             5 |
| Implementation practicality   |               5 |           4 |       4 |                 4 |             4 |
| Originality/contribution      |               4 |           4 |       5 |                 5 |             5 |
| Clarity                       |               5 |           5 |       5 |                 5 |             5 |
| **Overall**                   |         **4.7** |     **4.4** | **4.6** |           **4.7** |       **4.6** |

## Proposal 1 Review: Software Architecture Policy Harness

### Strengths

P1 is the best architectural foundation. It provides the cleanest system
boundary between the coding LLM and the harness. Its strongest contributions
are:

- explicit separation between principles and executable policies;
- artifact set: task surface, selected policies, phase plan, evidence ledger,
  validation results, residual risk;
- state-machine framing;
- dynamic policy adoption;
- plugin model;
- implementation roadmap aligned with a real harness such as Archon.

P1 also captures a key lesson from prior experiments: a provider/node
completion is not enough. Validation output must be structurally meaningful.
This directly addresses the secure environment setup case where provider-limit
text was marked complete.

### Weaknesses

P1 is broad and architecture-heavy. It needs sharper security semantics in
three places:

- exactly when a policy becomes `fail_closed`;
- how tool calls are blocked or escalated;
- how validators distinguish weak evidence from strong evidence.

These gaps are covered well by P2 and P4, so P1 should be treated as the
system backbone, not the full method.

### Suggestions

- Keep P1's artifact model as the canonical architecture.
- Merge P4's tool broker and evidence-integrity details into P1.
- Merge P2's policy-to-control compilation and fail-safe categories into P1's
  `PolicyRecord` and `PhaseBinding` schemas.

## Proposal 2 Review: Software Security Policy Controls

### Strengths

P2 is the strongest security-control proposal. It correctly treats principles
as controls that must compile into:

- risk triggers;
- required controls;
- forbidden workarounds;
- inspection evidence;
- implementation evidence;
- validation evidence;
- adversarial tests;
- residual-risk reporting.

Its most important contribution is security semantics. It understands that
functional success and security success can diverge. The autossh example is
used correctly: a live tunnel can be less secure than a blocked scaffold.

P2 also emphasizes adversarial tests and runtime probes, which directly
responds to the BaxBench finding that explicit test/runtime verification is
rare.

### Weaknesses

P2 is less detailed than P1 on architecture and less detailed than P3 on
automatic selection. It says what security controls should exist, but not
fully how selection improves over time or how plugins should be managed.

### Suggestions

- Use P2 as the security-control compiler.
- Integrate its control-contract idea into the final `PolicyRecord` model.
- Make its fail-safe categories formal, especially for high-risk
  underspecified tasks.

## Proposal 3 Review: ML Policy Selection and Dynamic Adoption

### Strengths

P3 is the strongest answer to the first major research question: how to
optimize policy selection.

Its most important contributions are:

- treat selection as a constrained decision problem, not prompt ranking;
- start with transparent hybrid selection;
- use rule triggers for safety-critical precision;
- use retrieval for recall;
- use graph expansion for structured policy relationships;
- use LLM extraction only as an assistant, not authority;
- log rejected candidates for future learning;
- introduce supervised ranking only after human labels exist;
- introduce contextual bandits only after reliable outcome labels exist.

P3 is especially strong because it avoids premature RL. It recognizes that
unsafe exploration and sparse reward make unconstrained RL inappropriate for
security-sensitive code generation.

### Weaknesses

P3 is selection-heavy. It needs the harness enforcement and evidence model from
P1/P2/P4 to avoid becoming a policy recommendation engine rather than a secure
coding method.

Its proposed reward model is useful, but it needs a stronger statement that
some constraints are non-negotiable and cannot be traded for reward.

### Suggestions

- Use P3's staged selector roadmap.
- Treat hard security constraints as preconditions before reward computation.
- Preserve rejected candidates and selection propensities from the first
  prototype; this will make later learning possible.

## Proposal 4 Review: AI Agent Security Policy Harness

### Strengths

P4 is the strongest proposal for securing the agentic process itself.

Its unique contributions are:

- prompt-injection resistance;
- tool brokering;
- evidence-spoofing prevention;
- unsafe-autonomy control;
- benchmark-completion shortcut detection;
- plugin trust tiers;
- append-only evidence;
- dynamic hardening monotonicity;
- final claim gate.

P4 is crucial because it addresses a risk that P1/P2/P3 only partially cover:
the agent and its environment are themselves attack surfaces. Repo files,
issue text, logs, dependency metadata, generated files, and benchmark prompts
can all contain misleading or hostile instructions.

### Weaknesses

P4 is very security-harness focused and less concerned with empirical
methodology or selection optimization. Its strict controls could create
overhead or overblocking if not paired with P3's selection and P5's evaluation.

### Suggestions

- Make P4's tool broker mandatory in the final method.
- Keep dynamic hardening monotonic by default, but define a controlled
  relaxation procedure for legitimate false positives.
- Use P4's plugin trust model before allowing external policy packs.

## Proposal 5 Review: Empirical Evaluation Methodology

### Strengths

P5 is the strongest proposal for making the work publishable. It correctly
frames the research contribution as a causal trajectory-control intervention,
not an anecdotal comparison.

Its most important contributions are:

- experimental unit: `task x agent/provider x policy condition x run replicate`;
- condition ladder: baseline, generic reminder, flat policy dump, selected
  policies, phase-distributed policies, dynamic controller, oracle policies;
- ablation design;
- trajectory metrics;
- correctness/security outcome metrics;
- human annotation plan;
- statistical analysis plan;
- mediation framing;
- cross-task and cross-provider generalization.

P5 prevents a common research mistake: claiming that "more defensive coding
events" proves better security. It insists on independent outcome scoring.

### Weaknesses

P5 depends on the architecture and policy machinery from the other proposals.
It evaluates the method but does not by itself specify the operational method.

### Suggestions

- Use P5's experimental conditions as the default evaluation plan.
- Freeze the trajectory codebook after pilot studies before confirmatory
  evaluation.
- Include safe blocking as a positive security outcome when task semantics
  justify it.

## Cross-Proposal Agreements

All proposals agree on these points:

1. Policy state should live outside the coding LLM.
2. Full policy dumping is inferior to compact selected policy sets.
3. Policies must be bound to behavior phases.
4. The harness must collect independent evidence.
5. Dynamic policy adoption is necessary because new risks appear during the
   trajectory.
6. Repair and adaptation are high-risk phases.
7. Runtime probes and adversarial tests are underused by baseline agents and
   should be explicitly scheduled.
8. Missing trust inputs should produce fail-safe blocking in high-risk tasks.
9. Trajectory metrics must be paired with final correctness/security outcomes.
10. Extensibility requires a plugin-style policy architecture.

## Cross-Proposal Tensions

### Tension 1: Harness Strictness vs Task Completion

P2 and P4 emphasize fail-closed behavior. P1 and P3 emphasize adaptability.
The final method should resolve this by using blocking levels:

- `advisory`;
- `required`;
- `fail_closed`.

High-risk ambiguity and non-negotiable security controls should be
`fail_closed`; lower-risk controls can be `required` or `advisory`.

### Tension 2: Dynamic Adoption vs Policy Overload

Dynamic policy adoption can add too many obligations. The final method needs:

- policy budget;
- redundancy suppression;
- severity threshold;
- phase-local injection only;
- evidence-driven removal from active prompt context while preserving ledger
  state.

Policy state can remain active in the ledger without being repeated in every
prompt.

### Tension 3: Learned Selection vs Auditable Security

P3 proposes learning. P4 warns against policy bypass. The final method should
start transparent and only allow learned models to rank or recommend policies
within a constrained safe candidate space.

### Tension 4: Security Outcome vs Functional Outcome

Security controls can reduce functional pass rate if overapplied. P5 correctly
requires reporting negative interactions. The final evaluation should measure
joint success:

```text
functional pass AND security pass
```

not either alone.

## Overall Recommendation

The final method should be named:

```text
Policy-Guided Agent Harness (PGAH)
```

The core method should have five pillars:

1. **Policy registry:** normalized executable policies derived from principles.
2. **Policy selector:** transparent hybrid selection with later supervised or
   constrained bandit optimization.
3. **Phase distributor:** maps policies to behavior-phase obligations.
4. **Policy harness:** mediates prompts, tools, loops, validators, probes, and
   evidence.
5. **Evaluation layer:** measures trajectory changes and final
   correctness/security outcomes.

This combination is confident and promising for the security community because
it is:

- operational, not just rhetorical;
- auditable;
- measurable;
- security-aware at the agent-process level;
- extensible across tasks;
- empirically evaluable.

## Priority Suggestions Before Implementation

1. Define canonical schemas first.
2. Build a small policy registry with 20-40 high-value policies.
3. Implement a transparent selector before attempting learning.
4. Build the evidence ledger early; it is the backbone of enforcement and
   evaluation.
5. Implement runtime/adversarial probe templates for a few task families.
6. Run a pilot on 10-20 tasks before scaling to BaxBench.
7. Treat the dynamic policy controller as a later stage unless the static
   phase-distributed harness is stable.

## Final Evaluation Judgment

All five proposals are strong. The final design should not choose one winner.
It should integrate them.

The architecture and agent-security proposals define the harness. The
software-security proposal defines what policies must enforce. The ML proposal
defines how policies are selected and adapted. The empirical proposal defines
how to prove the method works.

Together they support a publishable research direction:

```text
Principle-derived policies can improve secure code generation when they are
selected for task risk, distributed across agent behavior phases, enforced by a
harness, dynamically updated during execution, and evaluated with both
trajectory and outcome metrics.
```
