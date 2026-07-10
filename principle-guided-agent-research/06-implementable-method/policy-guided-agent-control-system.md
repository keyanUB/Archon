# Implementable Method: Policy-Guided Agent Control System (PGACS)

Date: 2026-07-10

## Executive Summary

This document defines an implementable, agent-agnostic methodology for enhancing
coding agents' secure-coding behavior using principles. It is a re-architecture
of the earlier Policy-Guided Agent Harness (PGAH), keeping PGAH's strongest
ideas (policies as executable objects, evidence over self-report, fail-safe
blocking, monotonic hardening) but reorganizing them so the system is:

- **agent/LLM-agnostic by construction** — works across Claude Code, Codex,
  Cursor, Aider, and raw SDK loops, at whatever enforcement strength each agent
  supports;
- **buildable as a thin core** — a message bus plus a controller function, not a
  25-field schema and a workflow engine;
- **extensible by writing plug-ins** (packs and adapters), not by editing the
  engine.

The organizing idea is a strict separation:

```text
Policy (declarative data)  ≠  the three enforcement channels (mechanism)
```

One `Policy` object carries three thin handlers — one per layer — and the whole
system is driven by a common **event/intervention bus** that any agent joins
through a capability-declaring **adapter**.

This document is the methodology/approach. Experimental design (benchmarks,
datasets, multi-agent/multi-LLM comparisons) is deliberately out of scope here
and handled separately.

## Relationship to Prior Artifacts

| Prior artifact                      | What PGACS keeps                                                                             | What PGACS changes                                                                                                                                  |
| ----------------------------------- | -------------------------------------------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------- |
| `01-foundation`                     | Behavior taxonomy as phase vocabulary; select→distribute→enforce→observe pipeline            | Phases become soft signals, not a rigid DAG                                                                                                         |
| `02-expert-proposals/02` (security) | Policy-to-control compilation, forbidden workarounds, fail-safe outcomes, adversarial probes | Enforcement moves onto an event bus; monitors are per-event                                                                                         |
| `05-final-method` (PGAH)            | Policy objects, evidence ledger, dynamic monotonic hardening, tool brokering                 | Harness is a bus (not a workflow DAG); policy carries per-layer handlers; adapters make it agent-agnostic; the 25-field registry schema is deferred |

The core reframing versus PGAH: **the workflow harness is one adapter, not the
architecture.**

## Core Architecture

```text
                  ┌───────────────────────────────────────┐
   task + repo →  │  PolicyController (the brain)          │
                  │  - holds PolicyState (active policies)  │
                  │  - reads events, mutates state,         │
                  │    emits interventions                  │
                  │  - writes EvidenceLedger                │
                  └───────▲───────────────────┬─────────────┘
                          │ events            │ interventions
                          │ (obs stream)      │ (inject / allow-deny / loop-directive)
                  ┌───────┴───────────────────▼─────────────┐
                  │           AgentAdapter                   │
                  │  capabilities: {inject?, interceptTools?,│
                  │                 driveSteps?}             │
                  └───────▲───────────────────┬──────────────┘
                          │                   │
                   ANY CODING AGENT (Claude Code / Codex / Cursor / Aider / raw SDK)
```

Three subscribers (Layers A/B/C) read the shared `PolicyState` and react.
Adapters translate a specific agent into the common bus. Packs contribute
policies. Nothing else touches the core.

## 1. Policy-Harness: the Harness Is a Bus

The harness is a runtime that speaks two message types.

### Observation events (agent → controller, normalized by the adapter)

```ts
type ObservationEvent =
  | { kind: 'tool_call'; tool: string; args: unknown }
  | { kind: 'file_edit'; path: string; diff: string }
  | { kind: 'command_run'; cmd: string; exitCode: number; stdout: string; stderr: string }
  | { kind: 'message'; role: 'agent'; text: string }
  | { kind: 'phase_hint'; phase: BehaviorPhase } // soft, best-effort
  | { kind: 'dependency_added'; manifest: string; packages: string[] }
  | { kind: 'service_started'; bindAddress: string; port: number };
```

### Interventions (controller → agent, applied by the adapter)

```ts
type Intervention =
  | { kind: 'inject_context'; text: string; scope: 'system' | 'message' | 'file' }
  | { kind: 'tool_decision'; decision: 'allow' | 'deny' | 'require_evidence'; reason: string }
  | { kind: 'loop_directive'; directive: LoopDirective }
  | { kind: 'demand_evidence'; policyId: string; expected: string[] }
  | { kind: 'terminal_status'; status: TerminalStatus; rationale: string };
```

### Why a bus and not a DAG

A workflow DAG (the Archon/PGAH driver) is _one_ adapter — the `driveSteps`
case. A DAG cannot wrap Cursor or a raw SDK loop, and it confounds "policy
effect" with "forced structure." The bus subsumes the DAG and also works when
all the adapter can do is tail a log. This is the change that turns "an Archon
workflow" into "a system for any agent."

### The AgentAdapter interface

```ts
interface AgentAdapter {
  id: string;
  capabilities: { inject: boolean; interceptTools: boolean; driveSteps: boolean };
  onEvent(cb: (e: ObservationEvent) => void): void; // agent → controller
  apply(i: Intervention): Promise<void>; // controller → agent
}
```

Concrete adapters, cheapest → strongest enforcement:

| Adapter                                                         | inject | interceptTools | driveSteps | Enforcement                                       |
| --------------------------------------------------------------- | :----: | :------------: | :--------: | ------------------------------------------------- |
| Log/diff                                                        |   ✗    |       ✗        |     ✗      | post-hoc verify + re-prompt; works for _anything_ |
| Context                                                         |   ✓    |       ✗        |     ✗      | proactive guidance; external verify               |
| Hook/broker (Claude Code hooks, MCP tool-proxy, shell/PTY shim) |   ✓    |       ✓        |     ✗      | real-time allow/deny + evidence                   |
| Driver (Archon workflow)                                        |   ✓    |       ✓        |     ✓      | full phase gating                                 |

**Graceful degradation is a first-class requirement.** The same policies run on
every adapter; only enforcement strength varies. The weakest adapter still
delivers context + post-hoc verification; stronger adapters add real-time
control.

## 2. System Design: Three Layers, One Policy

Each `Policy` exposes three optional handlers. The layers are independent
subscribers to `PolicyState`, which is what makes them separately implementable
and separately testable.

```ts
interface Policy {
  id: string;
  packId: string;
  activation: Matcher; // when relevant? (§3)
  severity: 'advisory' | 'required' | 'fail_closed';

  prompt?: (ctx: RenderCtx) => PromptFragment; // Layer A — proactive
  monitors?: Monitor[]; // Layer B — detective
  invariants?: Invariant[]; // Layer C — corrective
}

type Monitor = (e: ObservationEvent, s: PolicyState) => Signal | null;
type Signal = { level: 'safe' | 'suspicious' | 'violation'; evidence: EvidenceItem };
type Invariant = {
  id: string;
  check: (before: RepoState, after: RepoState) => boolean;
  message: string;
};
```

### Layer A — Code-LLM layer (proactive / preventive)

Renders **phase-appropriate slices** of active policies into whatever channel
the adapter supports (system prompt, `AGENTS.md`/`CLAUDE.md`, injected message).

- **Phase-conditioned rendering, not full-corpus dumping.** The same path-
  traversal policy renders as an _inspection question_ early and an
  _implementation rule_ later. Phase comes from `phase_hint` events or a
  lightweight classifier — a soft signal, never a hard gate.
- If the adapter cannot inject mid-run (`inject:false`), Layer A front-loads
  everything into the initial context and the system leans on Layers B/C.
- Cost of failure: low (it is advice). This is the floor of the system.

### Layer B — Harness/monitor layer (detective / runtime probing)

Every observation event is fanned out to the `monitors` of all active policies.
A monitor is a **cheap, deterministic classifier over one event** that emits a
`Signal` and writes evidence. Two tiers:

- **Passive monitors** (always on, near-free): regex/AST/heuristic over diffs
  and commands — `StrictHostKeyChecking=no`, `shell=True` with interpolation,
  `yaml.load`, secret-shaped strings, `chmod 777`, a new dependency in a
  manifest, SQL string interpolation.
- **Active probes** (armed on demand, expensive): exercise the artifact — start
  the service and issue an unauthenticated request, feed `../../etc/passwd`, run
  the security test, check the fail-safe preflight. Probes are **scheduled by
  Layer C**, never run blindly, because they cost time and tokens.

**The model's prose is never evidence.** Signals — grounded in observed diffs,
commands, and probe results — are the input to Layer C.

### Layer C — Loop/conditioning layer (corrective / predictive)

The novel layer. Agents are loops (`act → observe failure → adapt → retry`), and
the danger is _insecure adaptation under failure pressure_. Layer C runs a
**predict-then-condition** step at each loop boundary:

1. **State**: events so far, active policies, satisfied vs missing evidence,
   recent failure signals, retry count.
2. **Predict**: estimate next-step risk. Example rule: "build just failed +
   a `required` validation policy is unsatisfied → high probability the agent
   weakens validation to get green." Start with rules over the state; upgrade to
   a small learned predictor once trajectories are logged.
3. **Condition**: pre-shape the next iteration _before the agent acts_ — inject a
   targeted anti-shortcut reminder, arm a probe to catch the specific
   regression, tighten a policy to `fail_closed`, or (broker case)
   pre-authorize/deny the tool it is about to reach for.
4. **Invariant check**: after the step, diff against `invariants` — did a repair
   delete a security test, flip `verify=True`→`False`, broaden an allowlist? If
   so → `violation` → forced rollback or re-prompt, never silent.

```ts
type LoopDirective =
  | { kind: 'reinforce'; policyId: string; text: string }
  | { kind: 'arm_probe'; probeId: string }
  | { kind: 'harden'; policyId: string; to: 'required' | 'fail_closed' }
  | { kind: 'rollback'; reason: string }
  | { kind: 'stop'; status: TerminalStatus };
```

Loop conditioning **+ monotonic hardening** (policy state only gets stricter
during a run unless a human relaxes it) is the concrete mechanism that stops the
single most damaging failure mode. It is implementable as a pure function
`(PolicyState, Event[]) → Intervention[]`.

## 3. Automatic Policy Selection On Demand (Across All Three Layers)

Selection is **not one-shot**. It is a controller mutating shared state that all
three layers observe.

```text
initial task surface ──► select()   ──► PolicyState v0
                                            │
   ObservationEvent  ──► reassess() ──► PolicyState v1 (⊇ v0, monotonic)
                                            │
        (Layers A/B/C automatically pick up the delta)
```

- **v0** from task-surface extraction: LLM structured-output + deterministic repo
  scan (see §5 for the mechanism split).
- **Deltas** fire on trigger events. Each delta simultaneously touches all three
  layers _because the `Policy` object carries all three handlers_:

| Trigger event                   | Delta effect (A / B / C)                                                                                     |
| ------------------------------- | ------------------------------------------------------------------------------------------------------------ |
| New dependency                  | add supply-chain pack → prompt fragment / arm lockfile+provenance monitors / add "no unpinned dep" invariant |
| `subprocess`/shell sink appears | command-injection policy → prompt rule / arm metachar monitor / invariant `no shell=True with interpolation` |
| Service binds a port            | runtime-exposure policy → prompt note / arm auth+bind probe / invariant `no 0.0.0.0 unless approved`         |
| Missing trust input discovered  | fail-safe policy → prompt gate / arm preflight probe / invariant `do not activate`                           |
| Build passes, no tests exist    | test-requirement policy → prompt demand / arm "tests present" monitor                                        |

- **Every delta is logged with rationale** — required later for learned
  selection (§5).

### Guardrails against overload (dynamic adoption's real failure mode)

- **Policy budget** (target 3–8 active for ordinary tasks; more only if each has
  a concrete control + validator).
- **Redundancy suppression** across near-duplicate policies.
- **Policy state ≠ prompt pressure.** A policy can be _active in state_ (monitors
  armed, invariants live) without being _re-rendered into every prompt_. This
  decouples enforcement breadth from prompt cost.

## 4. Cross-Task Extensibility: Policy Packs as Plug-Ins

The plug-in seam is a **shared surface vocabulary** — a small fixed ontology
every pack speaks. The core (bus, controller, ledger, three layers, adapters)
never changes; a pack contributes domain content.

```ts
type SurfaceVocabulary = {
  inputChannels: string[]; // http_request, cli_arg, file, env, message
  sinks: string[]; // sql, shell, filesystem, template, deserialization, network
  assets: string[]; // secrets, PII, auth_state, filesystem, service_ports
  trustBoundaries: string[]; // client/server, remote/local, user/admin
  actions: string[]; // dep_install, service_start, credential_create, permission_change
  runtimeExposure: string[]; // local_only, network_service, public_api, persistent_remote_access
};

interface PolicyPack {
  id: string;
  version: string;
  trustTier: 'core' | 'trusted' | 'experimental' | 'advisory';
  policies: Policy[];
  matchers: Matcher[]; // surface signals → candidate policies
  probes?: ProbeTemplate[];
}
```

```text
core/                # bus, controller, ledger, 3 layers, adapters (STABLE)
packs/
  file-parser/       # path traversal, safe parse, error disclosure
  web-api/           # authn/z, input validation, output encoding, size/rate limits
  database/          # parameterization, object-level authz, transaction safety
  env-setup/         # host authenticity, least privilege, fail-safe activation
  data-pipeline/     # ← non-codegen: PII handling, schema validation, sink authz
  ml-training/       # ← beyond code: data provenance, eval leakage, unsafe pickle
  agent-tooling/     # ← prompt injection, tool authz, evidence integrity
```

**Test of a real plug-in architecture:** a non-code-generation family drops into
the same select→distribute→monitor→condition machinery by writing a pack — no
core changes. Example: a data-pipeline task where the "sink" is a warehouse
table and the "asset" is PII reuses Layer B monitors (schema-violation, PII in
logs) and Layer C invariants (no dropped validation step) unchanged.

**Trust tiers** prevent an experimental pack from silently weakening core gates:
`experimental`/`advisory` packs can _recommend_ policies but cannot _hard-gate_ a
run; only `core`/`trusted` packs can raise severity to `fail_closed`.

## 5. Policy Selection and Enforcement Mechanism

Decision: **"LLM proposes, rules dispose, learning ranks."** Do not use one
mechanism everywhere — split by _function_, because perception and enforcement
have opposite requirements.

| Function                                                                          | Requirement                           | Mechanism                                                   | Rationale                                                                         |
| --------------------------------------------------------------------------------- | ------------------------------------- | ----------------------------------------------------------- | --------------------------------------------------------------------------------- |
| Task-surface extraction & policy _proposal_                                       | recall over messy NL                  | LLM (structured output) + retrieval + GRASP-graph expansion | fuzzy perception is what LLMs do well; needs recall over the corpus               |
| High-precision safety triggers                                                    | never miss critical cases             | deterministic rules (sink+input → policy)                   | non-negotiable risks need 100% recall on the known-critical set                   |
| **Enforcement** (allow/deny, evidence-satisfied?, invariant-violated?)            | auditable, reproducible, non-gameable | **deterministic decision logic — never an LLM**             | a probabilistic gate is not a gate; must be replayable and explainable            |
| Soft/semantic checks (does this _actually_ validate? does the error leak a path?) | judgment beyond regex                 | critic/judge LLM, **output = evidence only**                | too subtle for AST, but its verdict is evidence _gated by rules_, never authority |
| Selection _optimization_ (rank within the safe candidate set)                     | improves with data                    | decision tree / GBDT ranker → later constrained bandit      | interpretable, works with small labels, ranks _within_ a rules-vetted set         |

### Verdict: hybrid, not RL, and not a single "selector agent"

- **LLM policy-proposer** (perception) + **deterministic rule triggers** (safety
  floor) produce a candidate set.
- **Decision-tree/GBDT ranker** orders it once logged decisions + outcomes exist.
- **Deterministic controller** owns all enforcement.
- **Critic LLM** supplies semantic evidence where deterministic checks cannot
  reach.

### Why not RL / a large learned agent for selection or enforcement

- Rewards are sparse, noisy, and delayed.
- Unsafe exploration is unacceptable in a security setting.
- Decisively: the enforcement path must be auditable and reproducible to support
  a defensible research claim. Transparency _is_ the contribution ("principled
  control"), not a limitation.

RL earns a place only later, as a **constrained ranker over an already-safe
candidate set**, with offline policy evaluation before any online use.

### LLMs are advisors with no authority

The moment an LLM can relax a gate, prompt injection from repo/issue/dependency
text becomes a hole in _this_ system. Authority lives only in deterministic code
plus human. The proposer and critic advise; they never decide.

## Key Design Choices and Rationales

1. **Separate policy-data from enforcement channels (one Policy, three
   handlers).** Makes plug-ins, dynamic adoption, and per-layer testing
   possible. A `PolicyDelta` touching all three layers is one object mutation,
   not three subsystems to coordinate.
2. **Event/intervention bus + capability-declaring adapters.** The only way to be
   genuinely agent/LLM-agnostic. Same policies span Claude Code (hooks), Codex,
   Cursor, and a log file; enforcement degrades gracefully rather than breaking.
3. **Deterministic enforcement, LLM perception.** Gates must be auditable,
   reproducible, and injection-resistant; selection benefits from LLM recall.
   Never mix the two.
4. **Monitors/probes produce evidence; model prose never does.** Agents
   overclaim; "no evidence, no claim" is the backbone of enforcement and of any
   later measurement.
5. **Loop conditioning = predict-then-condition + monotonic hardening.** The
   highest-value, least-covered failure mode is insecure adaptation under
   failure pressure; intervene _before_ the retry, and forbid state relaxation.
6. **Policy state ≠ prompt pressure (phase-local injection + budget).** Dynamic
   adoption's failure mode is overload; keep policies armed in state without
   re-rendering them into every prompt.
7. **Plug-in packs over a fixed surface vocabulary; trust tiers.** Extensibility
   to new task families (including non-codegen) with zero core changes, without
   letting an experimental pack weaken core gates.
8. **Graceful degradation is a first-class requirement.** The weakest adapter
   still delivers context + post-hoc verify; stronger adapters add real-time
   control. Also a clean experimental knob later.

## Minimal Implementable Core (Build Order)

Build the thinnest slice that exercises all three layers end-to-end, then widen.
Every later capability is an addition at a stable seam, not a redesign.

1. **Bus + `EvidenceLedger` + `PolicyState`** — pure data + a controller
   function.
2. **One adapter** — the context+hook adapter for an agent already in use
   (Claude Code hooks or an MCP tool-proxy) — giving inject + interceptTools.
3. **One pack, ~6 policies** (path traversal, input validation, safe parse,
   error disclosure, command injection, dependency pinning), each with a prompt
   fragment + at least one passive monitor + one invariant.
4. **Deterministic controller** with a handful of dynamic triggers and monotonic
   hardening.
5. **One active probe + one critic-LLM check** — to prove the expensive path
   works.
6. **Then widen**: more adapters (Codex, log-only), more packs, the learned
   ranker.

## Interfaces At A Glance

```ts
// The whole core in one view.
interface PolicyController {
  state: PolicyState; // active policies (monotonic)
  ledger: EvidenceLedger; // append-only evidence
  ingest(e: ObservationEvent): Intervention[]; // event → deltas + interventions
  select(surface: TaskSurface): PolicyState; // §5 proposer + rules
  reassess(e: ObservationEvent): PolicyDelta | null; // §3 dynamic adoption
  gate(): TerminalStatus; // deterministic final decision
}

type TerminalStatus =
  | 'SUCCESS_VERIFIED'
  | 'SUCCESS_WITH_RESIDUAL_RISK'
  | 'BLOCKED_INPUT_REQUIRED'
  | 'BLOCKED_POLICY_CONFLICT'
  | 'FAILED_FUNCTIONAL_VALIDATION'
  | 'FAILED_POLICY_VALIDATION'
  | 'FAILED_HARNESS_ERROR';
```

## Final Definition

```text
The Policy-Guided Agent Control System converts security/engineering principles
into Policy objects that each carry a prompt fragment, runtime monitors, and
repair invariants; selects a compact policy set from task surface and adapts it
dynamically across the trajectory; enforces it through three graceful-degrading
layers (proactive prompt, detective monitoring/probing, corrective loop
conditioning) driven by an event/intervention bus that any agent joins via a
capability-declaring adapter; keeps all enforcement deterministic while using
LLMs only to propose and to supply evidence; and extends to new task families by
writing plug-in packs over a fixed surface vocabulary — never by editing the
core.
```
