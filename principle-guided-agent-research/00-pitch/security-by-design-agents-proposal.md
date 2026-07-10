# Proposal: An Automatic Security Harness for AI Coding Agents

Date: 2026-07-10

Status: Team proposal / pitch. Design detail lives in
[`06-implementable-method/policy-guided-agent-control-system.md`](../06-implementable-method/policy-guided-agent-control-system.md).

---

## The ask, in three sentences

Agentic ("vibe") coding is putting software authorship in the hands of people
who do not have secure-coding expertise, and multiple independent studies show
the code these agents produce is measurably insecure. We propose to build an
**automatic security harness** — a control system that sits around any coding
agent and binds the _right_ security principle to each security-relevant moment
of the agent's coding lifecycle, enforced by an external harness rather than
hoped for in a prompt. We can prototype the strongest version fast by building
on our own harness runtime (Archon), while keeping the architecture agent- and
LLM-agnostic so it generalizes far beyond any one tool.

---

## 1. Why now: agentic coding changed _who_ writes software

For most of software history, the person typing the code had at least some
training in how software fails. That assumption is breaking.

Agentic coding assistants have collapsed the distance between "I want a feature"
and "there is running code." The result is a demographic shift in software
authorship:

- **Experts** now ship far more code per hour than they can personally review.
- **Students and career-changers** produce production-shaped code before they
  have learned threat modeling, input validation, or authorization.
- **Non-specialists** (founders, analysts, designers, researchers) now build and
  deploy real backends, file handlers, and integrations with no security
  background at all.

The through-line: **the security knowledge that used to live in the author's
head is increasingly not there.** The agent is now the de facto author, and the
human is a reviewer who often cannot evaluate what they are approving. Security
by _review_ assumed a qualified reviewer. That assumption no longer holds at
scale.

This is not a reason to slow agentic coding down — it is winning for good
reasons. It is a reason to move the security knowledge _into the loop_, so it is
applied automatically regardless of who is driving.

## 2. The evidence: agent-generated code is measurably insecure

This is not speculation. The empirical picture across several independent lines
of work is consistent:

- **Assistants introduce vulnerabilities at high rates.** The foundational study
  of GitHub Copilot (Pearce et al., "Asleep at the Keyboard", IEEE S&P 2022)
  generated 1,689 programs across 89 security-relevant scenarios drawn from
  MITRE's Top-25 CWEs and found **roughly 40% contained a vulnerability**.
- **Assistants make _humans_ less secure — and overconfident.** The Stanford
  study (Perry et al., "Do Users Write More Insecure Code with AI Assistants?",
  CCS 2023; 47 participants, Python/JS/C) found participants with an AI assistant
  wrote **significantly less secure code**, yet were **more likely to believe
  their code was secure**. The false confidence is arguably worse than the bug.
- **Even functionally correct agent code is often insecure.** BaxBench (Vero et
  al., ETH SRI Lab, ICML 2025) — 392 security-critical backend tasks with
  functional tests _and_ expert-designed exploits — found that **even the best
  model leaves ~62% of solutions incorrect or insecure, and about half of the
  functionally-correct solutions are still exploitable.** Generic
  "security-focused" prompting helps only inconsistently.
- **Our own observations agree.** Across the agent-behavior comparisons in this
  repository, agents rarely run adversarial tests or runtime probes, sometimes
  leak internal details in errors, and under failure pressure will take unsafe
  shortcuts (disable host-key checking, fabricate credentials, weaken
  validation) to make a task "complete."

Two conclusions follow. First, **the problem is real and load-bearing**, not a
corner case. Second, **the naive fixes do not work**:

| Naive fix                           | Why it falls short                                                                                                                                                               |
| ----------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| "Add a secure-coding system prompt" | One-shot text is forgotten under long trajectories, contradicted by repo/issue content, and rationalized away under failure pressure. Benchmarks show weak, inconsistent effect. |
| "Run a scanner after the fact"      | Catches a subset of known patterns, misses logic/authz/exposure bugs, and arrives after the agent already reported success. No control over the trajectory.                      |
| "Fine-tune a more secure model"     | Expensive, per-model, non-portable, opaque, and still probabilistic — you cannot audit or guarantee any specific control.                                                        |

The gap is structural: security today is _advisory and post-hoc_. We need it to
be **enforced and in-the-loop** — **security by design for the agent itself.**

## 3. Our idea: bind the right principle to each intervention point

We propose an **automatic security harness pipeline** for AI coding agents.

The core intuition — the thing we are selling — is this:

> A coding agent's run is a sequence of _security-relevant moments_: it inspects
> untrusted input, it writes to a dangerous sink, it installs a dependency, it
> starts a service, it repairs a failing build. Each of these is an
> **intervention point.** Security fails when the right principle is absent at
> that exact moment. So: **compile principles into policies, and bind each policy
> to the intervention points where it can actually change behavior — then let an
> external harness enforce it.**

("Weave" was the user's word; we will use **bind to intervention points**, which
is more precise and testable.)

Three properties make this more than a better prompt:

1. **The harness owns the security state, not the model.** Principles become
   executable policy objects held _outside_ the LLM. The model can reason and
   write; it cannot forget, relax, or be argued out of a policy by hostile repo
   content.
2. **Enforcement is layered across the lifecycle, not one-shot.** The right
   principle shows up as an inspection question early, an implementation rule
   mid-run, a runtime probe at validation, and a repair guardrail under failure.
3. **Claims require evidence.** "This input is validated" is only true if the
   harness _observed_ the validation code and a passing adversarial test — never
   because the model said so.

### The agent lifecycle and where we intervene

| Lifecycle moment   | Security risk if unguided                                         | Harness intervention                                                            |
| ------------------ | ----------------------------------------------------------------- | ------------------------------------------------------------------------------- |
| Orientation        | Misses that the task is high-risk (e.g. persistent remote access) | Classify risk; surface assets, trust boundaries, missing trust inputs           |
| Inspection         | Reads code but not the untrusted inputs / dangerous sinks         | Inject "what to look for"; record what was actually inspected                   |
| Planning           | Plans features without controls                                   | Convert active policies into explicit design constraints                        |
| Implementation     | Writes to a sink without validation                               | Bind implementation rules; monitor diffs in real time                           |
| Static/build check | Green build treated as "done"                                     | Deterministic dangerous-API and secret scans                                    |
| Test / runtime     | Rarely writes adversarial tests or probes live behavior           | Schedule policy-specific tests + runtime probes (auth, exposure, error leakage) |
| Failure & repair   | Weakens security to make tests pass                               | **Loop conditioning**: forbid weakening controls; harden, don't relax           |
| Reporting          | Overclaims success                                                | Final claim gate: report only what the evidence ledger supports                 |

Every row is a place where today's agents silently do the wrong thing, and where
a harness can deterministically do the right thing.

## 4. The design (and why each choice)

Full technical detail is in the
[PGACS design doc](../06-implementable-method/policy-guided-agent-control-system.md).
Here is the design at pitch altitude, with the rationale for each decision the
team should sign off on.

### Design choice 1 — Separate the _policy_ (data) from the _enforcement channels_ (mechanism)

**What:** one `Policy` object carries three thin handlers — a prompt fragment, a
set of runtime monitors, and repair invariants — for the three enforcement
layers.

**Why:** this is the decision that makes everything else buildable. Dynamic
adoption, plug-in extensibility, and independent testing of each layer all fall
out of it: adding a risk mid-run is _one object mutation_ that automatically
updates the prompt, the monitors, and the guardrails, instead of three
subsystems you have to keep in sync. The earlier PGAH design tangled these and
became a cathedral; separating them makes it a week of core work.

### Design choice 2 — The harness is an event/intervention **bus**, and agents join via capability-declaring **adapters**

**What:** the agent emits a normalized stream of observation events (tool calls,
file edits, commands, service starts); the harness emits interventions (inject
context, allow/deny a tool, condition the loop). An `AgentAdapter` declares which
capabilities it supports: `inject`, `interceptTools`, `driveSteps`.

**Why:** this is what makes us **agent- and LLM-agnostic**, which is a hard
requirement for the team — we will evaluate across many agents and models. A
workflow DAG (the obvious first instinct) only wraps agents you fully drive; it
cannot wrap Cursor, Aider, or a raw SDK loop, and it confounds "policy effect"
with "we forced a rigid workflow." The bus subsumes the DAG _and_ works when all
we can do is tail a log. Crucially, **enforcement degrades gracefully**: the same
policies run everywhere; weak adapters get context + post-hoc verification, strong
adapters add real-time blocking. We are never blocked waiting for an agent to
expose more.

### Design choice 3 — Three enforcement layers: proactive, detective, corrective

**What:**

- **Layer A (prompt):** inject phase-appropriate principle slices — preventive.
- **Layer B (monitor/probe):** check each behavior; cheap passive monitors on
  every diff/command, expensive active probes on demand — detective, and the
  source of _evidence_.
- **Layer C (loop conditioning):** at each repair boundary, **predict** the next
  unsafe move and **condition** the next iteration before the agent acts, and
  enforce invariants so repairs never weaken a control — corrective.

**Why:** the layers map directly to the three ways security fails in real
trajectories — the principle was never stated (A), the bad behavior was never
caught (B), or a repair quietly undid a control (C). Layer C is the novel,
high-value piece: our own comparisons show the most dangerous moments are
_adaptations under failure pressure_, and no existing tool intervenes there. The
layers are independent subscribers, so we can build, test, and evaluate each one
in isolation.

### Design choice 4 — Policy selection is dynamic and touches all three layers

**What:** select a compact policy set (target 3–8) from the task surface, then
_re-select_ as the trajectory reveals new risks (a new dependency, a shell sink,
a bound port). Policy state is monotonic — it can only get stricter during a run
unless a human relaxes it.

**Why:** initial selection cannot foresee everything an agent will do, and
security failures are usually introduced by something that appeared _mid-run_.
Monotonic hardening directly answers the observed failure where agents relax an
inconvenient control to get to green. Because policies carry all three handlers,
one dynamic delta updates prompt + monitors + guardrails together.

### Design choice 5 — "LLM proposes, rules dispose, learning ranks"

**What:** split the mechanism by function. Use an **LLM** for fuzzy perception
(task-surface extraction, proposing candidate policies) and for _semantic
evidence_ (a critic that judges "does this actually validate the input?"). Use
**deterministic rules** for the safety-critical triggers and for **all
enforcement decisions** (allow/deny, evidence-satisfied, invariant-violated).
Add a **decision-tree/GBDT ranker** later to optimize selection once we have
logged data. Defer RL to a constrained ranker over an already-safe set.

**Why (this is a question the team will ask directly):**

- **Enforcement must be deterministic.** A probabilistic gate is not a gate. It
  must be auditable and reproducible — both for security guarantees and for a
  defensible research claim. And the moment an LLM can relax a gate, prompt
  injection from repo/issue/dependency text becomes a hole in _our_ system.
- **Perception should be LLM-driven**, because interpreting messy task language
  and code is exactly what LLMs are good at — but as an **advisor with no
  authority**.
- **We reject RL as the core mechanism (for now):** rewards are sparse, noisy,
  and delayed; unsafe exploration is unacceptable in security; and a black box
  that "helped" is not a contribution we can stand behind. Transparency is a
  feature. RL can come back later, constrained and offline-evaluated.

### Design choice 6 — Extend to new domains via plug-in **packs**, not core edits

**What:** the core (bus, controller, layers, ledger) is fixed. A **Policy Pack**
contributes policies + monitors + probes + invariants for a task family
(file-parser, web-api, database, env-setup, and beyond code generation:
data-pipeline, ML-training, agent-tooling). Packs speak a fixed _surface
vocabulary_ (inputs, sinks, assets, trust boundaries, actions) and carry a trust
tier so experimental packs can recommend but not hard-gate.

**Why:** extensibility is the difference between a demo and a platform. The test
of a real plug-in architecture is that a _non-code-generation_ family (say, PII
handling in a data pipeline) drops into the same machinery by writing a pack,
with zero core changes. This is also how the idea scales into a product surface
and how the team divides work.

## 5. Why build on Archon (and why we are not locked in)

We should prototype the **strongest** adapter first, and Archon is the fastest
path to it. Archon already gives us, for free:

- a workflow/DAG engine (the `driveSteps` adapter — full phase gating);
- multi-provider execution (Claude, Codex, Pi/community — our multi-LLM axis);
- worktree isolation per run (safe to let a harness intercept and probe);
- hooks, MCP config, and script/bash nodes (the raw material for tool brokering
  and deterministic validators);
- an events/artifacts model we can repurpose as the evidence ledger.

So the pitch is: **use Archon as an accelerant and reference substrate** to stand
up the driver + broker adapters and a first pack in weeks, not quarters.

The important part: **the bus-and-adapter architecture means Archon is a
substrate, not a dependency.** Agents that never run inside Archon (Cursor, a
raw Claude Code session, a CI job) are reached by lighter adapters — a
hook/tool-proxy adapter and a log/diff adapter — that consume the same policies
and controller. If we ever outgrow Archon, we swap the driver adapter and keep
the policy model, the packs, and the two lighter adapters intact. We get the
speed of an existing harness builder without betting the methodology on it.

## 6. Why this is defensible and worth doing

- **It attacks a validated, growing problem** with clear stakes (see §2).
- **It is a mechanism, not a prompt.** The contribution — bind principles to
  intervention points and enforce them externally with evidence — is a control
  architecture, which is far more compelling to a security audience than "we
  added instructions."
- **It is auditable and reproducible.** Deterministic enforcement + an evidence
  ledger means every security claim is traceable to an observation. That is
  publishable and shippable.
- **It generalizes.** Agent-agnostic by construction and extensible by packs, so
  it grows across agents, LLMs, task families, and eventually non-coding
  domains.
- **It has a fail-safe stance the field lacks.** For underspecified high-risk
  tasks, "refuse to activate and report the missing trust inputs" is a _correct_
  outcome — a genuinely novel framing versus tools that reward liveness.

## 7. Risks and how we mitigate them

We should be honest with the team about where this can go wrong.

| Risk                                                                                  | Mitigation                                                                                                                                      |
| ------------------------------------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------- |
| **We just re-run a scanner** and the policy machinery adds nothing.                   | Include a "dumb harness = run all validators" control in evaluation; the claim must be that _selection + binding_ beats running everything.     |
| **Over-blocking hurts functional correctness** / agents refuse valid work.            | Blocking levels (advisory/required/fail-closed); measure joint functional-AND-security success; adjudicate whether each block was warranted.    |
| **Structure, not policy, is doing the work** (rigid workflow alone changes behavior). | Bus lets us run the _same policies_ with and without forced structure and compare.                                                              |
| **Prompt injection subverts the harness.**                                            | LLMs never hold enforcement authority; only deterministic code + human can relax a gate.                                                        |
| **Scope creep rebuilds the PGAH cathedral.**                                          | Ship the minimal core first (below); everything else is an addition at a stable seam.                                                           |
| **Cost/latency of probes and critic LLMs.**                                           | Passive monitors are near-free and always on; expensive probes are scheduled by Layer C only when armed; report security lift per token/minute. |

## 8. What we build first (and the roadmap)

**Minimal core — target: a few weeks.** Enough to demonstrate all three layers
end-to-end on one agent.

1. Bus + evidence ledger + policy-state controller (pure functions).
2. One adapter on Archon (context + hook/broker) — inject and intercept.
3. One pack, ~6 policies (path traversal, input validation, safe parse, error
   disclosure, command injection, dependency pinning), each with a prompt
   fragment + one passive monitor + one invariant.
4. Deterministic controller with a few dynamic triggers + monotonic hardening.
5. One active probe + one critic-LLM check, to prove the expensive path.

**Then widen (quarters):**

- more adapters: Codex driver, a hook adapter for raw Claude Code, a log/diff
  adapter for anything;
- more packs: web-api, database, env-setup;
- the learned selection ranker, once we have logged decisions + outcomes;
- the first non-code-generation pack, to prove the plug-in claim.

**Decision milestones the team can gate on:**

- _M1:_ on 5–10 known-risky tasks, the harness produces a filled evidence ledger
  and blocks at least one real unsafe shortcut a baseline agent takes.
- _M2:_ the same policies run on a second agent via a different adapter with no
  policy changes (agent-agnosticism demonstrated).
- _M3:_ a new task family works by writing a pack only (extensibility
  demonstrated).

## 9. The call to action

We are asking the team to greenlight the **minimal core** (§8, M1) as a focused
first milestone. It is small, it reuses Archon, and it produces a concrete
artifact — an evidence ledger plus a caught unsafe shortcut — that we can show,
measure, and build the larger evaluation around. The upside is a defensible,
generalizable, security-by-design control system for coding agents, aimed
squarely at a problem the whole industry now has and no one has solved well.

---

## Appendix: evidence base

Figures below were verified against the primary sources (2026-07-10).

- Pearce, H., Ahmad, B., Tan, B., Dolan-Gavitt, B., Karri, R. "Asleep at the
  Keyboard? Assessing the Security of GitHub Copilot's Code Contributions."
  IEEE S&P, 2022. arXiv:2108.09293. (1,689 programs across 89 scenarios from
  MITRE Top-25 CWEs; ~40% vulnerable.)
- Perry, N., Srivastava, M., Kumar, D., Boneh, D. "Do Users Write More Insecure
  Code with AI Assistants?" ACM CCS, 2023. arXiv:2211.03622. (47 participants;
  AI-assisted users wrote less secure code and were more confident it was
  secure.)
- Vero, M., et al. "BaxBench: Can LLMs Generate Correct and Secure Backends?"
  ICML, 2025. arXiv:2502.11844; baxbench.com. (392 tasks = 28 scenarios × 14
  frameworks × 6 languages; even the best model leaves ~62% of solutions
  incorrect or insecure, and ~half of correct solutions remain exploitable.)
- Meta "CyberSecEval" / Purple Llama: insecure-code-generation and cyber-risk
  evaluations for LLMs.
- Internal: `reports/baxbench_agent_behavior_codex.md`,
  `reports/grasp-secure-coding/workflow-comparison.md`,
  `reports/secure-environment-setup/docker-comparison.md`,
  `reports/agent-behavior-comparison/*`.
