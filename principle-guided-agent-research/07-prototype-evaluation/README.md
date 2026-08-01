# Prototype Policy-Selection Evaluation

Date: 2026-07-27

## Purpose

This evaluation asks whether the milestone 2 policy selector is accurate enough
to justify integration with the Archon runtime. It is deliberately lightweight:
the reference labels were produced by an independent security-focused subagent
rather than through time-consuming human annotation.

These are **silver labels**, not expert ground truth. They support prototype
decisions but cannot support a publication claim about absolute selector
quality.

## Artifacts

- `silver-policy-selection-labels.json` contains 12 frozen tasks and provisional
  required/relevant policy labels.
- `subagent-labeling-notes.md` records the independent labeling procedure,
  uncertainties, and policy-corpus coverage gaps.
- `selector-evaluation.generated.json` contains deterministic selector outputs,
  aggregate metrics, and task-level disagreements.
- `scripts/evaluate-pgacs-policy-selection.ts` reproduces the comparison.

The subagent did not inspect the selector implementation or its generated
autossh selection before labeling. This reduces, but does not eliminate,
confirmation bias.

## Sample

The sample contains two tasks for each family:

- environment setup;
- web API;
- authentication/session;
- file parsing;
- dependency/build;
- agent tooling.

Each task has a compact set of policy IDs labeled as required or additionally
relevant. All task-specific IDs were validated against the 84-policy domain
registry. The current deterministic registry additionally contains three core
fallback policies, which do not replace task-specific labels.

## Results

| Metric | Result |
| --- | ---: |
| Tasks | 12 |
| Selector completed without error | 12/12 |
| Task-family classification accuracy | 83.33% |
| Required-policy recall | 26.92% |
| Acceptable-selection precision | 15.63% |
| Average selected policies | 8.0 |

The selector reached its eight-policy budget for every task. That is a strong
sign of weak discrimination rather than evidence that all eight policies were
necessary.

The strongest results were on dependency/build and agent-tooling tasks. Web API,
authentication/session, and file-parser tasks had substantial required-policy
misses. Both file-parser tasks were also assigned the wrong dominant family.

## Interpretation

The experiment supports a narrow feasibility conclusion:

> PGACS can turn a task surface and policy registry into a deterministic,
> replayable, explainable decision, but the current metadata and extraction
> rules are not precise enough to select enforcement policies reliably.

The observed failures fall into four categories:

1. **Surface extraction:** keyword-count classification allowed `agent`, `API`,
   and similar secondary terms to override the central file-parser behavior.
2. **Registry metadata:** broad inferred tags make many semantically different
   policies look equivalent to the selector.
3. **Ranking:** additive overlap rewards generic policies repeatedly and fills
   the budget without a meaningful minimum-relevance threshold.
4. **Corpus coverage:** direct policies are missing for path confinement, safe
   parsing, ordinary command construction, API input validation, and session
   controls. A selector cannot retrieve a policy that does not exist.

Exact-ID scoring also understates useful behavior when the registry contains
near-duplicate policies. A future capability-level evaluation should score the
security control achieved, not only the source record chosen.

## Prototype Decision

Do not integrate this selector into Archon enforcement yet. The next iteration
should remain small:

1. add an explicit `controlCapabilities` field to a compact seed registry;
2. map mandatory rules and silver labels to capabilities rather than broad tags
   or exact duplicate-prone IDs;
3. improve task-family extraction so central task actions outweigh incidental
   keywords;
4. add a minimum relevance threshold so selection need not fill all eight
   slots;
5. retain at least four of the current tasks as an untouched holdout when
   adjusting the prototype;
6. optionally ask a second independent subagent to label the holdout and report
   agreement before any human review.

This is enough to test whether precision and recall improve. Learned ranking,
runtime monitors, and full Archon integration remain deferred.

## Reproduction

From the Archon repository root:

```bash
bun run scripts/evaluate-pgacs-policy-selection.ts
```

The output is deterministic for a fixed registry, selector, and label file.
