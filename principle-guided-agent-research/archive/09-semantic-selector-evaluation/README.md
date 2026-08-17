# LLM Semantic Selector Prototype

Date: 2026-07-27

## Question

Can a simple LLM semantic selector use the expanded principle corpus more
effectively than the initial deterministic tag-overlap selector, without adding
a manually maintained capability taxonomy?

## Prototype

The corrected selector implementation makes one batch request containing:

- the 298 selectable records from the expanded corpus;
- the 12 frozen task prompts and repository hints, without reference
  task-family labels;
- instructions to select at most six non-redundant policies per task;
- a structured-output schema for policy IDs, importance, rationales, and
  coverage gaps.

Claude runs without tools. The local harness then verifies that every task is
present, every selected ID exists and is selectable, rationales are non-empty,
duplicates are removed, and the policy-count limit is respected.

The selector does not use task-family classification or inferred risk tags when
choosing policies. It reads prepared policy text directly. A regression test
ensures task-family and policy-label fields are absent from the prompt.

## Independence

An independent security-focused subagent relabeled the same 12 frozen tasks
against the expanded corpus before seeing semantic-selector output. The labels
contain 33 required and 25 relevant policy IDs.

After selection, the same evaluator performed a separate semantic adjudication.
The frozen labels were not changed. Adjudication credits a different policy only
when it imposes the same concrete task-specific control, and separately marks
additional relevant or irrelevant selections.

All labels and adjudication remain model-generated silver evidence, not expert
ground truth.

## Preserved Historical Result

The table below records the 2026-07-27 run. That run included `taskFamily` from
the silver-label artifact in each task input. It did not expose policy IDs, but
it confounds claims that the semantic selector avoided task-family
classification. The figures remain useful as historical prototype observations,
not as validated evidence for the corrected selector. A new model-backed run and
new adjudication are required before replacing them.

| Metric | Initial deterministic prototype | Semantic expanded prototype |
| --- | ---: | ---: |
| Required-policy recall, exact ID | 26.92% | 54.55% |
| Acceptable precision, exact ID | 15.63% | 47.62% |
| Average selected policies | 8.0 | 3.5 |
| Required-control recall, adjudicated | Not measured | 75.76% |
| Relevant-control precision, adjudicated | Not measured | 100.00% |
| Tasks reporting a coverage gap | Not supported | 3 |

The adjudicated recall consists of 18 exact required-policy matches and seven
control-equivalent matches. Eight required controls remained missing. The
adjudicator considered all 42 selected policies relevant, but that perfect
precision must be treated cautiously because it comes from one model evaluator.

The baseline and semantic prototype use different corpus sizes and separately
adapted silver labels. This is evidence of prototype progression, not a
controlled selector-only ablation.

## Observed Improvements

- Selection no longer fills the maximum budget automatically.
- In the historical run, file-parser selections improved despite the earlier
  deterministic misclassification; because reference task-family metadata was
  supplied, this observation requires confirmation in the corrected rerun.
- The selector found direct controls for IDOR, OAuth transaction binding, SSRF,
  archive traversal, dependency provenance, command execution, and deterministic
  agent authorization.
- Rationales connect selected policy text to concrete task behavior.
- The selector explicitly reported missing SSH known-host pinning, fail-safe
  backup retention, and SSRF network-segmentation controls.

## Remaining Misses

The adjudication found eight required controls not covered:

- encrypted SSH transport for autossh;
- backup data protection and fail-safe local retention;
- HTTPS for the URL-preview service;
- archive resource quotas;
- deterministic external enforcement for two agent-tooling tasks;
- least-privilege authorization for restricted fetching.

Some misses reflect selection judgment; others reflect imperfect corpus
specificity. This distinction is why coverage gaps and selected policies are
both recorded.

## Invalid Trial Excluded

An initial evaluation run accidentally serialized the full silver-label objects
into the LLM prompt. JavaScript retained `requiredPolicyIds` and
`relevantPolicyIds` at runtime even though TypeScript treated the objects as the
narrower task-input type. That leaked the answers and produced a meaningless
perfect score.

That run was overwritten and excluded. A second historical run removed policy
labels but still included `taskFamily`; it produced the preserved results above.
The current implementation constructs fresh task-input objects containing only
`taskId`, `prompt`, and `repoHints`. The regression test verifies that policy
labels, their values, and task-family metadata cannot appear in the prompt.

Selections now record hashes of their corpus and label inputs plus a normalized
selection fingerprint. The evaluator rejects adjudication unless task IDs,
required labels, selected policy IDs, label hash, and selection fingerprint all
match.

## Model Record

The selector was configured with the Claude CLI `sonnet` alias. The CLI reported
usage for `claude-sonnet-5` and `claude-haiku-4-5-20251001`, even with prompt
suggestions disabled. The run is therefore recorded using the exact reported
model IDs rather than claimed as a single-model-only execution.

## Artifacts

- `expanded-silver-labels.json` — frozen independent labels;
- `semantic-selection.generated.json` — validated selector output;
- `semantic-adjudication.json` — post-selection equivalence/relevance review;
- `semantic-selector-comparison.generated.json` — strict and adjudicated
  metrics;
- `scripts/run-pgacs-semantic-selector.ts` — tool-less structured selector;
- `scripts/evaluate-pgacs-semantic-selector.ts` — deterministic evaluator;
- `scripts/run-pgacs-semantic-selector.test.ts` — label-leakage regression test.

## Reproduction

From the Archon repository root:

```bash
bun run scripts/run-pgacs-semantic-selector.ts
bun run scripts/evaluate-pgacs-semantic-selector.ts
```

The first command invokes the configured LLM and can vary between runs. The
second command is deterministic for fixed labels, selection output, and
adjudication.

## Conclusion

The historical run supports continuing to test the simpler method: semantic
proposal over prepared policy text, constrained by a thin deterministic shell.
The corrected implementation must be rerun before claiming measured improvement
without task-family metadata.

The next step should not add a heavier selector. It should place this semantic
proposal step in front of one coding-agent task and observe whether the selected
policies actually alter the implementation and validation trajectory.
