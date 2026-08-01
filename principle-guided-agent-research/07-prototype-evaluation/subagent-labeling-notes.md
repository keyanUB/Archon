# PGACS Silver-Labeling Notes

Date: 2026-07-27

## Evaluation Role and Independence

This artifact was produced by one model acting as an independent
software-security evaluator. The evaluator read:

- `06-implementable-method/01-policy-registry-and-task-surface.md`;
- `06-implementable-method/03-policy-selection.md`;
- `.archon/data/research/pgacs/policy-registry.normalized.json`; and
- research reports describing the intended cross-task evaluation.

To reduce confirmation bias, the evaluator did not inspect the selector
implementation or `policy-selection.example.json`. The labels therefore express
the evaluator's reading of task risk and policy meaning, not an attempt to match
the prototype's current output.

## Labeling Procedure

The evaluator used the following compact procedure:

1. Construct two small, plausible tasks for each requested `TaskSurface` family.
2. Identify the assets, untrusted inputs, trust boundaries, and dangerous
   operations stated in each prompt and its repository hints.
3. Read the normalized policy text and provenance for semantically applicable
   records.
4. Mark a policy `required` only when omitting its control would leave a material
   security failure in that task.
5. Mark a policy `relevant` when it would usefully strengthen the solution but
   could reasonably be owned by another layer or omitted without creating the
   task's central security failure.
6. Keep each set small and avoid adding generic lifecycle policies solely
   because they are broadly desirable.
7. Use policy IDs exactly as represented in the normalized registry.

The label decision is task-specific. Registry `severity` informed interpretation
but did not determine the label: an advisory policy can be required for a
particular task, and a fail-closed policy can remain merely relevant when the
task does not depend on its full control.

## Uncertainties

Several decisions depend on deployment boundaries that short prompts cannot
fully describe. For example, TLS for a web endpoint may be implemented by a
reverse proxy rather than application code. Such controls are generally marked
relevant unless the prompt explicitly places transport configuration in scope.

The archive task labels sandboxing as required because the registry has no
direct path-confinement policy. In a mature corpus, canonical path validation,
symlink handling, extraction-without-write, and sandboxing would be separate
controls. The current label should not be interpreted as evidence that
sandboxing alone prevents archive traversal.

The two LLM policy-import controls are also broader than ideal. `LLM-056`
combines input sanitization with testing guidance, while `LLM-063` addresses
deterministic enforcement generally. More precise schema-validation and
policy-data trust-boundary records would reduce this ambiguity.

Some records are near duplicates, including pairs such as `ASVS-292` /
`ASVS-308`, `ASVS-289` / `ASVS-307`, and `ASVS-295` / `ASVS-311`. The labels use
one representative rather than treating duplicated text as independent
security obligations.

## Corpus Coverage Gaps

The registry provides useful coverage for:

- encrypted network transport and secure network defaults;
- object-level and centralized authorization;
- OAuth transaction binding and trusted JWT key sources;
- secrets storage and least-privilege access;
- dependency provenance, expected repositories, and model integrity;
- sandboxing, resource quotas, and safe failure;
- least-privilege agent tools and deterministic controls outside the LLM.

Coverage is materially weaker for:

- canonical path confinement, archive traversal, and symlink attacks;
- safe parser and deserializer configuration;
- generic request schema validation and output encoding;
- command argument construction and shell injection outside LLM extensions;
- session expiration, cookie properties, CSRF, logout, and revocation;
- SSRF defenses beyond a general outbound-resource allowlist;
- rate limiting and abuse controls for ordinary APIs;
- concrete dependency version pinning and lockfile verification;
- policy-specific validators and executable evidence checks.

These gaps matter to interpretation of selector recall. A selector cannot return
a missing policy, so evaluation should distinguish a selector miss from a
registry coverage gap. For this prototype, the JSON records the best applicable
existing controls and these notes disclose where the match is only partial.

## Why These Are Silver Labels

The labels are provisional silver data, not ground truth, because:

- a model generated both the tasks and judgments;
- only one evaluator labeled the sample;
- no independent human adjudication or inter-rater agreement was performed;
- the tasks are synthetic and may not represent benchmark frequency;
- repository context is summarized as hints rather than inspected working code;
- policy records contain broad inferred metadata and occasional source-text
  quality issues;
- no implementation outcome or exploit test was used to validate whether each
  chosen policy changes security behavior.

The sample is still useful for a feasibility check. It can reveal obvious
selection misses, over-selection, unstable rankings, and task-family coverage
problems. It should not be used to claim expert-level precision or to tune a
production policy controller.

## Recommended Prototype Use

Run the selector once against this frozen file and report required-policy
recall, useful precision over required plus relevant labels, irrelevant-policy
rate, and selected-policy count by task family. Analyze errors in four buckets:

1. task-surface extraction error;
2. policy retrieval or ranking error;
3. registry metadata error; and
4. missing policy capability.

Do not tune repeatedly on all 12 tasks and then report the same-task score as
generalization. If the prototype is adjusted, keep at least four tasks untouched
as a small holdout or create a second blinded silver set.

## Future Upgrade Path

A lightweight next iteration should:

1. ask a second independent security evaluator to relabel the same frozen
   tasks;
2. adjudicate only disagreements and high-impact coverage gaps;
3. add a few precise policies for path confinement, parser safety, command
   construction, and request validation;
4. attach explicit control capabilities instead of relying on broad inferred
   tags; and
5. replace selected silver labels with human-reviewed gold labels when research
   time permits.

This keeps the prototype small while testing the central claim: a harness can
select a compact, security-relevant policy set before more expensive runtime
enforcement is built.
