# SWE-bench Lite: Direct Sonnet vs Archon Assist

Date: 2026-06-23

## Goal

Compare a direct Claude Sonnet run against Archon on the same small bug-fix task from SWE-bench Lite.

This experiment focused on trajectory and validation behavior, not just whether the final task appeared fixed.

## Task

Dataset: `princeton-nlp/SWE-bench_Lite`

Selected instance:

- `instance_id`: `django__django-13401`
- `repo`: `django/django`
- `base_commit`: `453967477e3ddae704cd739eac2449c0e13d464c`
- `version`: `3.2`

Problem summary:

Inherited field instances from an abstract Django model were treated as equal across different concrete child models. The fix requires adjusting `Field.__eq__`, `Field.__hash__`, and `Field.__lt__` so field identity accounts for the owning model while preserving `creation_counter` ordering semantics.

## Workspaces

Temporary experiment root:

`/private/tmp/archon-swebench-lite`

Archon checkout:

`/private/tmp/archon-swebench-lite/django`

Direct Sonnet checkout:

`/private/tmp/archon-swebench-lite/django-direct-sonnet`

Direct Sonnet stream log:

`/private/tmp/archon-swebench-lite/direct-sonnet-stream.jsonl`

Archon workflow log:

`/Users/keyanguo/.archon/workspaces/django/django/logs/0f95ee089a9128748e26935c6352dbb1.jsonl`

## Direct Sonnet Run

Invocation used the local Claude CLI with:

```bash
claude --model sonnet --print --verbose --output-format stream-json \
  --permission-mode bypassPermissions --max-budget-usd 3
```

The CLI resolved `--model sonnet` to:

`claude-sonnet-4-6`

Observed run metadata:

- Duration: 48.6 seconds
- Cost: `$0.2250108`
- Session ID: `6278a31a-6de8-470d-87e1-44228b81081a`

### Trajectory

1. Read the SWE-bench prompt.
2. Searched the Django source for comparison methods related to fields.
3. Read `django/db/models/fields/__init__.py`.
4. Edited `Field.__eq__`, `Field.__lt__`, and `Field.__hash__`.
5. Tried direct `pytest`; it failed due Django test settings.
6. Tried additional test commands and investigated the correct Django runner.
7. Ran Django's `tests/runtests.py`, initially against the wrong checkout.
8. Corrected validation with explicit `PYTHONPATH` pointing at the direct Sonnet checkout.
9. Ran `model_fields` tests successfully.
10. Added an ad hoc inline Python behavior check.
11. Returned a final summary.

### Validation Behavior

Direct Sonnet eventually validated the behavior, but the validation was exploratory:

- First test command was not suitable for Django's test harness.
- One validation attempt used the wrong checkout path.
- Final command corrected the environment with explicit `PYTHONPATH`.
- Existing `model_fields` tests passed.
- A manual inline check showed:

```text
b_field == c_field: False
len of set: 2
```

Direct Sonnet did not add a committed regression test for the SWE-bench fail-to-pass case.

### Patch Quality

Direct Sonnet fixed the main observed behavior, but its patch was weaker than the gold patch.

The main concern was `Field.__lt__`: it accessed `self.model` directly. Unbound `Field` instances may not have a `model` attribute, so this can raise `AttributeError` in tie cases. The gold patch guards model access with `hasattr`/`getattr` logic.

Its `__hash__` also used the model object directly instead of the gold patch's stable `(app_label, model_name)` components.

## Archon Run

Because the SWE-bench instance was not a normal enabled GitHub issue in the checkout, the full `archon-fix-github-issue` workflow was not used. The run used the general fallback workflow:

`archon-assist`

Run ID:

`0f95ee089a9128748e26935c6352dbb1`

Observed run metadata:

- Duration: about 80 seconds
- Input tokens: 15,059
- Output tokens: 3,677

### Trajectory

1. Read the SWE-bench task.
2. Searched `__eq__`, `__hash__`, and `__lt__` in `django/db/models/fields/__init__.py`.
3. Read the relevant field comparison methods.
4. Edited `Field.__eq__`, `Field.__lt__`, and `Field.__hash__`.
5. Ran `python tests/runtests.py model_fields.tests --verbosity=1`.
6. Installed the package editable with `python -m pip install -e . -q`.
7. Re-ran `model_fields.tests`.
8. Noticed the target fail-to-pass test was not present locally.
9. Added a regression test in `tests/model_fields/tests.py`.
10. Ran the updated focused test suite.
11. Ran broader regression coverage:

```bash
python tests/runtests.py model_fields model_inheritance migrations.test_state field_deconstruction --verbosity=1
```

### Validation Behavior

Archon validation was more benchmark-like:

- It used Django's own test runner rather than raw `pytest`.
- It installed the project editable before rerunning tests.
- It converted the failing behavior into a real regression test.
- It ran both targeted and broader test suites.

The broader validation reported 551 tests passing.

### Patch Quality

Archon's implementation patch matched the SWE-bench gold code patch:

- `__eq__` compares `creation_counter` and model identity via guarded model access.
- `__lt__` preserves `creation_counter` as the primary order and breaks ties with model metadata when both fields are model-bound.
- `__hash__` uses `creation_counter`, `app_label`, and `model_name` components.

Archon also added a regression test. The test was equivalent in intent to the official SWE-bench test patch, though named and placed slightly differently.

## Comparison

| Dimension          | Direct Sonnet                                    | Archon Assist                                           |
| ------------------ | ------------------------------------------------ | ------------------------------------------------------- |
| Model/provider     | `claude-sonnet-4-6` via local Claude CLI         | Archon workflow node using Claude                       |
| Workflow structure | Single raw agent session                         | Archon workflow run with JSONL logging                  |
| Planning           | Implicit                                         | Implicit inside `archon-assist`; not the full issue DAG |
| Code localization  | Prompt-guided search for field methods           | Same relevant method search                             |
| Implementation     | Fixed main behavior, but near-miss edge cases    | Matched SWE-bench gold code patch                       |
| Regression test    | No committed regression test                     | Added regression test                                   |
| Validation path    | Trial and correction; one wrong-checkout attempt | More direct Django runner usage and broader suite       |
| Output artifacts   | Raw Claude stream log                            | Archon run log plus modified test/source files          |
| Runtime            | About 48.6 seconds                               | About 80 seconds                                        |

## Key Difference

Direct Sonnet asked, effectively:

```text
Can I find and patch the likely code, then get enough tests/manual checks passing?
```

Archon assist behaved more like:

```text
Can I patch the likely code, capture the behavior in tests, and validate nearby regressions?
```

Even though this run did not use the full `archon-fix-github-issue` DAG, Archon produced a stronger repair trajectory: it matched the gold implementation and added a persistent regression test.

## Expected Full Bug-Fix Workflow Difference

The full `archon-fix-github-issue` workflow is heavier than the fallback `archon-assist` run used here. Its intended trajectory is:

```text
GitHub issue
  -> classify
  -> investigate
  -> investigation.md
  -> implement from artifact
  -> validate
  -> draft PR
  -> review agents
  -> synthesize findings
  -> self-fix
  -> simplify
  -> report
```

That workflow would make the plan, validation commands, tests, review findings, and self-fixes explicit artifacts rather than relying on a single raw agent trajectory.
