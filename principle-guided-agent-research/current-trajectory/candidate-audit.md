# PGACS Trajectory Task Candidate Audit

Status: corpus audit and prospective candidate selection complete; zero tasks
are admitted for the causal C2/C3 pilot yet.

## 1. Audit Rule

This audit applies the eight mandatory criteria in the
[trajectory-control protocol](README.md#4-task-admission). A useful historical
trajectory is not automatically an admissible causal task. In particular:

- known final outcomes cannot be reused to invent a task-specific behavior
  predicate;
- a final patch property is not a trajectory event;
- an adapter capability test is not evidence that a real task exercises the
  mechanism; and
- a task outside secure code completion may qualify adapter generality but not
  the primary research construct.

The audit reviewed task contracts and observable tool sequences. It did not use
private reasoning or treat model explanations as facts.

## 2. Existing Evidence Screening

| Evidence source                             | Useful observation                                                                                                               | Admission decision                                                                                                                                                                        |
| ------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| archived ZIP baseline/guided pair           | policy guidance changed inspection, implementation, and validation behavior                                                      | reject for causal pilot: no online intervention, one standalone generation task, and outcomes already known                                                                               |
| BaxBench ten-task and C2 traces             | writes, command execution, runtime testing, correction, and repair are observable                                                | retain for taxonomy and adapter fixtures; reject as primary tasks because they are standalone generation and their outcomes informed prior analysis                                       |
| SWE-bench Django trajectory                 | repository search, edit, failed validation, environment correction, regression-test addition, and broader tests form a rich loop | reject: correctness task with no independent security oracle, and gold/outcome information is already known                                                                               |
| SecRepoBench task 910                       | repository reads and target writes are captured at a real pre-action boundary                                                    | retain as negative applicability evidence: C3 emitted no denial and the insecure omission was found only by artifact probing                                                              |
| SetupBench autossh/Redis/MongoDB selections | configuration writes and service-start commands provide strong pre-execution control points                                      | transfer-only candidates: task form is secure environment setup, not secure repository completion; only autossh currently has a local security oracle and none has a PGACS trajectory run |

No historical task passes all admission criteria. Reporting zero admissions is
preferable to retrofitting a predicate around a known vulnerability.

## 3. Prospective SecRepoBench Candidate Selection

The next primary candidates were selected before any new model execution using
[`candidate-selection.v0.1.json`](candidate-selection.v0.1.json). The selector:

1. uses SecRepoBench revision
   `7ca5c4a7e908f8013e7b9ae624ba0d96f8c6ec76`;
2. excludes development tasks `910`, `1065`, and `19902`;
3. keeps the already-qualified evaluator project strata `lcms`, `file`, and
   `mruby`;
4. ranks unused task IDs by
   `SHA-256("pgacs-trajectory-pilot-v0.1:" + task_id)`; and
5. selects the lowest digest in each stratum.

Only task ID, project name, and changed file participate. The selector excludes
crash type, CWE, fixing commit, secure/vulnerable code, and evaluator outcomes.

| Candidate | Project | Target           | Status                 |
| --------- | ------- | ---------------- | ---------------------- |
| `42227`   | lcms    | `src/cmscgats.c` | selected, not admitted |
| `9922`    | file    | `src/is_json.c`  | selected, not admitted |
| `57672`   | mruby   | `src/vm.c`       | selected, not admitted |

These identities are frozen as candidates. Replacement is permitted only for a
predeclared admission failure, using the next task in the same deterministic
ranking. A candidate is never replaced because its model output is secure,
insecure, easy, or difficult.

## 4. Candidate Mechanism

The first mechanism to qualify is `validation_avoidance` at the
`candidate_submitted` boundary:

```text
agent edits candidate
  -> agent requests an approved public validation probe, or does not
  -> candidate_submitted event
  -> C2 records missing/current evidence but permits submission
  -> C3 conditions submission until current-revision evidence exists
  -> independent developer-test and OSS-Fuzz oracle remains hidden and final
```

The approved pre-submission probe cannot be the hidden OSS-Fuzz proof of
concept, reveal benchmark labels, or determine the terminal security result. It
must be derived from visible repository contracts and selected policy
obligations. Candidate options include a bounded compile/static check or a
public, policy-derived negative test. C2 and C3 receive the same probe tool;
only enforcement mode differs.

This mechanism tests a real behavioral proposition: submitting a security-
sensitive revision without current validation evidence can be conditioned. It
does not claim that running a probe proves security. The independent evaluator
retains outcome authority.

## 5. Admission Gaps

| Criterion                  | Current evidence                                                | Required gate                                                                                   |
| -------------------------- | --------------------------------------------------------------- | ----------------------------------------------------------------------------------------------- |
| natural multi-step loop    | repository inspection and completion are structurally available | one observation-only calibration trace per candidate; no security outcome inspection            |
| visible pre-outcome action | target write and submission are adapter-visible                 | add a normalized `candidate_submitted` receipt to the OpenHands bridge                          |
| interceptable action       | finish is harness mediated                                      | implement allow/condition behavior with deterministic replay                                    |
| frozen fact and predicate  | policy/repository facts exist                                   | define one generic current-revision validation predicate, not task-specific vulnerability rules |
| feasible secure completion | benchmark secure references exist                               | calibrate secure reference in the pinned task image without exposing it to generation           |
| independent oracles        | upstream developer tests and OSS-Fuzz PoC exist                 | qualify each task through the PGACS oracle and record conclusive secure/vulnerable replays      |
| blinded predicate fixtures | none frozen                                                     | create positive, negative, and ambiguous fixtures and obtain independent blinded adjudication   |
| C2/C3 opportunity parity   | same adapter design is possible                                 | prove identical tool/capability receipts and opportunity exposure in both modes                 |

Because the current researcher has viewed benchmark paired-code material while
developing the prototype, that researcher must not be the sole blinded fixture
adjudicator. Fixture labels should be assigned by another team member from the
frozen predicate specification, without candidate outcomes.

## 6. SetupBench Transfer Track

The previously selected autossh, Redis, and MongoDB tasks should not be pooled
with the secure-completion pilot. They are valuable later for adapter generality:

- `bgsetup-autossh-reverse-tunnel`: pending configuration and service-start
  actions; local security oracle exists;
- `dbsetup-redis-3`: ACL, network-bind, persistence, and permission actions;
  security oracle remains TBD; and
- `dbsetup-mongodb-3`: authorization, replica-set exposure, role, and key-file
  actions; security oracle remains TBD.

A separate transfer experiment may test whether the event/intervention bus
works for privileged environment actions. It cannot establish the primary
secure repository code-completion claim.

## 7. Next Gate

T2 is partially complete: candidate selection and repository preparation are
frozen, but admission is not. All three task images were acquired and prepared.
Local calibration cannot qualify them on the current `arm64` Docker host because
the images are `amd64`. In the first attempted replay, task `42227`'s exact
fixing-commit file compiled and passed developer tests but ASan faulted inside
sanitizer coverage under emulation; SecRepoBench's frozen report marks the same
secure reference as passing. The evaluator now fails closed before non-native
sanitizer execution. This is an infrastructure incident, not a candidate
security result.

The next implementation order is:

1. calibrate tasks `42227`, `9922`, and `57672` on a native `amd64` Docker host,
   without model runs;
2. add the approved-probe request and candidate-submission event contract;
3. implement the generic observation-only validation-evidence predicate;
4. build and independently adjudicate frozen fixtures; and
5. issue admission records only for candidates that pass every criterion.

No C2/C3 effectiveness run begins before all five gates pass.
