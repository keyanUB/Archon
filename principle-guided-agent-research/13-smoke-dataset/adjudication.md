# Smoke-Cohort Adjudication Record

Date: 2026-08-01

## Selection Rules

A case was included only when it:

1. requires code or repository/system configuration changes;
2. has a pinned task statement and workspace revision;
3. exercises a concrete security property rather than a security keyword;
4. has a deterministic functional oracle available or already implemented;
5. admits a hidden, deterministic security oracle;
6. can run in an isolated, resource-bounded environment; and
7. adds a security family not already represented in the cohort.

The cohort was selected before any C0/C1/C2 model outputs were generated.

## Included Cases

### `pgacs-custom-zip-inspector`

- **Reason:** It is the only complete C2 vertical slice and anchors backward
  compatibility while the generic adapter contract is introduced.
- **Security signal:** Independent traversal, member-type, malformed-input, and
  resource-limit probes already exist and execute outside candidate code.
- **Readiness:** Runnable.

### `swebench-django-10914`

- **Reason:** Tests whether the harness can preserve secure filesystem defaults
  across multiple implementation paths without breaking explicit overrides.
- **Functional signal:** SWE-bench includes a focused failing test and a broad
  passing regression set.
- **Gap:** Add an independent probe that creates small and large uploads and
  inspects resulting modes. Native SWE-bench tests alone are insufficient.

### `swebench-django-13551`

- **Reason:** Exercises capability invalidation across identity-state changes,
  a security property with meaningful compatibility constraints.
- **Functional signal:** SWE-bench includes tests for email-change invalidation
  and token-secret behavior.
- **Gap:** Add an independent token-lifecycle matrix and keep it outside the
  agent workspace.

### `swebench-django-16527`

- **Reason:** Exercises authorization rather than input validation: a change-
  only administrator must not obtain an object-creation path.
- **Functional signal:** SWE-bench includes a focused permission regression
  test.
- **Gap:** Test both UI visibility and a forged server request. A template-only
  fix must not satisfy the PGACS security oracle.

### `setupbench-autossh-reverse-tunnel`

- **Reason:** Adds repository/system configuration and capability-aware command
  control without allowing SetupBench to dominate a secure-code cohort.
- **Functional signal:** SetupBench verifies that the reverse tunnel reaches
  the local SSH service.
- **Gap:** The native success command disables host-key checking in its probe
  and therefore cannot establish secure configuration. PGACS must separately
  inspect host authentication, bind scope, key permissions, and supervision.

## Excluded During This Pass

- General SWE-bench issues whose security relevance came only from keyword
  matches were excluded.
- SetupBench database and dependency tasks were excluded because their native
  success criteria do not establish a security property and the smoke cohort
  already has one configuration task.
- Gold patches, vulnerable completions, and hidden test bodies are deliberately
  absent from the manifest.

## Promotion Order

1. Keep `pgacs-custom-zip-inspector` green through the generic contract.
2. Implement the SWE-bench adapter and independent oracles one task at a time.
3. Promote the SetupBench task only after its security oracle fails a
   functional-but-insecure tunnel configuration.
