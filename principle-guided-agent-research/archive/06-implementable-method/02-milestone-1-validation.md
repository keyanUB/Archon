# Milestone 1 Validation: Policy Registry and Task-Surface Extraction

Date: 2026-07-27

## Purpose

This note validates the first PGACS milestone:

- the normalized policy registry;
- the task-surface extractor;
- the compact policy selection step that follows them.

The goal is not to prove the full harness yet. The goal is to verify that the
first layer produces a stable input contract for later enforcement.

## Validation Questions

1. Does the task-surface extractor identify the right task family?
2. Does it surface the relevant security-relevant features?
3. Does policy retrieval stay compact and explainable?
4. Does the registry preserve provenance from source principle to policy?
5. Does uncertainty activate a visible generic security floor instead of an
   empty policy set?

## Representative Checks

### 1. Environment setup task

Example shape:

```text
Install autossh and configure it as a persistent supervised process.
Connect remote port 9000 to localhost:22.
Use AUTOSSH_LOGFILE and AUTOSSH_POLL.
Restart automatically on failure.
```

Expected task-surface signals:

- `taskFamily = environment_setup`
- `runtimeExposure` includes `port_binding` and `remote_access`
- `environmentConstraints` include `headless`, `minimal_environment`, and
  `root_privileges`
- `likelyCwes` includes at least one exposure-related item
- `missingSecurityInputs` calls out the absent threat model and validation
  criteria

Expected registry behavior:

- select policies tied to runtime hardening, least privilege, transport/network
  configuration, dependency integrity, and fail-safe setup
- avoid pulling in unrelated application-runtime policies

### 2. Web API task

Example shape:

```text
Add an endpoint that accepts user input and stores it in the database.
```

Expected task-surface signals:

- `taskFamily = web_api`
- `inputChannels` include `network`
- `dangerousSinks` include `database`
- `trustBoundaries` include `untrusted_input`

Expected registry behavior:

- select input-validation, authorization, and sink-protection policies
- avoid environment-setup-only controls unless the repo evidence shows runtime
  exposure or deployment risk
- classify the surface as `sufficient`

### 3. Auth/session task

Example shape:

```text
Implement login, session persistence, and token handling.
```

Expected task-surface signals:

- `taskFamily = auth_session`
- `assets` include secrets or credentials
- `trustBoundaries` include `secret_boundary`
- `likelyCwes` include auth/session-related risks

Expected registry behavior:

- select authentication, authorization, secret-handling, and session-integrity
  policies
- prefer fail-closed policies for ambiguous credential flow

### 4. Sparse or ambiguous task

Example shape:

```text
Refactor the helper for readability.
```

Expected task-surface and registry behavior:

- classify the surface as `insufficient` when no security-bearing fact is
  supported by evidence;
- record unresolved input, sink, trust-boundary, and validation questions;
- return the three-policy generic security floor in `fallback` mode;
- retain mandatory fail-fast behavior if later evidence reveals a known risk
  without specific policy coverage.

## What Good Looks Like

The milestone is behaving well when:

- the extractor produces a single dominant task family rather than a wide,
  contradictory set;
- the selected policies are explainable from surface tags and provenance;
- the policy set remains compact;
- unrelated policies do not dominate the output;
- the registry entries can be traced back to the original source corpus;
- sparse surfaces produce an explicit fallback decision rather than an empty
  result.

## What Bad Looks Like

The milestone is not ready if:

- the extractor overfits to generic keywords like `file` or `network`;
- the selector returns a broad grab bag of policies with no clear rationale;
- environment-setup tasks trigger mostly application-runtime policies;
- provenance from source principle to policy record is missing;
- the task surface is too weak to support later phase binding;
- missing evidence is silently interpreted as low risk.

## Conclusion

Milestone 1 is the right first step because it creates the shared vocabulary for
selection. The validation target is not perfect recall. The target is a stable,
interpretable contract that later harness layers can depend on. The implemented
prototype now represents uncertainty directly and guarantees a non-empty core
security floor for valid sparse inputs.
