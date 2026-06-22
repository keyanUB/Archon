---
description: Validate security controls for environment setup
argument-hint: (reads all prior setup artifacts)
---

# Secure Environment Setup: Security Validation

**Request**: $ARGUMENTS
**Workflow ID**: $WORKFLOW_ID

---

## Mission

Validate that the implementation obeys the selected setup/environment security policies.

Read:

```bash
cat $ARTIFACTS_DIR/policy-analysis.md
cat $ARTIFACTS_DIR/secure-setup-plan.md
cat $ARTIFACTS_DIR/implementation.md
cat $ARTIFACTS_DIR/functional-validation.md
```

## Security Checks

Check for:

- Dedicated least-privilege service identity where applicable.
- No unnecessary root execution for long-running service processes.
- Restricted permissions for secrets, keys, config, and logs.
- No private keys, tokens, or passwords embedded in world-readable files.
- Host key verification is not disabled for SSH-based setup.
- Network binding is no broader than requested.
- Restart policy includes sane delay/rate limiting.
- Logging is configured and not world-writable.
- Package source/provenance is reasonable for the target OS.
- Any missing live input is fail-safe and documented.

## Autossh Security Checks

For autossh tasks, verify the service does not use insecure shortcuts such as:

- `StrictHostKeyChecking=no`
- root private key by default
- broad `0.0.0.0` remote bind without explicit user requirement
- missing `ExitOnForwardFailure=yes`
- missing `AUTOSSH_LOGFILE`
- missing or zero `AUTOSSH_POLL`
- uncontrolled `Restart=always` without rate limits

## Output

Write `$ARTIFACTS_DIR/security-validation.md`:

```markdown
# Security Validation

## Status

{PASS | PARTIAL | FAIL}

## Policy Coverage

| Theme | Controls Verified | Result |
|-------|-------------------|--------|
| ... | ... | ... |

## Findings

| Severity | Finding | Required Fix |
|----------|---------|--------------|
| ... | ... | ... |

## Residual Risk

...
```

