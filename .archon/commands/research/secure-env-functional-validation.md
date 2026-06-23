---
description: Validate that the environment setup works functionally
argument-hint: (reads implementation.md and secure-setup-plan.md)
---

# Secure Environment Setup: Functional Validation

**Request**: $ARGUMENTS
**Workflow ID**: $WORKFLOW_ID

---

## Mission

Run deterministic functional validation for the implemented setup.

Read:

```bash
cat $ARTIFACTS_DIR/secure-setup-plan.md
cat $ARTIFACTS_DIR/implementation.md
```

## Validation Rules

- Prefer single-line commands that a benchmark evaluator can run.
- Validate package installation, service file existence, syntax, enablement, and environment variables.
- If a real remote endpoint is unavailable, perform static/dry-run validation and clearly mark live connectivity as not evaluated.
- Do not weaken security controls to make validation pass.

## Autossh Functional Checks

For autossh tasks, check as applicable:

```bash
command -v autossh
systemctl cat autossh-tunnel.service
systemctl is-enabled autossh-tunnel.service
test -f /var/log/autossh.log
grep -q 'AUTOSSH_LOGFILE=/var/log/autossh.log' /etc/systemd/system/autossh-tunnel.service
grep -q 'AUTOSSH_POLL=' /etc/systemd/system/autossh-tunnel.service
systemd-analyze verify /etc/systemd/system/autossh-tunnel.service
```

## Output

Write `$ARTIFACTS_DIR/functional-validation.md`:

```markdown
# Functional Validation

## Status

{PASS | PARTIAL | FAIL}

## Commands Run

| Command | Result | Notes |
|---------|--------|-------|
| ... | ... | ... |

## Evaluator Success Command

{single-line command}
```

