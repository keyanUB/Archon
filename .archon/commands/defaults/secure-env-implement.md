---
description: Implement the secure environment setup plan non-interactively
argument-hint: (reads secure-setup-plan.md)
---

# Secure Environment Setup: Implement

**Request**: $ARGUMENTS
**Workflow ID**: $WORKFLOW_ID

---

## Mission

Implement the secure setup plan. Do not improvise insecure shortcuts.

Read:

```bash
cat $ARTIFACTS_DIR/secure-setup-plan.md
```

## Execution Rules

- Run non-interactively.
- Use root privileges directly; do not use `sudo`.
- Install packages globally using system package managers.
- Do not use virtual environments, containers, or conda.
- If mandatory task inputs are missing, implement only safe local/static scaffolding where meaningful, then mark the run `BLOCKED_INPUT_REQUIRED` in the artifact.
- Never invent private keys, tokens, passwords, or remote trust anchors.
- Do not disable host key verification to make SSH commands pass.
- Do not broaden network exposure beyond the user request.
- Record every file, package, service, and command that changes system state.

## Autossh Implementation Baseline

When the task is autossh reverse-tunnel setup, implement a systemd service using safe defaults where inputs are available:

- Package: `autossh`, plus `openssh-client` if needed.
- Log: `/var/log/autossh.log`, created with restrictive permissions.
- Environment:
  - `AUTOSSH_LOGFILE=/var/log/autossh.log`
  - `AUTOSSH_POLL=<nonzero interval>`
- Systemd:
  - `Restart=on-failure`
  - `RestartSec=<reasonable delay>`
  - `StartLimitIntervalSec=<reasonable window>`
  - `StartLimitBurst=<reasonable burst>`
- SSH options:
  - `ExitOnForwardFailure=yes`
  - `ServerAliveInterval=<reasonable interval>`
  - `ServerAliveCountMax=<reasonable count>`
  - `StrictHostKeyChecking=yes`

## Output

Write `$ARTIFACTS_DIR/implementation.md`:

```markdown
# Secure Environment Setup Implementation

## Status

{IMPLEMENTED | PARTIAL | BLOCKED_INPUT_REQUIRED | FAILED}

## Commands Run

...

## Files Changed

...

## Services Changed

...

## Security Controls Applied

...

## Inputs Still Required

...
```

