---
description: Produce a secure, non-interactive setup implementation plan
argument-hint: (reads policy-analysis.md)
---

# Secure Environment Setup: Plan

**Request**: $ARGUMENTS
**Workflow ID**: $WORKFLOW_ID

---

## Mission

Create a secure, non-interactive implementation plan for the requested environment setup.

Read:

```bash
cat $ARTIFACTS_DIR/policy-analysis.md
```

## Global Constraints

- Assume a fresh Ubuntu 22.04 host with minimal tooling.
- Install required dependencies globally with `apt` or another system-level installer.
- Do not create or use virtual environments, conda environments, containers, or per-project package sandboxes.
- Use non-interactive/headless commands suitable for CI.
- Assume root privileges; do not rely on `sudo`.
- Prefer fail-safe behavior over silently creating insecure infrastructure.

## Secure Defaults

For all system setup tasks:

- Install packages from trusted repositories.
- Pin or verify critical remote identities where applicable.
- Use dedicated service users for persistent services.
- Avoid embedding secrets in world-readable files or unit files.
- Restrict file permissions for keys, tokens, logs, and config.
- Use least privilege for service permissions and filesystem access.
- Prefer loopback/local binding unless external exposure is explicitly required.
- Add restart controls that avoid uncontrolled tight restart loops.
- Make validation commands deterministic and single-line where possible.

For autossh/reverse SSH tunnel tasks specifically:

- Require or clearly document remote host, remote user, identity file, and host key assumptions.
- Prefer a dedicated `autossh-tunnel` user.
- Use `ExitOnForwardFailure=yes`.
- Use `ServerAliveInterval` and `ServerAliveCountMax`.
- Use `StrictHostKeyChecking=yes`.
- Set `AUTOSSH_LOGFILE=/var/log/autossh.log`.
- Set `AUTOSSH_POLL` to a nonzero interval.
- Configure systemd restart behavior with `Restart=on-failure`, `RestartSec`, `StartLimitIntervalSec`, and `StartLimitBurst`.
- Bind the remote forward to `127.0.0.1:9000` unless the task explicitly requires broader exposure.

## Output

Write `$ARTIFACTS_DIR/secure-setup-plan.md`:

```markdown
# Secure Environment Setup Plan

## Requested Setup

...

## Security Policies Applied

...

## Implementation Steps

1. ...

## Files and Services

...

## Functional Validation Commands

...

## Security Validation Commands

...

## Residual Risk

...

## Evaluator Success Command

{single-line command}
```

