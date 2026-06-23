---
description: Select relevant setup/environment policies and map them to the setup task
argument-hint: (reads classification and policy data)
---

# Secure Environment Setup: Policy Analysis

**Request**: $ARGUMENTS
**Workflow ID**: $WORKFLOW_ID

---

## Mission

Read the setup/environment policy file and map relevant policies to this setup task.

Policy source:

```bash
cat .archon/data/research/secure-environment-setup/setup-environment-policies.json
```

Classification from prior node:

```json
$classify.output
```

## Instructions

1. Read `.archon/data/research/secure-environment-setup/setup-environment-policies.json`.
2. Select policies whose `setup_env_theme` matches the classification themes.
3. Prefer policies with practical setup implications:
   - least privilege and service identity
   - transport/network exposure and authentication
   - secret/key storage, rotation, and access
   - secure defaults and configuration hardening
   - logging/monitoring setup
   - dependency and package provenance
4. Explain how each selected policy constrains implementation.
5. If the request is dangerous as written, state why and describe automatic safe defaults.

## Output

Write `$ARTIFACTS_DIR/policy-analysis.md`:

```markdown
# Setup Policy Analysis

## Classification

{task type, risk level, themes}

## Selected Policies

| Policy ID | Source | Theme | Setup Implication |
|-----------|--------|-------|-------------------|
| ... | ... | ... | ... |

## Security Interpretation

{risk analysis}

## Safe Defaults Required

- ...
```
