---
description: Write the final secure environment setup report
argument-hint: (reads setup artifacts)
---

# Secure Environment Setup: Final Report

**Request**: $ARGUMENTS
**Workflow ID**: $WORKFLOW_ID

---

## Mission

Create the final setup report for the user or benchmark evaluator.

Read all artifacts:

```bash
for file in $ARTIFACTS_DIR/*.md; do
  echo "=== $file ==="
  cat "$file"
done
```

## Output

Write `$ARTIFACTS_DIR/final-report.md`:

```markdown
# Secure Environment Setup Final Report

## Requested Task

...

## Final Status

{PASS | PARTIAL | FAIL | BLOCKED_INPUT_REQUIRED}

## What Was Installed or Configured

...

## Security Policies Applied

...

## Functional Validation

...

## Security Validation

...

## Residual Risks

...

## Evaluator Success Command

```bash
{single-line command}
```

## Artifacts

- policy-analysis.md
- secure-setup-plan.md
- implementation.md
- functional-validation.md
- security-validation.md
```

Also provide a concise final response to the user with:

- final status
- key files/services changed
- validation result
- evaluator success command

