# Policy-Guided Agent Control: Milestone 1 Prototype

This directory is the first concrete implementation step for PGACS in Archon.

The prototype keeps the scope narrow:

1. normalize the existing secure-environment-setup policy corpus;
2. extract a task surface from a task prompt plus repo hints;
3. emit machine-readable schemas and a sample task-surface instance;
4. keep the policy registry separate from enforcement.

## Files

- `scripts/generate-pgacs-research-artifacts.ts`
  - Generates the normalized registry and the schema files.
- `scripts/pgacs-policy-registry.ts`
  - Policy-corpus normalizer and selector.
- `scripts/pgacs-task-surface.ts`
  - Heuristic task-surface extractor.

## Generated artifacts

The generator writes to:

```text
.archon/data/research/pgacs/
```

Expected files:

- `policy-registry.normalized.json`
- `policy-record.schema.json`
- `task-surface.schema.json`
- `task-surface.example.json`

## Intended use

This is not the final harness. It is the first buildable layer that makes the
research method concrete enough to test policy selection before any runtime
enforcement is added.

