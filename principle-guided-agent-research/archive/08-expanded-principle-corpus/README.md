# Expanded Principle Corpus

Date: 2026-07-27

## Purpose

The initial PGACS registry contains 84 setup/environment policies. That corpus
is too narrow for evaluating policy selection across web APIs, authentication,
file parsing, dependency builds, and agent tooling.

This prototype therefore combines every principle/policy source already
prepared in the Archon repository into one compact semantic catalog. It does
not add a capability taxonomy or infer more enforcement metadata.

## Included Sources

| Source | Granular/selectable | Context-only | Role |
| --- | ---: | ---: | --- |
| OWASP SCP / GRASP graph | 214 | 14 | Detailed secure-coding principles plus category summaries |
| Setup/environment policy corpus | 84 | 0 | Setup, deployment, supply-chain, runtime, and agent-security policies |
| OWASP SCP quick reference | 0 | 55 | Compact summaries useful as semantic context |
| **Total** | **298** | **69** | **367 records** |

The quick-reference bullets and GRASP category nodes are marked context-only
because they summarize more granular records. They remain in the corpus for
inspection and semantic context but should not be returned as selected policy
IDs.

## Record Shape

The enlarged corpus intentionally uses a smaller representation than
`PolicyRecord`:

```ts
type PrincipleCorpusRecord = {
  id: string;
  source: string;
  sourceRef: string;
  kind: 'principle' | 'policy' | 'category_summary' | 'quick_reference';
  category?: string;
  text: string;
  cweTags: string[];
  selectable: boolean;
  provenance: {
    path: string;
    recordId: string;
  };
};
```

This is sufficient for an LLM semantic selector: it can read policy meaning,
category, and provenance without depending on noisy inferred tags.

## Design Choices

### Preserve rather than rewrite

Source text is retained as prepared. The builder does not ask another model to
summarize, classify, or enrich every record. This keeps corpus construction
deterministic and prevents model-generated metadata from becoming assumed
ground truth.

### Stable namespaced IDs

Corpus IDs include their source namespace, for example:

- `grasp-scp:OWASP_001`;
- `setup:ASVS-280`;
- `owasp-scp-quick:input-validation-01`.

The original ID remains in `sourceRef`, preserving compatibility with source
documents while preventing collisions between future packs.

### No semantic deduplication yet

Near-duplicate policies are preserved because deciding that two controls are
equivalent requires semantic judgment. The later selector should avoid choosing
redundant records, and its decision log can reveal which duplicates matter in
practice.

## Generated Artifact

The corpus is generated at:

```text
.archon/data/research/pgacs/principle-corpus.expanded.json
```

Rebuild it from the Archon repository root:

```bash
bun run scripts/build-pgacs-principle-corpus.ts
```

## Immediate Use

The next prototype should give the semantic selector the 298 selectable
records, require output IDs to exist in this immutable catalog, and separately
record any missing control the selector cannot find. The deterministic baseline
uses its original 84-policy domain registry plus the three-policy core security
floor; it remains separate from this expanded semantic corpus.
