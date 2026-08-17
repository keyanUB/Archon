# Archive Relocation Record

Historical research phases previously lived directly under
`principle-guided-agent-research/`. They were moved without changing their phase
names:

```text
principle-guided-agent-research/<phase>/
  -> principle-guided-agent-research/archive/<phase>/
```

This relocation separates the active SecRepoBench specification from prior
research while retaining every tracked artifact. Markdown links and current
script lookup paths were adjusted where needed. Frozen JSON evidence was not
rewritten: embedded paths, content hashes, and receipts continue to describe
the original execution state.

Consequences:

- current code should use the `archive/<phase>` filesystem location;
- historical manifests may still display the pre-relocation path;
- path- or script-digest-bound receipts must be reproduced from their recorded
  commit; and
- archived evidence must never be silently re-signed after relocation.
