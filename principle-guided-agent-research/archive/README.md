# PGACS Research Archive

This directory preserves superseded designs, intermediate datasets, generated
artifacts, and prior experiments. It exists for provenance and retrieval. The
active specification and development instructions are in
[`../README.md`](../README.md).

The path change and its effect on frozen receipts are documented in
[`RELOCATION.md`](RELOCATION.md).

Archived material is not deleted or flattened. Relative links between archived
phases continue to work. Frozen JSON artifacts retain their original embedded
paths and digests; changing them would rewrite historical evidence.

## Retrieval Guide

| Phase | Contents | Use it when |
| --- | --- | --- |
| [00-pitch](00-pitch/) | Proposal, presentation, and early framing | Preparing historical presentations or tracing the original motivation |
| [01-foundation](01-foundation/) | Research questions, resources, and initial taxonomy | Tracing the research foundation |
| [02-expert-proposals](02-expert-proposals/) | Architecture, security, ML, agent-security, and evaluation proposals | Recovering alternatives considered before synthesis |
| [03-synthesis](03-synthesis/) | Five-agent methodology synthesis | Understanding how the initial proposals were combined |
| [04-review](04-review/) | Proposal review and rubric | Recovering early design criticism and scoring |
| [05-final-method](05-final-method/) | Conceptual PGAH design | Comparing PGAH with the later implementable PGACS design |
| [06-implementable-method](06-implementable-method/) | Generic PGACS design, policy registry, selector, and detailed ADRs | Tracing generic architecture decisions that predate SecRepoBench |
| [07-prototype-evaluation](07-prototype-evaluation/) | First selector evaluation and silver labels | Reproducing the original deterministic selector study |
| [08-expanded-principle-corpus](08-expanded-principle-corpus/) | Expanded policy corpus summary | Inspecting policy-corpus provenance |
| [09-semantic-selector-evaluation](09-semantic-selector-evaluation/) | Semantic selector artifacts and adjudication | Reproducing or auditing semantic-selection experiments |
| [10-guided-trajectory-prototype](10-guided-trajectory-prototype/) | ZIP-task trajectory experiment and evaluator | Studying the earliest paired trajectory-control experiment |
| [11-prototype-report-and-roadmap](11-prototype-report-and-roadmap/) | Consolidated historical report | Reviewing the pre-C2 prototype state |
| [12-archon-c2-prototype](12-archon-c2-prototype/) | First Archon C2 harness and as-built design | Comparing the generic C2 mechanism with the current repository specialization |
| [13-smoke-dataset](13-smoke-dataset/) | Superseded smoke cohort | Reproducing old dataset validation only |
| [14-baxbench-pilot](14-baxbench-pilot/) | Ten-task prompt-only BaxBench pilot | Auditing the prompt-guidance baseline study |
| [15-multibench-prototype](15-multibench-prototype/) | PGACS v0.3, BaxBench C2, and multibench planning | Tracing the direct parent of the SecRepoBench branch |

## Authority Rule

Use archived material as evidence of what was attempted or decided at that
time. Do not use it to override the current technical design, reproduce a
current experiment without checking its frozen inputs, or infer that historical
metrics support current claims.

Some historical receipts bind the exact source path and script digest from the
commit that produced them. Relocating the surrounding directory intentionally
does not regenerate those receipts. Reproduce such a receipt from its recorded
commit, or treat a current validation mismatch as expected provenance drift,
not as permission to update the old digest.

When reviving an archived mechanism:

1. identify its source phase and frozen dependencies;
2. compare its contracts with the current technical design;
3. create a new active design decision rather than editing history; and
4. preserve the original artifact unchanged.
