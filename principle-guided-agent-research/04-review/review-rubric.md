# Review Rubric for Individual Methodology Proposals

Date: 2026-07-09

This rubric is used to evaluate the five expert proposals for the
principle-guided secure code generation methodology.

## Scoring Scale

Each criterion is scored from 1 to 5.

| Score | Meaning                                                         |
| ----- | --------------------------------------------------------------- |
| 1     | Missing or mostly unusable.                                     |
| 2     | Present but shallow, vague, or weakly connected to the project. |
| 3     | Solid but incomplete; useful with moderate refinement.          |
| 4     | Strong, concrete, and well aligned with the research goals.     |
| 5     | Excellent; directly usable as a core part of the final method.  |

## Criteria

1. **Research Fit**
   - Does the proposal address the central research goal: using principles or
     policies to guide agent behavior toward secure and correct code?

2. **Policy-Harness Design**
   - Does it move beyond prompt-only guidance and define executable harness
     mechanisms?

3. **Trajectory-Level Control**
   - Does it use agent behavior phases and explain how policies affect
     inspection, planning, implementation, validation, repair, and reporting?

4. **Dynamic Policy Selection and Adoption**
   - Does it explain how policies are selected initially and updated as the
     trajectory reveals new risks?

5. **Security Enforcement and Evidence**
   - Does it define concrete controls, validators, probes, evidence
     requirements, and fail-safe behavior?

6. **Cross-Task Extensibility**
   - Does it support adaptation across task families, languages, frameworks,
     and benchmark types?

7. **Evaluation Readiness**
   - Does it produce measurable hypotheses, metrics, artifacts, or experimental
     conditions?

8. **Implementation Practicality**
   - Is the proposal buildable in stages with reasonable first prototypes?

9. **Originality and Contribution**
   - Does it add a distinct insight that strengthens the final methodology?

10. **Clarity**
    - Is it clear, structured, and easy to use as a research/design artifact?

## Overall Rating

Overall rating is not a simple average. It considers:

- how central the proposal is to the final method;
- whether its weak points can be compensated by other proposals;
- whether its strengths are unique.
