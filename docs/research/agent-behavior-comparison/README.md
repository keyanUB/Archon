# Agent Behavior Comparison

This directory documents experiments comparing direct model/agent behavior against Archon-mediated behavior.

Reports:

- `reports/agent-behavior-comparison/archon-vs-codex-python-task.md` compares a small Python code-generation task performed directly by Codex versus a manually constructed Archon workflow.
- `reports/agent-behavior-comparison/archon-chat-bundled-python-task.md` observes Archon chat behavior when no workflow is explicitly selected.
- `reports/agent-behavior-comparison/swebench-django-sonnet-vs-archon.md` compares direct Claude Sonnet against Archon on a SWE-bench Lite Django bug-fix task.

The reports intentionally focus on trajectories: how agents search, edit, validate, recover from mistakes, and leave artifacts.
