import { expect, test } from 'bun:test';

import { buildPrompt } from './run-pgacs-semantic-selector';

test('semantic selector prompt receives task inputs without silver labels', () => {
  const labeledTask = {
    taskId: 'task-1',
    taskFamily: 'web_api',
    prompt: 'Add an endpoint.',
    repoHints: ['server.ts'],
    requiredPolicyIds: ['secret-required-answer'],
    relevantPolicyIds: ['secret-relevant-answer'],
  };
  const taskInput = {
    taskId: labeledTask.taskId,
    prompt: labeledTask.prompt,
    repoHints: labeledTask.repoHints,
  };
  const prompt = buildPrompt(
    [taskInput],
    [
      {
        id: 'policy-1',
        source: 'test',
        category: 'Input Validation',
        text: 'Validate input.',
        cweTags: ['CWE-20'],
        selectable: true,
      },
    ]
  );

  expect(prompt).not.toContain('requiredPolicyIds');
  expect(prompt).not.toContain('relevantPolicyIds');
  expect(prompt).not.toContain('secret-required-answer');
  expect(prompt).not.toContain('taskFamily');
  expect(prompt).not.toContain('web_api');
  expect(prompt).toContain('Add an endpoint.');
});
