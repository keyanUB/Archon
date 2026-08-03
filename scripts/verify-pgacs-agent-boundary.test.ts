import { describe, expect, test } from 'bun:test';

import { toolAttempted } from './verify-pgacs-agent-boundary';

describe('PGACS live agent-boundary verifier', () => {
  test('attributes direct Claude tool attempts to their exact input', () => {
    const stream = JSON.stringify({
      type: 'assistant',
      message: {
        content: [
          {
            type: 'tool_use',
            name: 'Bash',
            input: { command: 'cat /private/tmp/cell/attempts/boundary-secret.txt' },
          },
        ],
      },
    });
    expect(toolAttempted(stream, 'Bash', 'boundary-secret.txt')).toBe(true);
    expect(toolAttempted(stream, 'Bash', 'example.com')).toBe(false);
  });

  test('attributes Archon tool events without treating prompt text as an attempt', () => {
    const prompt = JSON.stringify({ type: 'prompt', content: 'curl https://example.com/' });
    const tool = JSON.stringify({
      type: 'tool',
      tool_name: 'Bash',
      tool_input: { command: 'curl https://example.com/' },
    });
    expect(toolAttempted(prompt, 'Bash', 'example.com')).toBe(false);
    expect(toolAttempted(tool, 'Bash', 'example.com')).toBe(true);
  });
});
