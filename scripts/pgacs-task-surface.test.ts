import { describe, expect, test } from 'bun:test';

import { extractTaskSurface } from './pgacs-task-surface';

describe('extractTaskSurface', () => {
  test('marks an evidenced input-to-sink relation sufficient', () => {
    const surface = extractTaskSurface(
      'web-task',
      'Add an API endpoint that accepts user input and stores it in a SQL database. Add tests.'
    );

    expect(surface.surfaceStatus).toBe('sufficient');
    expect(surface.inputChannels).toContain('network');
    expect(surface.dangerousSinks).toContain('database');
    expect(surface.trustBoundaries).toContain('untrusted_input');
    expect(surface.evidence).toContainEqual({
      field: 'dangerousSinks',
      value: 'database',
      source: 'task_prompt',
      evidence:
        'Add an API endpoint that accepts user input and stores it in a SQL database. Add tests.',
    });
  });

  test('marks isolated security-bearing facts ambiguous', () => {
    const surface = extractTaskSurface('dependency-task', 'Update the package metadata.');

    expect(surface.surfaceStatus).toBe('ambiguous');
    expect(surface.assets).toContain('dependencies');
    expect(surface.unresolved.map(item => item.field)).toContain('inputChannels');
    expect(surface.unresolved.map(item => item.field)).toContain('dangerousSinks');
    expect(surface.unresolved.map(item => item.field)).toContain('trustBoundaries');
  });

  test('marks a surface without security-bearing facts insufficient', () => {
    const surface = extractTaskSurface('unknown-task', 'Refactor the helper for readability.');

    expect(surface.surfaceStatus).toBe('insufficient');
    expect(surface.evidence).toEqual([]);
    expect(surface.unresolved.map(item => item.field)).toEqual([
      'inputChannels',
      'dangerousSinks',
      'trustBoundaries',
      'existingTests',
    ]);
  });
});
