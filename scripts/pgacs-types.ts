export type PolicySeverity = 'advisory' | 'required' | 'fail_closed';

export type TaskFamily =
  | 'web_api'
  | 'file_parser'
  | 'database'
  | 'auth_session'
  | 'environment_setup'
  | 'cli_tool'
  | 'dependency_build'
  | 'agent_tooling'
  | 'unknown';

export interface PolicyRecord {
  id: string;
  title: string;
  version: string;
  sourcePrinciples: {
    source: string;
    ref?: string;
    text: string;
  }[];
  normativeText: string;
  riskTags: string[];
  cweTags: string[];
  taskTriggers: string[];
  inputChannels: string[];
  dangerousSinks: string[];
  assetTags: string[];
  trustBoundaryTags: string[];
  dependencyTags: string[];
  environmentTags: string[];
  phaseBindings: string[];
  validators: string[];
  evidenceRequirements: string[];
  forbiddenWorkarounds: string[];
  severity: PolicySeverity;
}

export interface TaskSurfaceConfidence {
  taskFamily: number;
  risks: number;
  missingInputs: number;
}

export interface TaskSurface {
  taskId: string;
  taskFamily: TaskFamily;
  languageFrameworks: string[];
  inputChannels: string[];
  dangerousSinks: string[];
  assets: string[];
  trustBoundaries: string[];
  runtimeExposure: string[];
  dependencies: string[];
  environmentConstraints: string[];
  likelyCwes: string[];
  missingSecurityInputs: string[];
  existingTests: string[];
  confidence: TaskSurfaceConfidence;
}

export interface PolicySelection {
  policy: PolicyRecord;
  score: number;
  rationale: string[];
}
