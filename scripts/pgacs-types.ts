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

export type SurfaceStatus = 'sufficient' | 'ambiguous' | 'insufficient';

export interface SurfaceEvidence {
  field: string;
  value: string;
  source: 'task_prompt' | 'repo_hint' | 'repo_scan' | 'semantic_proposal';
  evidence: string;
}

export interface UnresolvedSurfaceQuestion {
  field: string;
  question: string;
  reason: string;
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
  surfaceStatus: SurfaceStatus;
  evidence: SurfaceEvidence[];
  unresolved: UnresolvedSurfaceQuestion[];
}

export interface PolicyProposal {
  policyId: string;
  confidence: number;
  rationale: string;
}

export interface PolicySelectionBudget {
  maxPolicies: number;
}

export interface SelectedPolicyDecision {
  policyId: string;
  score: number;
  disposition: 'mandatory' | 'ranked' | 'fallback';
  matchedSurface: string[];
  rationale: string[];
}

export type PolicySelectionMode = 'explicit' | 'hybrid' | 'fallback';

export interface RejectedPolicyDecision {
  policyId: string;
  score: number;
  reason: 'no_match' | 'budget' | 'invalid_proposal';
}

export interface PolicySelectionDecision {
  taskId: string;
  selectionMode: PolicySelectionMode;
  surfaceStatus: SurfaceStatus;
  selected: SelectedPolicyDecision[];
  rejected: RejectedPolicyDecision[];
  coverageGaps: string[];
  unresolved: UnresolvedSurfaceQuestion[];
  reassessmentTriggers: string[];
  budget: PolicySelectionBudget & {
    mandatoryPolicies: number;
    rankedPolicies: number;
    fallbackPolicies: number;
    budgetExceededByMandatory: boolean;
    budgetExceededBySafetyFloor: boolean;
  };
  selectorVersion: string;
}

export interface PolicySelectionDelta {
  trigger: string;
  addedPolicies: string[];
  retainedPolicies: string[];
  rationale: string;
}
