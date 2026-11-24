export { discoverTargets } from "./discover.js";
export { emitToolPauseRules, formatToolPauseEmit } from "./emit-toolpause.js";
export type { ToolPauseRulesEmit } from "./emit-toolpause.js";
export { builtinRules } from "./rules/index.js";
export { scanRoots, shouldFail, maxSeverity } from "./scan.js";
export type {
  Finding,
  Rule,
  ScanResult,
  ScanTarget,
  Severity,
  TargetKind,
} from "./types.js";
