export { discoverTargets } from "./discover.js";
export { loadConfigFile, mergeConfig } from "./config.js";
export { emitToolPauseRules, formatToolPauseEmit } from "./emit-toolpause.js";
export type { ToolPauseRulesEmit } from "./emit-toolpause.js";
export { builtinRules } from "./rules/index.js";
export { loadRulesFromDir } from "./rules/load.js";
export { scanRoots, shouldFail, maxSeverity, getActiveRules } from "./scan.js";
export { formatSarif } from "./format/sarif.js";
export { formatText } from "./format/text.js";
export { formatHtml } from "./format/html.js";
export { formatJson } from "./format/json.js";
export { packageVersion, TOOL_NAME, TOOL_URI } from "./version.js";
export type {
  Finding,
  Rule,
  ScanConfig,
  ScanResult,
  ScanTarget,
  Severity,
  TargetKind,
  BaselineFile,
  DriftFile,
} from "./types.js";
