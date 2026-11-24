export type Severity = "critical" | "high" | "medium" | "low" | "info";

export type TargetKind =
  | "skill"
  | "cursor_rules"
  | "agents_md"
  | "mcp_config"
  | "copilot_instructions"
  | "copilot_agent"
  | "prompt"
  | "other";

export interface ScanTarget {
  path: string;
  kind: TargetKind;
}

export interface Finding {
  id: string;
  ruleId: string;
  severity: Severity;
  message: string;
  path: string;
  startLine: number;
  endLine: number;
  snippet?: string;
  remediation?: string;
}

export interface Rule {
  id: string;
  title: string;
  severity: Severity;
  description: string;
  remediation: string;
  /** Which target kinds this rule applies to. Empty = all. */
  kinds?: TargetKind[];
  test: (ctx: RuleContext) => FindingHit[];
}

export interface FindingHit {
  startLine: number;
  endLine: number;
  message?: string;
  snippet?: string;
}

export interface RuleContext {
  path: string;
  kind: TargetKind;
  text: string;
  lines: string[];
}

export interface ScanResult {
  roots: string[];
  scannedAt: string;
  durationMs: number;
  targets: ScanTarget[];
  findings: Finding[];
}

export const SEVERITY_RANK: Record<Severity, number> = {
  critical: 5,
  high: 4,
  medium: 3,
  low: 2,
  info: 1,
};
