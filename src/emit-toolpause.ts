import fs from "node:fs";
import path from "node:path";
import type { Finding, ScanResult, ScanTarget, Severity } from "./types.js";
import { SEVERITY_RANK } from "./types.js";

const GATE_URL = "https://toolpause.fly.dev";
const DOCS_URL = "https://toolpause.netlify.app/docs/scan-then-gate";
const SCAN_URL = "https://toolpause.netlify.app/scan";

export type GateDecision = "deny" | "require_approval";

export interface ToolPauseRulesEmit {
  source: "toolfence-scan";
  generated_at: string;
  summary: string;
  /** Paste-friendly fragment for ToolFence Gate → Rules. */
  policy: {
    deny_tools: string[];
    deny_tags: string[];
    tool_overrides: Record<string, GateDecision>;
    notes: string[];
  };
  /** Ready-to-paste strings for the Gate Inbox Rules form. */
  paste: {
    deny_tools: string;
    deny_tags: string;
    tool_overrides_json: string;
  };
  how_to_apply: string[];
  links: {
    gate: string;
    docs: string;
    scan: string;
  };
  findings_considered: number;
}

function tryParseJson(text: string): unknown {
  try {
    return JSON.parse(text);
  } catch {
    const stripped = text.replace(/^\s*\/\/.*$/gm, "");
    try {
      return JSON.parse(stripped);
    } catch {
      return null;
    }
  }
}

function collectMcpNames(target: ScanTarget): string[] {
  if (target.kind !== "mcp_config") return [];
  let text: string;
  try {
    text = fs.readFileSync(target.path, "utf8");
  } catch {
    return [];
  }
  const data = tryParseJson(text);
  if (!data || typeof data !== "object") return [];
  const names = new Set<string>();

  const servers =
    (data as { mcpServers?: Record<string, unknown> }).mcpServers ||
    (data as { servers?: Record<string, unknown> }).servers ||
    null;

  if (servers && typeof servers === "object") {
    for (const key of Object.keys(servers)) {
      names.add(key);
      const entry = servers[key] as Record<string, unknown> | undefined;
      if (!entry || typeof entry !== "object") continue;
      const tools = entry.tools;
      if (Array.isArray(tools)) {
        for (const t of tools) {
          if (typeof t === "string" && t !== "*") names.add(`${key}.${t}`);
        }
      }
    }
  }

  return [...names];
}

function skillLabel(filePath: string): string {
  const base = path.basename(path.dirname(filePath));
  const file = path.basename(filePath, path.extname(filePath));
  if (file.toLowerCase() === "skill") return `skill:${base}`;
  return `skill:${file}`;
}

function decisionForFinding(f: Finding): GateDecision {
  // Critical always deny; high defaults to require_approval unless clearly over-broad / remote-exec.
  if (f.severity === "critical") return "deny";
  if (f.ruleId === "mcp-overbroad" || f.ruleId === "remote-exec" || f.ruleId === "credential-exfil") {
    return "deny";
  }
  return "require_approval";
}

function mergeDecision(
  current: GateDecision | undefined,
  next: GateDecision
): GateDecision {
  if (current === "deny" || next === "deny") return "deny";
  return "require_approval";
}

/**
 * Build a ToolFence Gate Rules fragment from scan findings.
 * MCP configs → deny / require_approval on server + tool names.
 * Skills → deny_tags + notes (skills aren't runtime tool names).
 */
export function emitToolPauseRules(
  result: ScanResult,
  minSeverity: Severity = "high"
): ToolPauseRulesEmit {
  const threshold = SEVERITY_RANK[minSeverity];
  const considered = result.findings.filter((f) => SEVERITY_RANK[f.severity] >= threshold);

  const denyTools = new Set<string>();
  const toolOverrides: Record<string, GateDecision> = {};
  const notes: string[] = [];
  const denyTags = new Set<string>(["skill-scan-blocked"]);

  const targetsByPath = new Map(result.targets.map((t) => [path.resolve(t.path), t]));

  for (const f of considered) {
    const target = targetsByPath.get(path.resolve(f.path));
    if (!target) continue;
    const decision = decisionForFinding(f);

    if (target.kind === "mcp_config") {
      const names = collectMcpNames(target);
      for (const name of names) {
        toolOverrides[name] = mergeDecision(toolOverrides[name], decision);
        if (toolOverrides[name] === "deny") denyTools.add(name);
      }
      notes.push(
        `MCP ${path.basename(f.path)}:${f.startLine} [${f.ruleId}/${f.severity}] → ${decision} (${names.join(", ") || "config"})`
      );
    } else {
      const label = skillLabel(f.path);
      notes.push(`${label} [${f.ruleId}/${f.severity}] ${f.message}`);
      denyTags.add("untrusted-skill");
      if (f.severity === "critical") denyTags.add("skill-scan-critical");
    }
  }

  const uniqNotes = [...new Set(notes)].slice(0, 40);
  const denyToolsSorted = [...denyTools].sort();
  const denyTagsSorted = [...denyTags].sort();
  const overridesSorted = Object.fromEntries(
    Object.entries(toolOverrides).sort(([a], [b]) => a.localeCompare(b))
  );

  return {
    source: "toolfence-scan",
    generated_at: new Date().toISOString(),
    summary:
      considered.length === 0
        ? "No findings at threshold — no Gate denies suggested."
        : `Suggested Gate policy from ${considered.length} finding(s). Merge into Rules — do not blind-overwrite production.`,
    policy: {
      deny_tools: denyToolsSorted,
      deny_tags: denyTagsSorted,
      tool_overrides: overridesSorted,
      notes: uniqNotes,
    },
    paste: {
      deny_tools: denyToolsSorted.join(", "),
      deny_tags: denyTagsSorted.join(", "),
      tool_overrides_json: JSON.stringify(overridesSorted, null, 2),
    },
    how_to_apply: [
      `Open Gate → Rules: ${GATE_URL}/`,
      "Merge paste.deny_tools into “Never allow these tools” (comma-separated).",
      "Merge paste.deny_tags into deny tags if you use tags on agents/skills.",
      "Merge paste.tool_overrides_json into per-tool overrides (JSON object).",
      "Save policy, then re-run a risky tool to confirm Inbox / deny behavior.",
      `Full walkthrough: ${DOCS_URL}`,
    ],
    links: {
      gate: `${GATE_URL}/`,
      docs: DOCS_URL,
      scan: SCAN_URL,
    },
    findings_considered: considered.length,
  };
}

export function formatToolPauseEmit(emit: ToolPauseRulesEmit): string {
  return JSON.stringify(emit, null, 2) + "\n";
}

/** Human next-steps for stderr after emit. */
export function formatEmitHints(emit: ToolPauseRulesEmit): string {
  const lines = [
    "",
    "Next — apply in ToolFence Gate:",
    ...emit.how_to_apply.map((s, i) => `  ${i + 1}. ${s}`),
    "",
  ];
  return lines.join("\n");
}
