import fs from "node:fs";
import path from "node:path";
import type { ScanResult, ScanTarget } from "./types.js";
import { SEVERITY_RANK } from "./types.js";

export interface ToolPauseRulesEmit {
  source: "skill-scan";
  generated_at: string;
  summary: string;
  /** Paste-friendly PolicySnapshot fragment for ToolPause Rules. */
  policy: {
    deny_tools: string[];
    deny_tags: string[];
    tool_overrides: Record<string, "deny" | "require_approval">;
    notes: string[];
  };
  findings_considered: number;
}

function tryParseJson(text: string): unknown {
  try {
    return JSON.parse(text);
  } catch {
    // JSONC-ish: strip // comments lightly
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

/**
 * Build a ToolPause Rules fragment from scan findings.
 * High/critical findings on MCP configs → deny those servers/tools.
 * Skill findings → deny_tags + notes (skills aren't tool names).
 */
export function emitToolPauseRules(
  result: ScanResult,
  minSeverity: keyof typeof SEVERITY_RANK = "high"
): ToolPauseRulesEmit {
  const threshold = SEVERITY_RANK[minSeverity];
  const considered = result.findings.filter((f) => SEVERITY_RANK[f.severity] >= threshold);

  const denyTools = new Set<string>();
  const toolOverrides: Record<string, "deny" | "require_approval"> = {};
  const notes: string[] = [];
  const denyTags = new Set<string>(["skill-scan-blocked"]);

  const targetsByPath = new Map(result.targets.map((t) => [path.resolve(t.path), t]));

  for (const f of considered) {
    const target = targetsByPath.get(path.resolve(f.path));
    if (!target) continue;

    if (target.kind === "mcp_config") {
      for (const name of collectMcpNames(target)) {
        denyTools.add(name);
        toolOverrides[name] = "deny";
      }
      notes.push(
        `MCP ${path.basename(f.path)}:${f.startLine} [${f.ruleId}] → deny servers/tools in that config`
      );
    } else {
      const label = skillLabel(f.path);
      notes.push(`${label} [${f.ruleId}/${f.severity}] ${f.message}`);
      // Skills aren't runtime tools — suggest a tag operators can attach + require_approval default
      denyTags.add("untrusted-skill");
    }
  }

  // De-dupe notes
  const uniqNotes = [...new Set(notes)].slice(0, 40);

  return {
    source: "skill-scan",
    generated_at: new Date().toISOString(),
    summary:
      considered.length === 0
        ? "No findings at threshold — no ToolPause denies suggested."
        : `Suggested denies from ${considered.length} finding(s). Paste policy into ToolPause Rules (merge carefully).`,
    policy: {
      deny_tools: [...denyTools].sort(),
      deny_tags: [...denyTags].sort(),
      tool_overrides: Object.fromEntries(
        Object.entries(toolOverrides).sort(([a], [b]) => a.localeCompare(b))
      ),
      notes: uniqNotes,
    },
    findings_considered: considered.length,
  };
}

export function formatToolPauseEmit(emit: ToolPauseRulesEmit): string {
  return JSON.stringify(emit, null, 2) + "\n";
}
