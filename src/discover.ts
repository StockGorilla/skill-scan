import fs from "node:fs";
import path from "node:path";
import type { ScanTarget, TargetKind } from "./types.js";

const IGNORE_DIRS = new Set([
  "node_modules",
  ".git",
  "dist",
  "build",
  ".next",
  "coverage",
  "__pycache__",
  ".venv",
  "venv",
  "marketing",
]);

/** Dotdirs we deliberately walk (agent / IDE instruction roots). */
const ALLOWED_DOTDIRS = new Set([".cursor", ".github", ".claude", ".agents"]);

function classify(filePath: string, baseName: string): TargetKind | null {
  const lower = filePath.replace(/\\/g, "/").toLowerCase();

  // Skills (Cursor, Claude, Copilot, agents)
  const baseLower = baseName.toLowerCase();
  if (
    baseName === "SKILL.md" ||
    baseLower === "skill.md" ||
    baseLower.endsWith(".skill.md") ||
    (baseLower.endsWith(".md") &&
      /(?:^|\/)(?:skill|skills|skillset|skillsets)\//.test(lower)) ||
    lower.includes("/.cursor/skills/") ||
    lower.includes("/.github/skills/") ||
    lower.includes("/.claude/skills/") ||
    lower.includes("/.agents/skills/")
  ) {
    return "skill";
  }

  // GitHub Copilot custom instructions + path-specific
  if (
    baseName === "copilot-instructions.md" ||
    lower.endsWith(".instructions.md") ||
    lower.includes("/.github/instructions/")
  ) {
    return "copilot_instructions";
  }

  // Copilot / VS Code prompt files
  if (lower.endsWith(".prompt.md") || lower.includes("/.github/prompts/")) {
    return "prompt";
  }

  // Copilot custom agents
  if (lower.includes("/.github/agents/") && baseName.endsWith(".md")) {
    return "copilot_agent";
  }

  // Cursor rules
  if (
    baseName === ".cursorrules" ||
    lower.includes("/.cursor/rules/") ||
    (baseName.endsWith(".mdc") && lower.includes("/.cursor/"))
  ) {
    return "cursor_rules";
  }

  // Cross-agent instruction files
  if (
    baseName === "AGENTS.md" ||
    baseName === "AGENT.md" ||
    baseName === "CLAUDE.md" ||
    baseName === "GEMINI.md"
  ) {
    return "agents_md";
  }

  // MCP configs (Cursor, VS Code, Claude Desktop, Copilot-adjacent)
  if (
    baseName === "mcp.json" ||
    baseName === "claude_desktop_config.json" ||
    lower.endsWith("/.cursor/mcp.json") ||
    lower.endsWith("/.vscode/mcp.json") ||
    lower.endsWith("/.github/mcp.json") ||
    (baseName === "settings.json" && lower.includes("mcp"))
  ) {
    return "mcp_config";
  }

  return null;
}

function shouldIgnoreDir(name: string): boolean {
  return IGNORE_DIRS.has(name);
}

function walk(dir: string, out: ScanTarget[], root: string): void {
  let entries: fs.Dirent[];
  try {
    entries = fs.readdirSync(dir, { withFileTypes: true });
  } catch {
    return;
  }
  for (const ent of entries) {
    const full = path.join(dir, ent.name);
    if (ent.isDirectory()) {
      if (shouldIgnoreDir(ent.name)) continue;
      if (ent.name.startsWith(".") && !ALLOWED_DOTDIRS.has(ent.name)) continue;
      walk(full, out, root);
      continue;
    }
    if (!ent.isFile()) continue;
    const kind = classify(full, ent.name);
    if (!kind) continue;
    out.push({ path: full, kind });
  }
}

/** Also pick up MCP-ish JSON at known relative paths even if name varies. */
function addKnownMcpPaths(root: string, out: ScanTarget[]): void {
  const candidates = [
    ".cursor/mcp.json",
    ".vscode/mcp.json",
    ".github/mcp.json",
    "mcp.json",
    "claude_desktop_config.json",
  ];
  const seen = new Set(out.map((t) => path.resolve(t.path)));
  for (const rel of candidates) {
    const full = path.join(root, rel);
    if (!fs.existsSync(full) || !fs.statSync(full).isFile()) continue;
    const resolved = path.resolve(full);
    if (seen.has(resolved)) continue;
    out.push({ path: full, kind: "mcp_config" });
    seen.add(resolved);
  }
}

/** Known Copilot instruction files that might sit outside walk edge cases. */
function addKnownCopilotPaths(root: string, out: ScanTarget[]): void {
  const candidates: Array<{ rel: string; kind: TargetKind }> = [
    { rel: ".github/copilot-instructions.md", kind: "copilot_instructions" },
  ];
  const seen = new Set(out.map((t) => path.resolve(t.path)));
  for (const { rel, kind } of candidates) {
    const full = path.join(root, rel);
    if (!fs.existsSync(full) || !fs.statSync(full).isFile()) continue;
    const resolved = path.resolve(full);
    if (seen.has(resolved)) continue;
    out.push({ path: full, kind });
    seen.add(resolved);
  }
}

function matchesIgnore(filePath: string, patterns: string[]): boolean {
  if (!patterns.length) return false;
  const norm = filePath.replace(/\\/g, "/");
  for (const raw of patterns) {
    const p = raw.replace(/\\/g, "/");
    if (p.startsWith("**/") && p.endsWith("/**")) {
      const mid = p.slice(3, -3);
      if (norm.includes(`/${mid}/`) || norm.includes(`${mid}/`)) return true;
    } else if (p.startsWith("**/")) {
      const suf = p.slice(3);
      if (norm.endsWith(suf) || norm.includes(`/${suf}`)) return true;
    } else if (norm.includes(p)) {
      return true;
    }
  }
  return false;
}

export function discoverTargets(roots: string[], ignore: string[] = []): ScanTarget[] {
  const out: ScanTarget[] = [];
  for (const root of roots) {
    const abs = path.resolve(root);
    if (!fs.existsSync(abs)) continue;
    const st = fs.statSync(abs);
    if (st.isFile()) {
      if (matchesIgnore(abs, ignore)) continue;
      const kind = classify(abs, path.basename(abs)) ?? "other";
      out.push({ path: abs, kind });
      continue;
    }
    walk(abs, out, abs);
    addKnownMcpPaths(abs, out);
    addKnownCopilotPaths(abs, out);
  }
  const filtered = out.filter((t) => !matchesIgnore(t.path, ignore));
  filtered.sort((a, b) => a.path.localeCompare(b.path));
  return filtered;
}
