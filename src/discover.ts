import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { loadGitignorePatterns, matchesGitignore } from "./gitignore.js";
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
]);

const ALLOWED_DOTDIRS = new Set([
  ".cursor",
  ".github",
  ".claude",
  ".agents",
  ".windsurf",
  ".continue",
  ".vscode",
  ".codex",
  ".gemini",
  ".cline",
]);

const SCRIPT_EXTS = new Set([".sh", ".bash", ".zsh", ".ps1", ".py", ".js", ".mjs", ".cjs", ".ts"]);

export interface DiscoverOptions {
  ignore?: string[];
  includeGlobal?: boolean;
  respectGitignore?: boolean;
}

function classify(filePath: string, baseName: string): TargetKind | null {
  const lower = filePath.replace(/\\/g, "/").toLowerCase();
  const baseLower = baseName.toLowerCase();
  const ext = path.extname(baseName).toLowerCase();

  if (
    baseName === "SKILL.md" ||
    baseLower === "skill.md" ||
    baseLower.endsWith(".skill.md") ||
    (baseLower.endsWith(".md") &&
      /(?:^|\/)(?:skill|skills|skillset|skillsets)\//.test(lower)) ||
    lower.includes("/.cursor/skills/") ||
    lower.includes("/.github/skills/") ||
    lower.includes("/.claude/skills/") ||
    lower.includes("/.agents/skills/") ||
    lower.includes("/.windsurf/skills/")
  ) {
    return "skill";
  }

  if (
    baseName === "copilot-instructions.md" ||
    lower.endsWith(".instructions.md") ||
    lower.includes("/.github/instructions/")
  ) {
    return "copilot_instructions";
  }

  if (lower.endsWith(".prompt.md") || lower.includes("/.github/prompts/")) {
    return "prompt";
  }

  if (lower.includes("/.github/agents/") && baseName.endsWith(".md")) {
    return "copilot_agent";
  }

  if (
    baseName === ".cursorrules" ||
    lower.includes("/.cursor/rules/") ||
    (baseName.endsWith(".mdc") && lower.includes("/.cursor/")) ||
    lower.includes("/.windsurf/rules/") ||
    lower.includes("/.continue/rules/") ||
    lower.includes("/.cline/rules/")
  ) {
    return "cursor_rules";
  }

  if (
    baseName === "AGENTS.md" ||
    baseName === "AGENT.md" ||
    baseName === "CLAUDE.md" ||
    baseName === "GEMINI.md" ||
    baseName === "CODEX.md"
  ) {
    return "agents_md";
  }

  if (
    baseName === "mcp.json" ||
    baseName === "claude_desktop_config.json" ||
    lower.endsWith("/.cursor/mcp.json") ||
    lower.endsWith("/.vscode/mcp.json") ||
    lower.endsWith("/.github/mcp.json") ||
    lower.endsWith("/.windsurf/mcp.json") ||
    lower.endsWith("/.gemini/settings.json") ||
    (baseName === "settings.json" && (lower.includes("mcp") || lower.includes("claude") || lower.includes("gemini")))
  ) {
    return "mcp_config";
  }

  if (
    SCRIPT_EXTS.has(ext) &&
    (lower.includes("/skills/") ||
      lower.includes("/.cursor/") ||
      lower.includes("/.claude/") ||
      lower.includes("/.agents/") ||
      lower.includes("/.github/skills/") ||
      lower.includes("/.windsurf/"))
  ) {
    return "script";
  }

  return null;
}

function looksLikeMcpConfig(text: string): boolean {
  return /"mcpServers"\s*:/.test(text) || /"servers"\s*:\s*\{/.test(text);
}

function shouldIgnoreDir(name: string): boolean {
  return IGNORE_DIRS.has(name);
}

function walk(
  dir: string,
  out: ScanTarget[],
  root: string,
  gitignore: string[],
  respectGitignore: boolean
): void {
  let entries: fs.Dirent[];
  try {
    entries = fs.readdirSync(dir, { withFileTypes: true });
  } catch {
    return;
  }
  for (const ent of entries) {
    const full = path.join(dir, ent.name);
    if (respectGitignore && matchesGitignore(full, root, gitignore)) continue;
    if (ent.isDirectory()) {
      if (shouldIgnoreDir(ent.name)) continue;
      if (ent.name.startsWith(".") && !ALLOWED_DOTDIRS.has(ent.name)) continue;
      walk(full, out, root, gitignore, respectGitignore);
      continue;
    }
    if (!ent.isFile()) continue;
    let kind = classify(full, ent.name);
    if (!kind && ent.name.endsWith(".json")) {
      try {
        const text = fs.readFileSync(full, "utf8");
        if (looksLikeMcpConfig(text)) kind = "mcp_config";
      } catch {
        /* ignore */
      }
    }
    if (!kind) continue;
    out.push({ path: full, kind });
  }
}

function addKnownPaths(root: string, out: ScanTarget[]): void {
  const candidates: Array<{ rel: string; kind: TargetKind }> = [
    { rel: ".cursor/mcp.json", kind: "mcp_config" },
    { rel: ".vscode/mcp.json", kind: "mcp_config" },
    { rel: ".github/mcp.json", kind: "mcp_config" },
    { rel: ".windsurf/mcp.json", kind: "mcp_config" },
    { rel: "mcp.json", kind: "mcp_config" },
    { rel: "claude_desktop_config.json", kind: "mcp_config" },
    { rel: ".gemini/settings.json", kind: "mcp_config" },
    { rel: ".github/copilot-instructions.md", kind: "copilot_instructions" },
    { rel: "AGENTS.md", kind: "agents_md" },
    { rel: "CLAUDE.md", kind: "agents_md" },
    { rel: "GEMINI.md", kind: "agents_md" },
    { rel: "CODEX.md", kind: "agents_md" },
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

function addGlobalRoots(out: ScanTarget[], respectGitignore: boolean): void {
  const home = os.homedir();
  const globals = [
    path.join(home, ".cursor"),
    path.join(home, ".claude"),
    path.join(home, ".agents"),
    path.join(home, ".copilot"),
    path.join(home, ".windsurf"),
    path.join(home, ".continue"),
    path.join(home, ".gemini"),
    path.join(home, ".codex"),
    path.join(home, "Library", "Application Support", "Claude"),
    path.join(home, "Library", "Application Support", "Cursor"),
  ];
  for (const g of globals) {
    if (!fs.existsSync(g)) continue;
    const gitignore = respectGitignore ? loadGitignorePatterns(g) : [];
    walk(g, out, g, gitignore, respectGitignore);
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

export function discoverTargets(roots: string[], opts: DiscoverOptions | string[] = {}): ScanTarget[] {
  // Back-compat: discoverTargets(roots, ignore[])
  const options: DiscoverOptions = Array.isArray(opts) ? { ignore: opts } : opts;
  const ignore = options.ignore || [];
  const respectGitignore = options.respectGitignore !== false;
  const out: ScanTarget[] = [];

  for (const root of roots) {
    const abs = path.resolve(root);
    if (!fs.existsSync(abs)) continue;
    const st = fs.statSync(abs);
    if (st.isFile()) {
      if (matchesIgnore(abs, ignore)) continue;
      let kind = classify(abs, path.basename(abs));
      if (!kind && abs.endsWith(".json")) {
        try {
          if (looksLikeMcpConfig(fs.readFileSync(abs, "utf8"))) kind = "mcp_config";
        } catch {
          /* ignore */
        }
      }
      out.push({ path: abs, kind: kind ?? "other" });
      continue;
    }
    const gitignore = respectGitignore ? loadGitignorePatterns(abs) : [];
    walk(abs, out, abs, gitignore, respectGitignore);
    addKnownPaths(abs, out);
  }

  if (options.includeGlobal) {
    addGlobalRoots(out, respectGitignore);
  }

  const filtered = out.filter((t) => !matchesIgnore(t.path, ignore));
  const seen = new Set<string>();
  const deduped: ScanTarget[] = [];
  for (const t of filtered) {
    const k = path.resolve(t.path);
    if (seen.has(k)) continue;
    seen.add(k);
    deduped.push(t);
  }
  deduped.sort((a, b) => a.path.localeCompare(b.path));
  return deduped;
}
