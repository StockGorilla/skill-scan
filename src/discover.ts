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

function classify(filePath: string, baseName: string): TargetKind | null {
  const lower = filePath.replace(/\\/g, "/").toLowerCase();
  if (baseName === "SKILL.md" || lower.includes("/.cursor/skills/")) return "skill";
  if (
    baseName === ".cursorrules" ||
    lower.includes("/.cursor/rules/") ||
    baseName.endsWith(".mdc") && lower.includes("/.cursor/")
  ) {
    return "cursor_rules";
  }
  if (baseName === "AGENTS.md" || baseName === "AGENT.md") return "agents_md";
  if (
    baseName === "mcp.json" ||
    baseName === "claude_desktop_config.json" ||
    lower.endsWith("/.cursor/mcp.json") ||
    (baseName === "settings.json" && lower.includes("mcp"))
  ) {
    return "mcp_config";
  }
  return null;
}

function shouldIgnoreDir(name: string): boolean {
  return IGNORE_DIRS.has(name) || name.startsWith(".");
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
      if (shouldIgnoreDir(ent.name) && ent.name !== ".cursor") continue;
      // Always allow .cursor; skip other dotdirs
      if (ent.name.startsWith(".") && ent.name !== ".cursor") continue;
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
    "mcp.json",
    "claude_desktop_config.json",
    ".vscode/mcp.json",
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

function matchesIgnore(filePath: string, patterns: string[]): boolean {
  if (!patterns.length) return false;
  const norm = filePath.replace(/\\/g, "/");
  for (const raw of patterns) {
    const p = raw.replace(/\\/g, "/");
    // minimal glob: **/foo/** and suffix/prefix *
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
  }
  const filtered = out.filter((t) => !matchesIgnore(t.path, ignore));
  filtered.sort((a, b) => a.path.localeCompare(b.path));
  return filtered;
}
