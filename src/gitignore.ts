import fs from "node:fs";
import path from "node:path";

/** Load .gitignore patterns from root (best-effort, not full gitignore semantics). */
export function loadGitignorePatterns(root: string): string[] {
  const file = path.join(root, ".gitignore");
  if (!fs.existsSync(file)) return [];
  const out: string[] = [];
  for (const raw of fs.readFileSync(file, "utf8").split(/\r?\n/)) {
    const line = raw.trim();
    if (!line || line.startsWith("#") || line.startsWith("!")) continue;
    out.push(line);
  }
  return out;
}

export function matchesGitignore(filePath: string, root: string, patterns: string[]): boolean {
  if (!patterns.length) return false;
  const rel = path.relative(root, filePath).replace(/\\/g, "/");
  if (rel.startsWith("..")) return false;
  for (const raw of patterns) {
    let p = raw.replace(/\\/g, "/").replace(/^\//, "");
    if (p.endsWith("/")) p = p.slice(0, -1);
    if (p.includes("**")) {
      const mid = p.replace(/\*\*/g, "").replace(/\/+/g, "/").replace(/^\//, "").replace(/\/$/, "");
      if (mid && (rel === mid || rel.startsWith(mid + "/") || rel.includes("/" + mid + "/"))) {
        return true;
      }
      continue;
    }
    if (p.startsWith("*.")) {
      if (rel.endsWith(p.slice(1))) return true;
      continue;
    }
    if (rel === p || rel.startsWith(p + "/") || rel.endsWith("/" + p) || rel.includes("/" + p + "/")) {
      return true;
    }
  }
  return false;
}
