import fs from "node:fs";
import path from "node:path";
import type { Finding } from "./types.js";

const LINE_IGNORE =
  /(?:#|\/\/|<!--)\s*(?:skill-scan-ignore|toolfence-scan-ignore)(?:\s*:\s*([A-Za-z0-9_*,-]+))?(?:\s*-->)?\s*$/i;
const NEXT_LINE_IGNORE =
  /(?:#|\/\/|<!--)\s*(?:skill-scan-ignore-next-line|toolfence-scan-ignore-next-line)(?:\s*:\s*([A-Za-z0-9_*,-]+))?(?:\s*-->)?\s*$/i;

export function loadSkillScanIgnoreFiles(roots: string[]): string[] {
  const patterns: string[] = [];
  for (const root of roots) {
    const abs = path.resolve(root);
    const dir = fs.existsSync(abs) && fs.statSync(abs).isFile() ? path.dirname(abs) : abs;
    const candidates = [
      path.join(dir, ".skill-scanignore"),
      path.join(dir, ".toolfence-scanignore"),
    ];
    for (const file of candidates) {
      if (!fs.existsSync(file) || !fs.statSync(file).isFile()) continue;
      const text = fs.readFileSync(file, "utf8");
      for (const raw of text.split(/\r?\n/)) {
        const line = raw.trim();
        if (!line || line.startsWith("#")) continue;
        patterns.push(line);
      }
    }
  }
  return patterns;
}

function ruleMatch(spec: string | undefined, ruleId: string): boolean {
  if (!spec || spec === "*" || spec.trim() === "") return true;
  const parts = spec.split(",").map((s) => s.trim()).filter(Boolean);
  return parts.includes(ruleId);
}

/** Drop findings on lines marked with skill-scan-ignore / toolfence-scan-ignore. */
export function applyLineSuppressions(
  findings: Finding[],
  fileTexts: Map<string, string>
): Finding[] {
  return findings.filter((f) => {
    const text = fileTexts.get(f.path) ?? fileTexts.get(path.resolve(f.path));
    if (text == null) return true;
    const lines = text.split(/\r?\n/);
    const idx = f.startLine - 1;
    if (idx < 0 || idx >= lines.length) return true;
    const line = lines[idx];
    const same = line.match(LINE_IGNORE);
    if (same && ruleMatch(same[1], f.ruleId)) return false;
    if (idx > 0) {
      const prev = lines[idx - 1].match(NEXT_LINE_IGNORE);
      if (prev && ruleMatch(prev[1], f.ruleId)) return false;
    }
    return true;
  });
}

export function filterDisabledRules(
  findings: Finding[],
  disableRules?: string[],
  enableRules?: string[]
): Finding[] {
  let out = findings;
  if (disableRules?.length) {
    const set = new Set(disableRules);
    out = out.filter((f) => !set.has(f.ruleId));
  }
  if (enableRules?.length) {
    const set = new Set(enableRules);
    out = out.filter((f) => set.has(f.ruleId));
  }
  return out;
}
