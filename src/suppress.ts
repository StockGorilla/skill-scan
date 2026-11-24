import fs from "node:fs";
import path from "node:path";
import type { Finding } from "./types.js";

const LINE_IGNORE =
  /(?:#|\/\/|<!--)\s*skill-scan-ignore(?:\s*-->)?\s*$/i;
const NEXT_LINE_IGNORE =
  /(?:#|\/\/|<!--)\s*skill-scan-ignore-next-line(?:\s*-->)?\s*$/i;

export function loadSkillScanIgnoreFiles(roots: string[]): string[] {
  const patterns: string[] = [];
  for (const root of roots) {
    const abs = path.resolve(root);
    const candidates = [
      path.join(abs, ".skill-scanignore"),
      ...(fs.existsSync(abs) && fs.statSync(abs).isFile()
        ? [path.join(path.dirname(abs), ".skill-scanignore")]
        : []),
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

/** Drop findings on lines marked with skill-scan-ignore / ignore-next-line. */
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
    if (LINE_IGNORE.test(line)) return false;
    if (idx > 0 && NEXT_LINE_IGNORE.test(lines[idx - 1])) return false;
    return true;
  });
}
