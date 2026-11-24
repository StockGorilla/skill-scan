import fs from "node:fs";
import path from "node:path";
import { discoverTargets } from "./discover.js";
import { builtinRules } from "./rules/index.js";
import { applyLineSuppressions, loadSkillScanIgnoreFiles } from "./suppress.js";
import type { Finding, ScanResult, Severity } from "./types.js";
import { SEVERITY_RANK } from "./types.js";

function readText(filePath: string): string | null {
  try {
    return fs.readFileSync(filePath, "utf8");
  } catch {
    return null;
  }
}

export function scanRoots(roots: string[], ignore: string[] = []): ScanResult {
  const started = Date.now();
  const fileIgnore = [...ignore, ...loadSkillScanIgnoreFiles(roots)];
  const targets = discoverTargets(roots, fileIgnore);
  const findings: Finding[] = [];
  const fileTexts = new Map<string, string>();
  let counter = 0;

  for (const target of targets) {
    const text = readText(target.path);
    if (text == null) continue;
    const resolved = path.resolve(target.path);
    fileTexts.set(resolved, text);
    fileTexts.set(target.path, text);
    const lines = text.split(/\r?\n/);
    const ctx = { path: target.path, kind: target.kind, text, lines };

    for (const rule of builtinRules) {
      if (rule.kinds && rule.kinds.length > 0 && !rule.kinds.includes(target.kind)) {
        continue;
      }
      const hits = rule.test(ctx);
      for (const hit of hits) {
        counter += 1;
        findings.push({
          id: `finding-${counter}`,
          ruleId: rule.id,
          severity: rule.severity,
          message: hit.message || rule.title,
          path: resolved,
          startLine: hit.startLine,
          endLine: hit.endLine,
          snippet: hit.snippet,
          remediation: rule.remediation,
        });
      }
    }
  }

  const filtered = applyLineSuppressions(findings, fileTexts);

  filtered.sort((a, b) => {
    const sev = SEVERITY_RANK[b.severity] - SEVERITY_RANK[a.severity];
    if (sev !== 0) return sev;
    return a.path.localeCompare(b.path) || a.startLine - b.startLine;
  });

  return {
    roots: roots.map((r) => path.resolve(r)),
    scannedAt: new Date().toISOString(),
    durationMs: Date.now() - started,
    targets,
    findings: filtered,
  };
}

export function maxSeverity(findings: Finding[]): Severity | null {
  if (!findings.length) return null;
  return findings.reduce(
    (best, f) => (SEVERITY_RANK[f.severity] > SEVERITY_RANK[best] ? f.severity : best),
    findings[0].severity
  );
}

export function shouldFail(findings: Finding[], failOn: Severity): boolean {
  const threshold = SEVERITY_RANK[failOn];
  return findings.some((f) => SEVERITY_RANK[f.severity] >= threshold);
}
