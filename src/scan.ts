import fs from "node:fs";
import path from "node:path";
import { applyBaseline, loadBaseline, writeBaseline } from "./baseline.js";
import { discoverTargets } from "./discover.js";
import { detectDrift, loadDrift, writeDrift } from "./drift.js";
import { builtinRules } from "./rules/index.js";
import { loadRulesFromDir } from "./rules/load.js";
import {
  applyLineSuppressions,
  filterDisabledRules,
  loadSkillScanIgnoreFiles,
} from "./suppress.js";
import type { Finding, Rule, ScanConfig, ScanResult, Severity } from "./types.js";
import { SEVERITY_RANK } from "./types.js";

function readText(filePath: string): string | null {
  try {
    return fs.readFileSync(filePath, "utf8");
  } catch {
    return null;
  }
}

export interface ScanOptions extends ScanConfig {
  driftPath?: string | null;
  updateDrift?: boolean;
}

function selectRules(cfg: ScanOptions): Rule[] {
  const custom = loadRulesFromDir(cfg.rulesDir);
  const merged = [...builtinRules, ...custom];
  // Deduplicate by id (custom overrides builtin)
  const byId = new Map<string, Rule>();
  for (const r of merged) byId.set(r.id, r);
  let rules = [...byId.values()];
  if (cfg.disableRules?.length) {
    const set = new Set(cfg.disableRules);
    rules = rules.filter((r) => !set.has(r.id));
  }
  if (cfg.enableRules?.length) {
    const set = new Set(cfg.enableRules);
    rules = rules.filter((r) => set.has(r.id));
  }
  return rules;
}

export function scanRoots(roots: string[], ignoreOrOpts: string[] | ScanOptions = []): ScanResult {
  const cfg: ScanOptions = Array.isArray(ignoreOrOpts)
    ? { ignore: ignoreOrOpts }
    : ignoreOrOpts;

  const started = Date.now();
  const fileIgnore = [...(cfg.ignore || []), ...loadSkillScanIgnoreFiles(roots)];
  const targets = discoverTargets(roots, {
    ignore: fileIgnore,
    includeGlobal: cfg.includeGlobal,
    respectGitignore: cfg.respectGitignore !== false,
  });

  const rules = selectRules(cfg);
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

    for (const rule of rules) {
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

  // Drift detection (rug-pull)
  if (cfg.driftPath) {
    if (cfg.updateDrift) {
      writeDrift(cfg.driftPath, targets);
    } else {
      const prior = loadDrift(cfg.driftPath);
      findings.push(...detectDrift(targets, prior));
    }
  }

  let filtered = applyLineSuppressions(findings, fileTexts);
  filtered = filterDisabledRules(filtered, undefined, undefined);

  // Baseline
  let baselineSuppressed = 0;
  if (cfg.baselinePath) {
    if (cfg.updateBaseline) {
      writeBaseline(cfg.baselinePath, filtered);
    } else {
      const baseline = loadBaseline(cfg.baselinePath);
      const { active, suppressed } = applyBaseline(filtered, baseline);
      baselineSuppressed = suppressed.length;
      filtered = active;
    }
  }

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
    baselineSuppressed: baselineSuppressed || undefined,
  };
}

export function getActiveRules(cfg: ScanOptions = {}): Rule[] {
  return selectRules(cfg);
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
