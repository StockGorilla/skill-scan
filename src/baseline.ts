import fs from "node:fs";
import path from "node:path";
import type { BaselineFile, Finding } from "./types.js";
import { findingFingerprint } from "./types.js";

export function loadBaseline(filePath: string | null | undefined): BaselineFile | null {
  if (!filePath) return null;
  const abs = path.resolve(filePath);
  if (!fs.existsSync(abs)) return null;
  try {
    const raw = JSON.parse(fs.readFileSync(abs, "utf8")) as BaselineFile;
    if (!raw || raw.version !== 1 || typeof raw.findings !== "object") return null;
    return raw;
  } catch {
    return null;
  }
}

export function applyBaseline(
  findings: Finding[],
  baseline: BaselineFile | null
): { active: Finding[]; suppressed: Finding[] } {
  if (!baseline) return { active: findings, suppressed: [] };
  const active: Finding[] = [];
  const suppressed: Finding[] = [];
  for (const f of findings) {
    const fp = findingFingerprint({
      ruleId: f.ruleId,
      path: path.relative(process.cwd(), f.path).split(path.sep).join("/") || f.path,
      startLine: f.startLine,
      message: f.message,
    });
    // Also try absolute/path variants for older baselines
    const fpAbs = findingFingerprint(f);
    if (baseline.findings[fp] || baseline.findings[fpAbs]) {
      suppressed.push(f);
    } else {
      active.push(f);
    }
  }
  return { active, suppressed };
}

export function writeBaseline(filePath: string, findings: Finding[]): BaselineFile {
  const abs = path.resolve(filePath);
  const file: BaselineFile = {
    version: 1,
    updatedAt: new Date().toISOString(),
    findings: {},
  };
  for (const f of findings) {
    const rel = path.relative(process.cwd(), f.path).split(path.sep).join("/") || f.path;
    const fp = findingFingerprint({
      ruleId: f.ruleId,
      path: rel,
      startLine: f.startLine,
      message: f.message,
    });
    file.findings[fp] = { ruleId: f.ruleId, path: rel, message: f.message };
  }
  fs.mkdirSync(path.dirname(abs), { recursive: true });
  fs.writeFileSync(abs, JSON.stringify(file, null, 2) + "\n", "utf8");
  return file;
}
