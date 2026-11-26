import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import type { DriftFile, Finding, ScanTarget } from "./types.js";

export function sha256File(filePath: string): string | null {
  try {
    const buf = fs.readFileSync(filePath);
    return crypto.createHash("sha256").update(buf).digest("hex");
  } catch {
    return null;
  }
}

export function loadDrift(filePath: string | null | undefined): DriftFile | null {
  if (!filePath) return null;
  const abs = path.resolve(filePath);
  if (!fs.existsSync(abs)) return null;
  try {
    const raw = JSON.parse(fs.readFileSync(abs, "utf8")) as DriftFile;
    if (!raw || raw.version !== 1 || typeof raw.entries !== "object") return null;
    return raw;
  } catch {
    return null;
  }
}

export function writeDrift(filePath: string, targets: ScanTarget[]): DriftFile {
  const abs = path.resolve(filePath);
  const file: DriftFile = {
    version: 1,
    updatedAt: new Date().toISOString(),
    entries: {},
  };
  for (const t of targets) {
    const hash = sha256File(t.path);
    if (!hash) continue;
    const rel = path.relative(process.cwd(), t.path).split(path.sep).join("/") || t.path;
    file.entries[rel] = { path: rel, kind: t.kind, sha256: hash };
  }
  fs.mkdirSync(path.dirname(abs), { recursive: true });
  fs.writeFileSync(abs, JSON.stringify(file, null, 2) + "\n", "utf8");
  return file;
}

/** Compare current targets to a prior drift snapshot; emit findings for changed/new paths. */
export function detectDrift(targets: ScanTarget[], prior: DriftFile | null): Finding[] {
  if (!prior) return [];
  const findings: Finding[] = [];
  let n = 0;
  const seen = new Set<string>();

  for (const t of targets) {
    const hash = sha256File(t.path);
    if (!hash) continue;
    const rel = path.relative(process.cwd(), t.path).split(path.sep).join("/") || t.path;
    seen.add(rel);
    const prev = prior.entries[rel];
    if (!prev) {
      n += 1;
      findings.push({
        id: `drift-new-${n}`,
        ruleId: "rug-pull-drift",
        severity: "medium",
        message: `New agent asset since drift baseline: ${rel}`,
        path: path.resolve(t.path),
        startLine: 1,
        endLine: 1,
        remediation:
          "Review the new skill/MCP/config before trusting it. Update the drift baseline with --update-drift after review.",
      });
      continue;
    }
    if (prev.sha256 !== hash) {
      n += 1;
      findings.push({
        id: `drift-changed-${n}`,
        ruleId: "rug-pull-drift",
        severity: "high",
        message: `Content changed since drift baseline (possible rug-pull): ${rel}`,
        path: path.resolve(t.path),
        startLine: 1,
        endLine: 1,
        snippet: `was ${prev.sha256.slice(0, 12)}… now ${hash.slice(0, 12)}…`,
        remediation:
          "Diff this file against the last trusted version. Update --update-drift only after confirming the change is intentional.",
      });
    }
  }

  for (const [rel] of Object.entries(prior.entries)) {
    if (seen.has(rel)) continue;
    n += 1;
    findings.push({
      id: `drift-removed-${n}`,
      ruleId: "rug-pull-drift",
      severity: "low",
      message: `Previously tracked agent asset missing: ${rel}`,
      path: path.resolve(rel),
      startLine: 1,
      endLine: 1,
      remediation: "Confirm intentional removal, then refresh the drift baseline.",
    });
  }

  return findings;
}
