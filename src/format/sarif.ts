import path from "node:path";
import type { Rule, ScanResult } from "../types.js";
import { TOOL_NAME, TOOL_URI, packageVersion } from "../version.js";

const LEVEL: Record<string, string> = {
  critical: "error",
  high: "error",
  medium: "warning",
  low: "note",
  info: "note",
};

function toUri(filePath: string, cwd: string): string {
  const abs = path.resolve(filePath);
  const rel = path.relative(cwd, abs);
  if (!rel || rel.startsWith("..") || path.isAbsolute(rel)) {
    // Outside cwd — use file:// absolute as last resort (rare for CI)
    return path.posix.normalize(abs.replace(/\\/g, "/"));
  }
  return rel.split(path.sep).join("/");
}

export function formatSarif(
  result: ScanResult,
  opts: { cwd?: string; rules?: Rule[] } = {}
): string {
  const cwd = opts.cwd || process.cwd();
  const ruleList = opts.rules || [];
  const byId = new Map(ruleList.map((r) => [r.id, r]));

  // Prefer rules that appear in findings + provided catalog
  const usedIds = new Set(result.findings.map((f) => f.ruleId));
  for (const r of ruleList) usedIds.add(r.id);

  const rules = [...usedIds].map((id) => {
    const r = byId.get(id);
    return {
      id,
      name: r?.title || id,
      shortDescription: { text: r?.title || id },
      fullDescription: { text: r?.description || r?.title || id },
      help: { text: r?.remediation || "Review and remediate this finding." },
      helpUri: `${TOOL_URI}#${id}`,
      defaultConfiguration: { level: LEVEL[r?.severity || "medium"] || "warning" },
      properties: {
        tags: ["security", "toolfence"],
        "security-severity":
          r?.severity === "critical"
            ? "9.0"
            : r?.severity === "high"
              ? "7.0"
              : r?.severity === "medium"
                ? "5.0"
                : r?.severity === "low"
                  ? "3.0"
                  : "1.0",
      },
    };
  });

  const sarif = {
    $schema: "https://json.schemastore.org/sarif-2.1.0.json",
    version: "2.1.0",
    runs: [
      {
        tool: {
          driver: {
            name: TOOL_NAME,
            informationUri: TOOL_URI,
            version: packageVersion(),
            rules,
          },
        },
        results: result.findings.map((f) => ({
          ruleId: f.ruleId,
          level: LEVEL[f.severity] || "warning",
          message: { text: f.message },
          locations: [
            {
              physicalLocation: {
                artifactLocation: {
                  uri: toUri(f.path, cwd),
                  uriBaseId: "%SRCROOT%",
                },
                region: {
                  startLine: f.startLine,
                  endLine: f.endLine,
                  snippet: f.snippet ? { text: f.snippet } : undefined,
                },
              },
            },
          ],
          properties: f.remediation ? { remediation: f.remediation } : undefined,
        })),
        originalUriBaseIds: {
          "%SRCROOT%": {
            uri: path.posix.normalize(path.resolve(cwd).replace(/\\/g, "/") + "/"),
          },
        },
      },
    ],
  };

  return JSON.stringify(sarif, null, 2);
}
