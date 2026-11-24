import type { ScanResult } from "../types.js";
import { builtinRules } from "../rules/index.js";

const LEVEL: Record<string, string> = {
  critical: "error",
  high: "error",
  medium: "warning",
  low: "note",
  info: "note",
};

export function formatSarif(result: ScanResult): string {
  const rules = builtinRules.map((r) => ({
    id: r.id,
    name: r.title,
    shortDescription: { text: r.title },
    fullDescription: { text: r.description },
    help: { text: r.remediation },
    defaultConfiguration: { level: LEVEL[r.severity] || "warning" },
    properties: { "security-severity": r.severity },
  }));

  const sarif = {
    $schema: "https://json.schemastore.org/sarif-2.1.0.json",
    version: "2.1.0",
    runs: [
      {
        tool: {
          driver: {
            name: "skill-scan",
            informationUri: "https://github.com/StockGorilla/toolpause/tree/main/packages/skill-scan",
            version: "0.1.0",
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
                artifactLocation: { uri: f.path },
                region: {
                  startLine: f.startLine,
                  endLine: f.endLine,
                  snippet: f.snippet ? { text: f.snippet } : undefined,
                },
              },
            },
          ],
        })),
      },
    ],
  };

  return JSON.stringify(sarif, null, 2);
}
