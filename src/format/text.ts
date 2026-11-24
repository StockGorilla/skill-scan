import type { ScanResult } from "../types.js";

export function formatText(result: ScanResult): string {
  const lines: string[] = [];
  lines.push(
    `skill-scan · ${result.targets.length} files · ${result.findings.length} findings · ${result.durationMs}ms`
  );
  if (!result.findings.length) {
    lines.push("No findings.");
    return lines.join("\n");
  }
  for (const f of result.findings) {
    lines.push("");
    lines.push(`[${f.severity.toUpperCase()}] ${f.ruleId}`);
    lines.push(`  ${f.path}:${f.startLine}`);
    lines.push(`  ${f.message}`);
    if (f.snippet) lines.push(`  > ${f.snippet}`);
    if (f.remediation) lines.push(`  fix: ${f.remediation}`);
  }
  lines.push("");
  return lines.join("\n");
}
