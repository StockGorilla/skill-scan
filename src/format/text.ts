import type { ScanResult } from "../types.js";
import { packageVersion, TOOL_NAME } from "../version.js";

export function formatText(result: ScanResult, opts: { fix?: boolean } = {}): string {
  const lines: string[] = [];
  const suppressed =
    result.baselineSuppressed && result.baselineSuppressed > 0
      ? ` · ${result.baselineSuppressed} baselined`
      : "";
  lines.push(
    `${TOOL_NAME} v${packageVersion()} · ${result.targets.length} files · ${result.findings.length} findings${suppressed} · ${result.durationMs}ms`
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

  if (opts.fix) {
    lines.push("");
    lines.push("── Fix checklist ──");
    const seen = new Set<string>();
    for (const f of result.findings) {
      const key = `${f.ruleId}|${f.remediation || ""}`;
      if (seen.has(key)) continue;
      seen.add(key);
      lines.push(`☐ [${f.ruleId}] ${f.remediation || f.message}`);
    }
  }

  lines.push("");
  return lines.join("\n");
}
