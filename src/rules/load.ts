import fs from "node:fs";
import path from "node:path";
import type { FindingHit, Rule, RuleContext, Severity, TargetKind } from "../types.js";
import { SEVERITY_RANK } from "../types.js";

function lineOf(text: string, index: number): number {
  return text.slice(0, index).split(/\r?\n/).length;
}

function hitsFromRegex(ctx: RuleContext, re: RegExp, message?: string): FindingHit[] {
  const hits: FindingHit[] = [];
  const flags = re.flags.includes("g") ? re.flags : `${re.flags}g`;
  const global = new RegExp(re.source, flags);
  let m: RegExpExecArray | null;
  while ((m = global.exec(ctx.text)) !== null) {
    const startLine = lineOf(ctx.text, m.index);
    const endLine = lineOf(ctx.text, m.index + Math.max(m[0].length - 1, 0));
    hits.push({
      startLine,
      endLine,
      message,
      snippet: ctx.lines[startLine - 1]?.trim().slice(0, 160),
    });
    if (m[0].length === 0) global.lastIndex += 1;
  }
  return hits;
}

/** Minimal YAML for rule packs: id/title/severity/pattern/message/kinds. */
function parseRuleYaml(text: string): Record<string, unknown>[] {
  const docs: Record<string, unknown>[] = [];
  let cur: Record<string, unknown> | null = null;
  const flush = () => {
    if (cur && cur.id) docs.push(cur);
    cur = null;
  };
  for (const raw of text.split(/\r?\n/)) {
    const line = raw.replace(/#.*$/, "");
    if (!line.trim()) continue;
    if (/^\s*-\s+id\s*:/.test(line) || (/^\s*-\s*$/.test(line.trim()) === false && /^\s*-\s+\w/.test(line))) {
      const idInline = line.match(/^\s*-\s+id\s*:\s*(.+)$/);
      flush();
      cur = {};
      if (idInline) {
        cur.id = idInline[1].trim().replace(/^["']|["']$/g, "");
      }
      continue;
    }
    if (/^\s*-\s*$/.test(line)) {
      flush();
      cur = {};
      continue;
    }
    const m = line.match(/^\s*([A-Za-z0-9_-]+)\s*:\s*(.*)$/);
    if (!m) continue;
    if (!cur) cur = {};
    const key = m[1];
    let val = m[2].trim();
    if (val.startsWith("[") && val.endsWith("]")) {
      cur[key] = val
        .slice(1, -1)
        .split(",")
        .map((s) => s.trim().replace(/^["']|["']$/g, ""))
        .filter(Boolean);
      continue;
    }
    cur[key] = val.replace(/^["']|["']$/g, "");
  }
  flush();
  return docs;
}

function toRule(raw: Record<string, unknown>): Rule | null {
  const id = String(raw.id || "").trim();
  if (!id) return null;
  const pattern = String(raw.pattern || raw.regex || "").trim();
  if (!pattern) return null;
  let flags = String(raw.flags || "i");
  if (!flags.includes("g")) flags += "g";
  let re: RegExp;
  try {
    re = new RegExp(pattern, flags);
  } catch {
    return null;
  }
  const sevRaw = String(raw.severity || "medium").toLowerCase();
  const severity: Severity = sevRaw in SEVERITY_RANK ? (sevRaw as Severity) : "medium";
  const kinds = Array.isArray(raw.kinds)
    ? (raw.kinds as string[]).map(String) as TargetKind[]
    : typeof raw.kinds === "string" && raw.kinds
      ? [raw.kinds as TargetKind]
      : undefined;
  const message = String(raw.message || raw.title || id);
  return {
    id,
    title: String(raw.title || id),
    severity,
    description: String(raw.description || message),
    remediation: String(raw.remediation || "Review and remediate this finding."),
    kinds: kinds?.length ? kinds : undefined,
    test(ctx: RuleContext) {
      return hitsFromRegex(ctx, re, message);
    },
  };
}

export function loadRulesFromDir(dir: string | null | undefined): Rule[] {
  if (!dir) return [];
  const abs = path.resolve(dir);
  if (!fs.existsSync(abs) || !fs.statSync(abs).isDirectory()) return [];
  const out: Rule[] = [];
  let entries: string[];
  try {
    entries = fs.readdirSync(abs);
  } catch {
    return [];
  }
  for (const name of entries) {
    if (!/\.(ya?ml|json)$/i.test(name)) continue;
    const full = path.join(abs, name);
    try {
      const text = fs.readFileSync(full, "utf8");
      const docs = name.endsWith(".json")
        ? (JSON.parse(text) as Record<string, unknown>[] | { rules: Record<string, unknown>[] })
        : parseRuleYaml(text);
      const list = Array.isArray(docs)
        ? docs
        : Array.isArray((docs as { rules?: unknown }).rules)
          ? (docs as { rules: Record<string, unknown>[] }).rules
          : [];
      for (const raw of list) {
        const rule = toRule(raw);
        if (rule) out.push(rule);
      }
    } catch {
      /* skip bad pack */
    }
  }
  return out;
}
