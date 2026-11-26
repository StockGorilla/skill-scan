import fs from "node:fs";
import path from "node:path";
import type { ScanConfig, Severity } from "./types.js";
import { SEVERITY_RANK } from "./types.js";

const CONFIG_NAMES = [".toolfence-scan.yml", ".toolfence-scan.yaml", ".toolfence-scan.json"];

/** Minimal YAML subset: key: value, key: [a, b], nested not supported. */
function parseSimpleYaml(text: string): Record<string, unknown> {
  const out: Record<string, unknown> = {};
  const lines = text.split(/\r?\n/);
  let listKey: string | null = null;
  let list: string[] = [];
  const flush = () => {
    if (listKey) {
      out[listKey] = list;
      listKey = null;
      list = [];
    }
  };
  for (const raw of lines) {
    const line = raw.replace(/#.*$/, "").trimEnd();
    if (!line.trim()) continue;
    const listItem = line.match(/^\s*-\s+(.+)$/);
    if (listItem && listKey) {
      list.push(listItem[1].replace(/^["']|["']$/g, "").trim());
      continue;
    }
    flush();
    const m = line.match(/^([A-Za-z0-9_-]+)\s*:\s*(.*)$/);
    if (!m) continue;
    const key = m[1];
    const val = m[2].trim();
    if (val === "" || val === "|" || val === ">") {
      listKey = key;
      list = [];
      continue;
    }
    if (val.startsWith("[") && val.endsWith("]")) {
      out[key] = val
        .slice(1, -1)
        .split(",")
        .map((s) => s.trim().replace(/^["']|["']$/g, ""))
        .filter(Boolean);
      continue;
    }
    out[key] = val.replace(/^["']|["']$/g, "");
  }
  flush();
  return out;
}

function asStringList(v: unknown): string[] | undefined {
  if (Array.isArray(v)) return v.map(String);
  if (typeof v === "string" && v.trim()) return [v.trim()];
  return undefined;
}

function normalize(raw: Record<string, unknown>): ScanConfig {
  const cfg: ScanConfig = {};
  const failOn = raw.failOn ?? raw["fail-on"] ?? raw.fail_on;
  if (typeof failOn === "string" && failOn in SEVERITY_RANK) {
    cfg.failOn = failOn as Severity;
  }
  cfg.ignore = asStringList(raw.ignore);
  cfg.disableRules = asStringList(raw.disableRules ?? raw["disable-rules"] ?? raw.disable_rules);
  cfg.enableRules = asStringList(raw.enableRules ?? raw["enable-rules"] ?? raw.enable_rules);
  if (raw.includeGlobal === true || raw.includeGlobal === "true" || raw["include-global"] === true) {
    cfg.includeGlobal = true;
  }
  if (raw.respectGitignore === false || raw["respect-gitignore"] === false) {
    cfg.respectGitignore = false;
  } else {
    cfg.respectGitignore = true;
  }
  const baseline = raw.baseline ?? raw.baselinePath ?? raw["baseline-path"];
  if (typeof baseline === "string") cfg.baselinePath = baseline;
  const rulesDir = raw.rulesDir ?? raw["rules-dir"];
  if (typeof rulesDir === "string") cfg.rulesDir = rulesDir;
  return cfg;
}

export function loadConfigFile(explicit?: string | null, cwd = process.cwd()): ScanConfig {
  const candidates = explicit
    ? [path.resolve(cwd, explicit)]
    : CONFIG_NAMES.map((n) => path.resolve(cwd, n));
  for (const file of candidates) {
    if (!fs.existsSync(file) || !fs.statSync(file).isFile()) continue;
    const text = fs.readFileSync(file, "utf8");
    const raw =
      file.endsWith(".json") ? (JSON.parse(text) as Record<string, unknown>) : parseSimpleYaml(text);
    return normalize(raw);
  }
  return { respectGitignore: true };
}

export function mergeConfig(base: ScanConfig, over: Partial<ScanConfig>): ScanConfig {
  return {
    failOn: over.failOn ?? base.failOn,
    ignore: [...(base.ignore || []), ...(over.ignore || [])],
    disableRules: over.disableRules ?? base.disableRules,
    enableRules: over.enableRules ?? base.enableRules,
    includeGlobal: over.includeGlobal ?? base.includeGlobal,
    respectGitignore: over.respectGitignore ?? base.respectGitignore,
    baselinePath: over.baselinePath !== undefined ? over.baselinePath : base.baselinePath,
    rulesDir: over.rulesDir !== undefined ? over.rulesDir : base.rulesDir,
    updateBaseline: over.updateBaseline ?? base.updateBaseline,
  };
}
