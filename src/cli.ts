#!/usr/bin/env node
import fs from "node:fs";
import path from "node:path";
import { loadConfigFile, mergeConfig } from "./config.js";
import {
  emitToolPauseRules,
  formatEmitHints,
  formatToolPauseEmit,
} from "./emit-toolpause.js";
import { formatHtml } from "./format/html.js";
import { formatJson } from "./format/json.js";
import { formatSarif } from "./format/sarif.js";
import { formatText } from "./format/text.js";
import { getActiveRules, scanRoots, shouldFail } from "./scan.js";
import type { ScanConfig, Severity } from "./types.js";
import { SEVERITY_RANK } from "./types.js";
import { packageVersion, TOOL_NAME } from "./version.js";

function printHelp(): void {
  process.stdout.write(`${TOOL_NAME} v${packageVersion()} — ToolFence Scan (pre-install security for agent skills & MCP)

Usage:
  ${TOOL_NAME} [path...] [options]
  skill-scan [path...] [options]          # CLI alias

Options:
  --format <text|json|sarif|html>   Output format (default: text)
  --fail-on <critical|high|medium|low|info>   Exit 1 if findings meet severity (default: high)
  --output <file>                   Write report to file
  --quiet                           Suppress summary / emit hints on stderr
  --inventory                       List discovered files only
  --emit-gate-rules                 Emit ToolFence Gate Rules JSON (alias: --emit-toolpause-rules)
  --ignore <pattern>                Skip paths matching pattern (repeatable)
  --config <file>                   Load .toolfence-scan.yml / .json
  --disable-rule <id>               Disable a rule (repeatable)
  --enable-rule <id>                Only run these rules (repeatable)
  --rules-dir <dir>                 Load extra YAML/JSON rule packs
  --baseline <file>                 Ignore findings listed in baseline JSON
  --update-baseline                 Write/refresh baseline from current findings
  --drift <file>                    Compare file hashes to drift snapshot
  --update-drift                    Write/refresh drift snapshot
  --include-global                  Also scan ~/.cursor, ~/.claude, etc.
  --no-gitignore                    Do not honor .gitignore
  --fix                            Print remediation checklist (text)
  -V, --version                     Print version
  -h, --help                        Show help

Exit codes:
  0  clean (or below fail-on threshold)
  1  findings at or above fail-on
  2  scanner error

Examples:
  npx ${TOOL_NAME} .
  npx ${TOOL_NAME} ./skills --format sarif --output results.sarif
  npx ${TOOL_NAME} . --format html --output report.html
  npx ${TOOL_NAME} . --emit-gate-rules --output gate-rules.json
  npx ${TOOL_NAME} . --baseline .toolfence-baseline.json --fail-on high
`);
}

type OutputFormat = "text" | "json" | "sarif" | "html";

interface CliArgs {
  help: boolean;
  version: boolean;
  roots: string[];
  format: OutputFormat;
  failOn: Severity | null;
  output: string | null;
  quiet: boolean;
  inventory: boolean;
  emitToolpause: boolean;
  ignore: string[];
  configPath: string | null;
  disableRules: string[];
  enableRules: string[];
  rulesDir: string | null;
  baselinePath: string | null;
  updateBaseline: boolean;
  driftPath: string | null;
  updateDrift: boolean;
  includeGlobal: boolean;
  respectGitignore: boolean;
  fix: boolean;
}

function parseArgs(argv: string[]): CliArgs {
  const args: CliArgs = {
    help: false,
    version: false,
    roots: [],
    format: "text",
    failOn: null,
    output: null,
    quiet: false,
    inventory: false,
    emitToolpause: false,
    ignore: [],
    configPath: null,
    disableRules: [],
    enableRules: [],
    rulesDir: null,
    baselinePath: null,
    updateBaseline: false,
    driftPath: null,
    updateDrift: false,
    includeGlobal: false,
    respectGitignore: true,
    fix: false,
  };

  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (a === "-h" || a === "--help") {
      args.help = true;
      continue;
    }
    if (a === "-V" || a === "--version") {
      args.version = true;
      continue;
    }
    if (a === "--quiet") {
      args.quiet = true;
      continue;
    }
    if (a === "--inventory") {
      args.inventory = true;
      continue;
    }
    if (a === "--fix") {
      args.fix = true;
      continue;
    }
    if (a === "--include-global") {
      args.includeGlobal = true;
      continue;
    }
    if (a === "--no-gitignore") {
      args.respectGitignore = false;
      continue;
    }
    if (a === "--update-baseline") {
      args.updateBaseline = true;
      continue;
    }
    if (a === "--update-drift") {
      args.updateDrift = true;
      continue;
    }
    if (a === "--emit-toolpause-rules" || a === "--emit-gate-rules") {
      args.emitToolpause = true;
      continue;
    }
    if (a === "--ignore") {
      const v = argv[++i];
      if (!v) throw new Error("--ignore requires a pattern");
      args.ignore.push(v);
      continue;
    }
    if (a === "--config") {
      args.configPath = argv[++i] || null;
      if (!args.configPath) throw new Error("--config requires a path");
      continue;
    }
    if (a === "--disable-rule") {
      const v = argv[++i];
      if (!v) throw new Error("--disable-rule requires an id");
      args.disableRules.push(v);
      continue;
    }
    if (a === "--enable-rule") {
      const v = argv[++i];
      if (!v) throw new Error("--enable-rule requires an id");
      args.enableRules.push(v);
      continue;
    }
    if (a === "--rules-dir") {
      args.rulesDir = argv[++i] || null;
      if (!args.rulesDir) throw new Error("--rules-dir requires a path");
      continue;
    }
    if (a === "--baseline") {
      args.baselinePath = argv[++i] || null;
      if (!args.baselinePath) throw new Error("--baseline requires a path");
      continue;
    }
    if (a === "--drift") {
      args.driftPath = argv[++i] || null;
      if (!args.driftPath) throw new Error("--drift requires a path");
      continue;
    }
    if (a === "--format") {
      const v = argv[++i];
      if (!v || !["text", "json", "sarif", "html"].includes(v)) {
        throw new Error("Invalid --format");
      }
      args.format = v as OutputFormat;
      continue;
    }
    if (a === "--fail-on") {
      const v = argv[++i] as Severity;
      if (!v || !(v in SEVERITY_RANK)) throw new Error("Invalid --fail-on");
      args.failOn = v;
      continue;
    }
    if (a === "--output") {
      args.output = argv[++i] || null;
      if (!args.output) throw new Error("--output requires a path");
      continue;
    }
    if (a.startsWith("-")) throw new Error(`Unknown option: ${a}`);
    args.roots.push(a);
  }

  if (!args.roots.length) args.roots.push(".");
  return args;
}

/** Write report then exit only after stdout drains (avoids 8KB pipe truncation). */
function finish(
  code: number,
  body: string | null,
  output: string | null,
  quiet: boolean,
  label: string
): void {
  if (body != null && output) {
    fs.mkdirSync(path.dirname(path.resolve(output)), { recursive: true });
    fs.writeFileSync(output, body.endsWith("\n") ? body : body + "\n", "utf8");
    if (!quiet) process.stderr.write(`Wrote ${label} → ${output}\n`);
    process.exit(code);
    return;
  }
  if (body != null) {
    const text = body.endsWith("\n") ? body : body + "\n";
    process.stdout.write(text, (err) => {
      process.exit(err ? 2 : code);
    });
    return;
  }
  process.exit(code);
}

function main(): void {
  try {
    const args = parseArgs(process.argv.slice(2));
    if (args.help) {
      printHelp();
      process.exit(0);
    }
    if (args.version) {
      finish(0, packageVersion(), null, true, "version");
      return;
    }

    const fileCfg = loadConfigFile(args.configPath);
    const over: Partial<ScanConfig> = {
      ignore: args.ignore,
      disableRules: args.disableRules.length ? args.disableRules : undefined,
      enableRules: args.enableRules.length ? args.enableRules : undefined,
      includeGlobal: args.includeGlobal || undefined,
      respectGitignore: args.respectGitignore,
      baselinePath: args.baselinePath,
      rulesDir: args.rulesDir,
      updateBaseline: args.updateBaseline,
      failOn: args.failOn || undefined,
    };
    const cfg = mergeConfig(fileCfg, over);
    const failOn: Severity = args.failOn || cfg.failOn || "high";

    const result = scanRoots(args.roots, {
      ...cfg,
      failOn,
      driftPath: args.driftPath,
      updateDrift: args.updateDrift,
    });

    if (args.inventory) {
      const lines = result.targets.map((t) => `${t.kind}\t${t.path}`);
      finish(
        0,
        lines.join("\n") + (lines.length ? "\n" : "") + `# ${result.targets.length} targets`,
        null,
        true,
        "inventory"
      );
      return;
    }

    if (args.emitToolpause) {
      const emit = emitToolPauseRules(result, failOn);
      if (!args.quiet) process.stderr.write(formatEmitHints(emit));
      finish(
        shouldFail(result.findings, failOn) ? 1 : 0,
        formatToolPauseEmit(emit),
        args.output,
        args.quiet,
        "gate-rules"
      );
      return;
    }

    const rules = getActiveRules(cfg);
    let body: string;
    switch (args.format) {
      case "json":
        body = formatJson(result);
        break;
      case "sarif":
        body = formatSarif(result, { cwd: process.cwd(), rules });
        break;
      case "html":
        body = formatHtml(result);
        break;
      default:
        body = formatText(result, { fix: args.fix });
    }

    finish(
      shouldFail(result.findings, failOn) ? 1 : 0,
      body,
      args.output,
      args.quiet,
      args.format
    );
  } catch (err) {
    process.stderr.write(
      `${TOOL_NAME} error: ${err instanceof Error ? err.message : String(err)}\n`
    );
    process.exit(2);
  }
}

main();
