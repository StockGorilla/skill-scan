#!/usr/bin/env node
import fs from "node:fs";
import path from "node:path";
import { emitToolPauseRules, formatToolPauseEmit } from "./emit-toolpause.js";
import { formatHtml } from "./format/html.js";
import { formatJson } from "./format/json.js";
import { formatSarif } from "./format/sarif.js";
import { formatText } from "./format/text.js";
import { scanRoots, shouldFail } from "./scan.js";
import type { Severity } from "./types.js";
import { SEVERITY_RANK } from "./types.js";

function printHelp(): void {
  process.stdout.write(`skill-scan — pre-install security for agent skills & MCP

Usage:
  skill-scan [path...] [options]

Options:
  --format <text|json|sarif|html>   Output format (default: text)
  --fail-on <critical|high|medium|low|info>   Exit 1 if findings meet severity (default: high)
  --output <file>                   Write report to file
  --quiet                           Suppress summary on stderr when writing files
  --inventory                       List discovered files only
  --emit-toolpause-rules            Emit ToolPause Rules JSON fragment (stdout or --output)
  --ignore <pattern>                Skip paths matching pattern (repeatable)
  -h, --help                        Show help

Exit codes:
  0  clean (or below fail-on threshold)
  1  findings at or above fail-on
  2  scanner error

Examples:
  npx skill-scan .
  npx skill-scan ./skills --format sarif --output results.sarif
  npx skill-scan . --fail-on critical
  npx skill-scan . --emit-toolpause-rules --output toolpause-rules.json
`);
}

type OutputFormat = "text" | "json" | "sarif" | "html";

type CliArgs =
  | { help: true }
  | {
      help: false;
      roots: string[];
      format: OutputFormat;
      failOn: Severity;
      output: string | null;
      quiet: boolean;
      inventory: boolean;
      emitToolpause: boolean;
      ignore: string[];
    };

function parseArgs(argv: string[]): CliArgs {
  const roots: string[] = [];
  let format: OutputFormat = "text";
  let failOn: Severity = "high";
  let output: string | null = null;
  let quiet = false;
  let inventory = false;
  let emitToolpause = false;
  const ignore: string[] = [];

  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (a === "-h" || a === "--help") return { help: true };
    if (a === "--quiet") {
      quiet = true;
      continue;
    }
    if (a === "--inventory") {
      inventory = true;
      continue;
    }
    if (a === "--emit-toolpause-rules") {
      emitToolpause = true;
      continue;
    }
    if (a === "--ignore") {
      const v = argv[++i];
      if (!v) throw new Error("--ignore requires a pattern");
      ignore.push(v);
      continue;
    }
    if (a === "--format") {
      const v = argv[++i];
      if (!v || !["text", "json", "sarif", "html"].includes(v)) {
        throw new Error("Invalid --format");
      }
      format = v as OutputFormat;
      continue;
    }
    if (a === "--fail-on") {
      const v = argv[++i] as Severity;
      if (!v || !(v in SEVERITY_RANK)) throw new Error("Invalid --fail-on");
      failOn = v;
      continue;
    }
    if (a === "--output") {
      output = argv[++i] || null;
      if (!output) throw new Error("--output requires a path");
      continue;
    }
    if (a.startsWith("-")) throw new Error(`Unknown option: ${a}`);
    roots.push(a);
  }

  if (!roots.length) roots.push(".");
  return { help: false, roots, format, failOn, output, quiet, inventory, emitToolpause, ignore };
}

function writeOut(body: string, output: string | null, quiet: boolean, label: string): void {
  if (output) {
    fs.mkdirSync(path.dirname(path.resolve(output)), { recursive: true });
    fs.writeFileSync(output, body.endsWith("\n") ? body : body + "\n", "utf8");
    if (!quiet) process.stderr.write(`Wrote ${label} → ${output}\n`);
  } else {
    process.stdout.write(body.endsWith("\n") ? body : body + "\n");
  }
}

function main(): void {
  try {
    const args = parseArgs(process.argv.slice(2));
    if (args.help) {
      printHelp();
      process.exit(0);
    }

    const result = scanRoots(args.roots, args.ignore);

    if (args.inventory) {
      const lines = result.targets.map((t) => `${t.kind}\t${t.path}`);
      process.stdout.write(
        lines.join("\n") + (lines.length ? "\n" : "") + `# ${result.targets.length} targets\n`
      );
      process.exit(0);
    }

    if (args.emitToolpause) {
      const emit = emitToolPauseRules(result, args.failOn);
      writeOut(formatToolPauseEmit(emit), args.output, args.quiet, "toolpause-rules");
      process.exit(shouldFail(result.findings, args.failOn) ? 1 : 0);
    }

    let body: string;
    switch (args.format) {
      case "json":
        body = formatJson(result);
        break;
      case "sarif":
        body = formatSarif(result);
        break;
      case "html":
        body = formatHtml(result);
        break;
      default:
        body = formatText(result);
    }

    writeOut(body, args.output, args.quiet, args.format);
    process.exit(shouldFail(result.findings, args.failOn) ? 1 : 0);
  } catch (err) {
    process.stderr.write(`skill-scan error: ${err instanceof Error ? err.message : String(err)}\n`);
    process.exit(2);
  }
}

main();
