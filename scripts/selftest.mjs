#!/usr/bin/env node
import { spawnSync } from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const cli = path.join(root, "dist", "cli.js");

function run(args, opts = {}) {
  const r = spawnSync(process.execPath, [cli, ...args], {
    cwd: opts.cwd || root,
    encoding: "utf8",
    env: { ...process.env, ...(opts.env || {}) },
  });
  return {
    status: r.status ?? 2,
    stdout: r.stdout || "",
    stderr: r.stderr || "",
  };
}

function assert(cond, msg) {
  if (!cond) {
    console.error(`selftest FAIL: ${msg}`);
    process.exit(1);
  }
}

function findingIds(jsonText) {
  const data = JSON.parse(jsonText);
  return new Set((data.findings || []).map((f) => f.ruleId));
}

// --- version / brand ---
{
  const r = run(["--version"]);
  assert(r.status === 0, "--version exit");
  assert(/^\d+\.\d+\.\d+/.test(r.stdout.trim()), "--version semver");
}

// --- known-bad fixtures must fire expected rules ---
const expectations = [
  ["fixtures/bad-injection", ["prompt-injection"]],
  ["fixtures/bad-hardcoded", ["hardcoded-secret"]],
  ["fixtures/bad-network", ["network-exfil"]],
  ["fixtures/bad-exfil", ["remote-exec"]],
  ["fixtures/bad-exfil-chain", ["exfil-chain"]],
  ["fixtures/mcp-overbroad", ["mcp-overbroad"]],
  ["fixtures/bad-mcp-string", ["mcp-overbroad"]],
  ["fixtures/bad-script", ["embedded-script-danger"]],
  ["fixtures/bad-shadow", ["tool-shadowing", "mcp-overbroad"]],
];

for (const [fixture, rules] of expectations) {
  const r = run([fixture, "--format", "json", "--fail-on", "info"]);
  assert(r.status === 1, `${fixture} should fail`);
  const ids = findingIds(r.stdout);
  for (const rule of rules) {
    assert(ids.has(rule), `${fixture} missing rule ${rule}; got ${[...ids].join(",")}`);
  }
  console.log(`ok  bad  ${fixture} → ${rules.join(", ")}`);
}

// --- benign / clean must stay clean at high ---
for (const fixture of ["fixtures/clean-skill", "fixtures/benign-docs"]) {
  const r = run([fixture, "--format", "json", "--fail-on", "high"]);
  assert(r.status === 0, `${fixture} should be clean at high`);
  const data = JSON.parse(r.stdout);
  const high = (data.findings || []).filter((f) =>
    ["critical", "high"].includes(f.severity)
  );
  assert(high.length === 0, `${fixture} unexpected high/critical: ${JSON.stringify(high)}`);
  console.log(`ok  clean ${fixture}`);
}

// --- SARIF: relative uri, tool name, real version ---
{
  const r = run(["fixtures/bad-injection", "--format", "sarif", "--fail-on", "info"]);
  assert(r.status === 1, "sarif scan fail");
  const sarif = JSON.parse(r.stdout);
  const driver = sarif.runs[0].tool.driver;
  assert(driver.name === "toolfence-scan", `driver.name=${driver.name}`);
  assert(driver.version && driver.version !== "0.1.0", `driver.version=${driver.version}`);
  assert(
    /skill-scan|StockGorilla/i.test(driver.informationUri || ""),
    "informationUri"
  );
  const uri = sarif.runs[0].results[0].locations[0].physicalLocation.artifactLocation.uri;
  assert(!path.isAbsolute(uri), `SARIF uri should be relative, got ${uri}`);
  assert(!uri.startsWith("file:"), `SARIF uri should not be file://, got ${uri}`);
  console.log("ok  sarif shape");
}

// --- inventory flag ---
{
  const r = run(["--inventory", "fixtures/clean-skill"]);
  assert(r.status === 0, "inventory exit");
  assert(/skill\t/.test(r.stdout), "inventory lists skill");
  console.log("ok  inventory");
}

// --- baseline suppresses repeat findings ---
{
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "tfs-base-"));
  const baseline = path.join(dir, "baseline.json");
  const first = run([
    "fixtures/bad-injection",
    "--format",
    "json",
    "--fail-on",
    "info",
    "--baseline",
    baseline,
    "--update-baseline",
  ]);
  assert(first.status === 1, "update-baseline still reports findings once");
  const second = run([
    "fixtures/bad-injection",
    "--format",
    "json",
    "--fail-on",
    "info",
    "--baseline",
    baseline,
  ]);
  assert(second.status === 0, "baselined findings should not fail");
  const data = JSON.parse(second.stdout);
  assert((data.findings || []).length === 0, "baseline should suppress all");
  console.log("ok  baseline");
}

// --- --rules-dir custom pack ---
{
  const r = run([
    "fixtures/clean-skill",
    "--rules-dir",
    "fixtures/custom-rules",
    "--enable-rule",
    "custom-ban-todo",
    "--format",
    "json",
    "--fail-on",
    "info",
  ]);
  // clean-skill has no TODO — should be clean
  assert(r.status === 0, "custom rules on clean fixture");
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), "tfs-todo-"));
  const skill = path.join(tmp, "SKILL.md");
  fs.writeFileSync(skill, "# x\nTODO remove me\n");
  const r2 = run([
    skill,
    "--rules-dir",
    path.join(root, "fixtures/custom-rules"),
    "--enable-rule",
    "custom-ban-todo",
    "--format",
    "json",
    "--fail-on",
    "info",
  ]);
  assert(r2.status === 1, "custom rule should fire");
  assert(findingIds(r2.stdout).has("custom-ban-todo"), "custom-ban-todo id");
  console.log("ok  rules-dir");
}

// --- drift detect ---
{
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "tfs-drift-"));
  const drift = path.join(dir, "drift.json");
  const skillDir = path.join(dir, "skill");
  fs.mkdirSync(skillDir);
  const skill = path.join(skillDir, "SKILL.md");
  fs.writeFileSync(skill, "# stable\n");
  run([skillDir, "--drift", drift, "--update-drift", "--fail-on", "info"]);
  fs.writeFileSync(skill, "# changed body\n");
  const r = run([skillDir, "--drift", drift, "--format", "json", "--fail-on", "info"]);
  assert(r.status === 1, "drift should fail on change");
  assert(findingIds(r.stdout).has("rug-pull-drift"), "rug-pull-drift");
  console.log("ok  drift");
}

console.log("selftest: all checks passed");
