#!/usr/bin/env node
import { spawnSync } from "node:child_process";
import path from "node:path";
import { fileURLToPath } from "node:url";

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const cli = path.join(root, "dist", "cli.js");

const result = spawnSync(
  process.execPath,
  [cli, "fixtures", "--fail-on", "high", "--format", "text"],
  { cwd: root, stdio: "inherit" }
);

const code = result.status ?? 2;
if (code === 0) {
  console.error("selftest: expected fixture scan to report findings (exit 1)");
  process.exit(1);
}
if (code !== 1) {
  console.error(`selftest: unexpected exit ${code}`);
  process.exit(code);
}
console.log("selftest: ok (fixtures flagged as expected)");
