import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

let cached: string | null = null;

export function packageVersion(): string {
  if (cached) return cached;
  try {
    const here = path.dirname(fileURLToPath(import.meta.url));
    const pkgPath = path.resolve(here, "..", "package.json");
    const pkg = JSON.parse(fs.readFileSync(pkgPath, "utf8")) as { version?: string };
    cached = pkg.version || "0.0.0";
  } catch {
    cached = "0.0.0";
  }
  return cached;
}

export const TOOL_NAME = "toolfence-scan";
export const TOOL_URI = "https://github.com/StockGorilla/skill-scan";
