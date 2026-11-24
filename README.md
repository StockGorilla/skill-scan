# skill-scan

**ToolFence Scan** — pre-install security for AI coding agents.

Scan **skills**, **MCP configs**, and **Cursor rules** for prompt injection, hidden Unicode, credential risks, and over-broad permissions **before** you trust them.

Part of [ToolFence](https://toolpause.netlify.app/#suite):

> **Scan** what you install → **Gate** what can hurt you → **Radar** on cost and risk.

```bash
npx skill-scan .
```

## 30-second demo

```bash
# From this package (fixtures include known-bad skills)
npx skill-scan ./fixtures --format text --fail-on high
```

Expect critical/high findings on the planted bad skills (and a non-zero exit).

Against your own repo:

```bash
npx skill-scan .
npx skill-scan . --format sarif --output results.sarif
npx skill-scan . --format html --output report.html
npx skill-scan . --fail-on high
npx skill-scan . --emit-toolpause-rules --output gate-rules.json
```

## What it scans

| Kind | Examples |
|------|----------|
| Skills | `SKILL.md`, `.cursor/skills/**` |
| Rules | `.cursorrules`, `.cursor/rules/**`, `AGENTS.md` |
| MCP | `.cursor/mcp.json`, `mcp.json`, `claude_desktop_config.json` |

Also: `skill-scan inventory .` lists discovered files by kind before rules run.

## Rule packs (v0.1)

See [RULES.md](./RULES.md) for the full catalog.

| Rule | Severity | Catches |
|------|----------|---------|
| `hidden-unicode` | high | Bidi / zero-width concealment |
| `prompt-injection` | critical | Ignore-previous / jailbreak language |
| `hide-from-user` | critical | Conceal actions from the human |
| `credential-exfil` | critical | Secret reads / webhook sinks |
| `mcp-overbroad` | high | Wildcard tools, auto-approve, shell MCP |
| `remote-exec` | high | `curl \| bash` installers |

Suppress a line with `# skill-scan-ignore` or add paths to `.skill-scanignore`.

## Bridge to ToolFence Gate

High/critical findings can emit a **Rules fragment** for [Gate](https://toolpause.fly.dev):

```bash
npx skill-scan . --emit-toolpause-rules --output gate-rules.json
```

Includes suggested `policy.deny_tools`, `policy.tool_overrides`, and `policy.deny_tags`. Merge carefully into Inbox → Rules (don’t blind-overwrite production policy).

## CI (GitHub)

After publish, smallest check:

```yaml
- run: npx skill-scan . --format sarif --output skill-scan.sarif --fail-on high
- uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: skill-scan.sarif
```

This monorepo also runs `.github/workflows/skill-scan.yml` against the package build.

## Develop locally

```bash
git clone https://github.com/StockGorilla/skill-scan.git
cd skill-scan
npm install
npm test          # build + fixture self-test (expects findings)
node dist/cli.js --help
```

(Also vendored in the ToolFence monorepo under `packages/skill-scan`.)

## Docs

- [RULES.md](./RULES.md) — rule catalog  
- [CONTRIBUTING.md](./CONTRIBUTING.md) — add a rule + fixture  
- [SECURITY.md](./SECURITY.md) — false positives / missed malware  

## Status

`skill-scan@0.1.0` — OSS wedge for **ToolFence Scan**. Package rename/alias to `@toolfence/scan` comes with the ToolFence package cutover.
