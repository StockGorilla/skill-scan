# toolfence-scan

**ToolFence Scan** — pre-install security for AI coding agents.

Scan **Cursor / Claude / Copilot / Windsurf / VS Code** skills, instructions, prompts, bundled scripts, and **MCP configs** for prompt injection, secrets, shadowing, and over-broad permissions **before** you trust them.

Part of [ToolFence](https://toolpause.netlify.app/#suite):

> **Scan** what you install → **Gate** what can hurt you → **Radar** on cost and risk.

```bash
npx toolfence-scan .
```

(`skill-scan` is also installed as a CLI alias.)

**What we check vs don’t:** [WHAT_WE_CHECK.md](./WHAT_WE_CHECK.md)

## 30-second demo

```bash
npx toolfence-scan ./fixtures --format text --fail-on high
```

Expect critical/high findings on planted bad fixtures (non-zero exit). Clean fixtures under `fixtures/clean-skill` and `fixtures/benign-docs` stay quiet.

```bash
npx toolfence-scan .
npx toolfence-scan . --format sarif --output results.sarif
npx toolfence-scan . --format html --output report.html
npx toolfence-scan . --fail-on high
npx toolfence-scan . --emit-gate-rules --output gate-rules.json
npx toolfence-scan . --baseline .toolfence-baseline.json
npx toolfence-scan . --fix   # remediation checklist
```

## What it scans

| Kind | Examples |
|------|----------|
| Skills | `SKILL.md`, `.cursor/skills/**`, `.claude/skills/**`, `.windsurf/skills/**` |
| Cursor / IDE rules | `.cursorrules`, `.cursor/rules/**`, Continue/Windsurf rules |
| Agents | `AGENTS.md`, `CLAUDE.md`, `GEMINI.md`, `CODEX.md` |
| **GitHub Copilot** | `.github/copilot-instructions.md`, prompts, agents |
| MCP | `.cursor/mcp.json`, `.vscode/mcp.json`, Claude Desktop, content-detected `mcpServers` |
| Scripts | `.sh` / `.py` / `.js` next to skills |
| Globals | `--include-global` → `~/.cursor`, `~/.claude`, … |

`toolfence-scan --inventory .` lists discovered files by kind.

## Rules (v0.2.0)

See [RULES.md](./RULES.md). Highlights: prompt injection, hidden Unicode, secrets, MCP overbroad (string **or** array `command`), embedded script danger, static exfil chains, tool shadowing, optional `--drift` rug-pull hashes.

Suppress with `# toolfence-scan-ignore` / `# skill-scan-ignore` (optional `:rule-id`), `.toolfence-scanignore`, or `--baseline`.

Config file (optional): `.toolfence-scan.yml`

```yaml
failOn: high
ignore:
  - "**/vendor/**"
disableRules:
  - tool-shadowing
rulesDir: ./my-rules
```

Custom packs: `--rules-dir ./my-rules` (YAML/JSON regex rules).

## GitHub Action

```yaml
- uses: StockGorilla/skill-scan@v0.2.0
  with:
    path: .
    fail-on: high
```

Uploads SARIF to GitHub code scanning when permissions allow (`security-events: write`).

## pre-commit

```yaml
# .pre-commit-config.yaml
- repo: https://github.com/StockGorilla/skill-scan
  rev: v0.2.0
  hooks:
    - id: toolfence-scan
```

## Bridge to ToolFence Gate

```bash
npx toolfence-scan . --emit-gate-rules --output gate-rules.json
```

Guide: [Scan → Gate](https://toolpause.netlify.app/docs/scan-then-gate).

## Develop locally

```bash
git clone https://github.com/StockGorilla/skill-scan.git
cd skill-scan
npm install
npm test
node dist/cli.js --help
```

## License

MIT
