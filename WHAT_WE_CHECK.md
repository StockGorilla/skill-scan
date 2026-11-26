# What toolfence-scan checks (and what it doesn’t)

Honesty beats inflated marketing. Use this when comparing us to Snyk Agent Scan, MCP-Scan, SkillSpector, or a runtime proxy.

## We check (static, pre-install)

| Area | Examples |
|------|----------|
| **Instruction packs** | Cursor skills/rules, Claude/`AGENTS.md`/`GEMINI.md`/`CODEX.md`, Copilot instructions/prompts/agents, Windsurf/Continue paths |
| **MCP configs** | `.cursor/mcp.json`, `.vscode/mcp.json`, Claude Desktop, content-detected `mcpServers` JSON |
| **Bundled scripts** | `.sh` / `.py` / `.js` / `.ts` next to skills — `eval`, `child_process`, decode-then-exec |
| **Prompt injection & concealment** | Ignore-previous / jailbreak / hide-from-user language; hidden Unicode |
| **Secrets** | Common key shapes (AWS, GitHub, GitLab, Slack, Stripe, JWT, npm, PEM) — not a full gitleaks corpus |
| **Exfil patterns** | Callback hosts, webhook URLs, static “read secret → POST” chains in one file |
| **MCP over-permission** | Shell commands (string or array), `/` mounts, `tools: "*"`, auto-approve |
| **Shadowing / drift** | Duplicate MCP names; optional content-hash drift baseline (`--drift`) |
| **CI outputs** | text / JSON / SARIF 2.1 (repo-relative) / HTML; baseline; `--rules-dir` packs |

## We do **not** check (yet / by design)

| Gap | Who owns it |
|-----|-------------|
| **Runtime** arg tampering between approve and execute | **ToolFence Gate** |
| Live MCP tool-poisoning via a **running proxy** | MCP-Scan / Invariant-style products |
| Full malware AV / YARA / binary unpacking | Specialist AV |
| LLM “rewrite this skill for me” | Deferred until FP rate is low |
| Exhaustive secret entropy / every SaaS token format | gitleaks / trufflehog |
| Token-bloat / context cost as a security verdict | Optional later; not a lead signal |
| Guaranteeing zero false positives | Pattern scanners always need suppressions / baselines |

## Trust controls

- Line suppressions: `# toolfence-scan-ignore` / `# skill-scan-ignore` (optional `:rule-id`)
- `.toolfence-scanignore` / `.skill-scanignore` path globs
- `--baseline` so only **new** findings fail CI
- `--fail-on` severity gate
- Fixture suite under `fixtures/` (known-bad + benign)

## Version

See `package.json` / `toolfence-scan --version`. Docs that claim features not listed here are wrong — file an issue.
