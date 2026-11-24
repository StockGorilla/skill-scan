# skill-scan rule catalog

| ruleId | Severity | Title | What it catches |
|--------|----------|-------|-----------------|
| `hidden-unicode` | high | Hidden or deceptive Unicode | Zero-width, bidi overrides, control chars that can hide instructions |
| `prompt-injection` | critical | Prompt injection / instruction override | Ignore-previous, jailbreak, disable safety/guardrails, DAN mode, bypass policy |
| `hide-from-user` | critical | Concealment from the human | Hide from user/human, auto-approve, run without confirmation, YOLO mode |
| `credential-exfil` | critical | Credential or secret exfiltration | Read `.env` / keys + send credentials language |
| `hardcoded-secret` | critical | Hardcoded secret or API key | AWS `AKIA…`, `sk-…`, `ghp_…`, Slack `xox…`, Google `AIza…`, PEM keys |
| `network-exfil` | high | Suspicious network exfil sink | webhook.site, ngrok, pastebin, oastify, Discord/Slack webhooks, raw IP URLs |
| `mcp-overbroad` | high | Over-broad MCP permissions | `"tools": "*"`, `alwaysAllow`, unrestricted shell/filesystem |
| `remote-exec` | high | Remote script execution | `curl\|bash`, `iwr\|iex`, `eval$(curl…)` |

## Suppressions

- End a line with `# skill-scan-ignore` (also `//` or `<!-- … -->`)
- Put `# skill-scan-ignore-next-line` on the previous line
- Add path globs to `.skill-scanignore` at the scan root (and/or pass `--ignore`)

Rules are pattern-based (regex / lightweight scanners). Open a PR with a new rule + fixture (see [CONTRIBUTING.md](./CONTRIBUTING.md)).

**Exit codes:** `0` clean (or below `--fail-on`) · `1` findings at/above threshold · `2` scanner error.

**Targets include** Cursor skills/rules, Claude skills, GitHub Copilot instructions/prompts/agents, and MCP configs.
