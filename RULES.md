# toolfence-scan rule catalog

| ruleId | Severity | Title | What it catches |
|--------|----------|-------|-----------------|
| `hidden-unicode` | high | Hidden or deceptive Unicode | Zero-width, bidi overrides, control chars that can hide instructions |
| `prompt-injection` | critical | Prompt injection / instruction override | Ignore-previous, jailbreak, disable safety/guardrails, DAN mode, bypass policy |
| `hide-from-user` | critical | Concealment from the human | Hide from user/human, auto-approve, run without confirmation, YOLO mode |
| `credential-exfil` | critical | Credential or secret exfiltration | Read `.env` / keys + send-credentials language |
| `hardcoded-secret` | critical | Hardcoded secret or API key | AWS, GitHub/GitLab PAT, Slack, Stripe, JWT, npm, SendGrid, PEM keys |
| `network-exfil` | high | Suspicious network exfil sink | webhook.site, ngrok, pastebin, oastify, Discord/Slack webhooks, raw IP URLs |
| `mcp-overbroad` | high | Over-broad MCP permissions | Shell command (string/array), `/` mounts, `tools: "*"`, alwaysAllow, unpinned `-y` runners |
| `remote-exec` | high | Remote script execution | `curl\|bash`, `iwr\|iex`, `eval$(curl…)` |
| `embedded-script-danger` | high | Dangerous embedded script / payload | `eval`, `child_process`, base64-decode-then-exec, encoded PowerShell |
| `exfil-chain` | critical | Covert exfiltration chain | Secret collection + outbound POST/webhook/encode in the same file |
| `tool-shadowing` | medium | Cross-tool name shadowing | Duplicate MCP server/tool names in one config |
| `rug-pull-drift` | high/medium/low | Content drift vs baseline | Emitted when `--drift` snapshot hash changes (not a static regex rule) |

## Suppressions

- End a line with `# toolfence-scan-ignore` or `# skill-scan-ignore` (optional `:rule-id`)
- `# toolfence-scan-ignore-next-line` / `# skill-scan-ignore-next-line` on the previous line
- Path globs in `.toolfence-scanignore` / `.skill-scanignore`
- CI baseline: `--baseline .toolfence-baseline.json` (only **new** findings fail)
- Config: `.toolfence-scan.yml` with `disableRules`, `ignore`, `failOn`, `rulesDir`

## Custom rules

```bash
npx toolfence-scan . --rules-dir ./my-rules
```

YAML pack example (`my-rules/extra.yml`):

```yaml
- id: custom-ban-todo
  title: Ban TODO in skills
  severity: low
  pattern: \bTODO\b
  message: TODO marker in skill text
  kinds: [skill]
```

## Honesty

See [WHAT_WE_CHECK.md](./WHAT_WE_CHECK.md) for what we do **not** claim (runtime tamper, full AV, live MCP proxy).

**Exit codes:** `0` clean (or below `--fail-on`) · `1` findings at/above threshold · `2` scanner error.
