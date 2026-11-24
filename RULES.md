# skill-scan rule catalog

| ruleId | Severity | Title | What it catches |
|--------|----------|-------|-----------------|
| `hidden-unicode` | high | Hidden or deceptive Unicode | Zero-width, bidi overrides, control chars that can hide instructions |
| `prompt-injection` | critical | Prompt injection / instruction override | “Ignore previous instructions”, jailbreak / unrestricted-system language |
| `hide-from-user` | critical | Concealment from the human | “Do not tell the user”, hide from human, auto-approve without user |
| `credential-exfil` | critical | Credential or secret exfiltration | Read `.env` / keys + send to webhooks / paste sinks |
| `mcp-overbroad` | high | Over-broad MCP permissions | `"tools": "*"`, `alwaysAllow`, unrestricted shell/filesystem |
| `remote-exec` | high | Remote pipe-to-shell | `curl … \| bash` (and similar) in skill steps |

Rules are pattern-based (regex / lightweight scanners). Custom packs: `--rules-dir` when available; otherwise open a PR with a new rule + fixture (see [CONTRIBUTING.md](./CONTRIBUTING.md)).

**Exit codes:** `0` clean (or below `--fail-on`) · `1` findings at/above threshold · `2` scanner error.
