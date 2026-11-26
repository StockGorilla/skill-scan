import type { FindingHit, Rule, RuleContext } from "../types.js";

function lineOf(text: string, index: number): number {
  return text.slice(0, index).split(/\r?\n/).length;
}

export function hitsFromRegex(ctx: RuleContext, re: RegExp, message?: string): FindingHit[] {
  const hits: FindingHit[] = [];
  const flags = re.flags.includes("g") ? re.flags : `${re.flags}g`;
  const global = new RegExp(re.source, flags);
  let m: RegExpExecArray | null;
  while ((m = global.exec(ctx.text)) !== null) {
    const startLine = lineOf(ctx.text, m.index);
    const endLine = lineOf(ctx.text, m.index + Math.max(m[0].length - 1, 0));
    hits.push({
      startLine,
      endLine,
      message,
      snippet: ctx.lines[startLine - 1]?.trim().slice(0, 160),
    });
    if (m[0].length === 0) global.lastIndex += 1;
  }
  return hits;
}

const hiddenUnicode: Rule = {
  id: "hidden-unicode",
  title: "Hidden or deceptive Unicode",
  severity: "high",
  description: "Zero-width, bidi override, or unusual control characters that can hide instructions.",
  remediation: "Remove invisible characters; keep skill text in plain visible Unicode.",
  test(ctx) {
    return hitsFromRegex(
      ctx,
      /[\u200B-\u200F\u202A-\u202E\u2060-\u2064\u2066-\u2069\uFEFF]/,
      "Invisible or bidi Unicode character"
    );
  },
};

const promptInjection: Rule = {
  id: "prompt-injection",
  title: "Prompt injection / instruction override",
  severity: "critical",
  description: "Language that tries to override system or developer instructions.",
  remediation: "Delete override language; skills should not instruct the model to ignore prior rules.",
  test(ctx) {
    return hitsFromRegex(
      ctx,
      /\b(?:ignore(?:\s+all)?(?:\s+previous|\s+prior|\s+above)?\s+instructions?|disregard(?:\s+all)?\s+(?:previous|prior|safety|guardrails?)|override(?:\s+system)?\s+prompt|you\s+are\s+now\s+unrestricted|jailbreak|disable(?:\s+all)?\s+(?:safety|guardrails?|content\s+filters?)|enter\s+DAN\s+mode|developer\s+mode\s+enabled|your\s+system\s+prompt\s+is|pretend\s+(?:you\s+have\s+no|there\s+are\s+no)\s+(?:restrictions|rules|limits)|bypass(?:\s+all)?\s+(?:safety|policy|policies|guardrails?))\b/i,
      "Possible instruction-override language"
    );
  },
};

const hideFromUser: Rule = {
  id: "hide-from-user",
  title: "Concealment from the human",
  severity: "critical",
  description: "Instructs the agent to hide actions or withhold information from the user.",
  remediation: "Remove concealment instructions; agent skills must stay transparent to the operator.",
  test(ctx) {
    return hitsFromRegex(
      ctx,
      /\b(do\s+not\s+tell\s+the\s+user|don't\s+tell\s+the\s+user|hide\s+this\s+from\s+(the\s+)?(user|human)|without\s+(the\s+)?user'?s?\s+knowledge|auto-?approve\s+without|run\s+without\s+(?:asking|confirmation|approval)|yolo\s+mode|never\s+ask\s+(?:the\s+)?(?:user|human)\s+for\s+(?:permission|confirmation))\b/i,
      "Concealment / auto-approve without human"
    );
  },
};

const credentialExfil: Rule = {
  id: "credential-exfil",
  title: "Credential or secret exfiltration",
  severity: "critical",
  description: "Reads secrets or instructs sending credentials to external endpoints.",
  remediation:
    "Never instruct agents to read or transmit raw credentials. Use a secret manager and env injection. Delete any 'send credentials to …' lines.",
  test(ctx) {
    // Avoid FP on educational "read about credentials" / "credentials documentation"
    const patterns = [
      /\b(cat|type|Get-Content|print)\s+[^\n]*(?:\.env(?:\b|\.)|\/\.aws\/credentials|id_rsa|secrets?\.(json|ya?ml)|\/etc\/shadow)/i,
      /\b(exfiltrate|steal)\s+(secrets?|credentials?|api\s*keys?|tokens?)\b/i,
      /\b(curl|wget|fetch|Invoke-WebRequest)\b[^\n]*(api[_-]?key|password|token|authorization|secret)\b/i,
      /\bsend\s+(?:the\s+)?(?:secrets?|credentials?|api\s*keys?|tokens?)\s+to\b/i,
      /\bread\s+(?:and\s+)?(?:exfiltrate|upload|post|send)\b[^\n]*(?:secret|credential|token|api[_-]?key)/i,
    ];
    return patterns.flatMap((re) => hitsFromRegex(ctx, re, "Possible secret handling / exfil sink"));
  },
};

const hardcodedSecret: Rule = {
  id: "hardcoded-secret",
  title: "Hardcoded secret or API key",
  severity: "critical",
  description: "Likely embedded credentials (AWS, GitHub, OpenAI, Slack, Stripe, JWT, npm, private keys).",
  remediation: "Remove secrets from skills/instructions; rotate the leaked credential; use env vars or a secret manager.",
  test(ctx) {
    const patterns: Array<[RegExp, string]> = [
      [/\bAKIA[0-9A-Z]{16}\b/, "Possible AWS access key id"],
      [/\b(?:sk|rk)_live_[a-zA-Z0-9]{20,}\b/, "Possible Stripe live secret key"],
      [/\b(?:sk|rk)-[a-zA-Z0-9_-]{20,}\b/, "Possible OpenAI/Stripe-style secret key"],
      [/\bghp_[A-Za-z0-9]{20,}\b/, "Possible GitHub personal access token"],
      [/\bgho_[A-Za-z0-9]{20,}\b/, "Possible GitHub OAuth token"],
      [/\bghu_[A-Za-z0-9]{20,}\b/, "Possible GitHub user-to-server token"],
      [/\bgithub_pat_[A-Za-z0-9_]{20,}\b/, "Possible GitHub fine-grained PAT"],
      [/\bglpat-[A-Za-z0-9\-_]{20,}\b/, "Possible GitLab personal access token"],
      [/\bxox[baprs]-[A-Za-z0-9-]{10,}\b/, "Possible Slack token"],
      [/\bAIza[0-9A-Za-z\-_]{20,}\b/, "Possible Google API key"],
      [/\bSG\.[A-Za-z0-9_\-]{20,}\.[A-Za-z0-9_\-]{20,}\b/, "Possible SendGrid API key"],
      [/\bnpm_[A-Za-z0-9]{30,}\b/, "Possible npm access token"],
      [/\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b/, "Possible JWT"],
      [/-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----/, "Embedded private key block"],
    ];
    return patterns.flatMap(([re, msg]) => hitsFromRegex(ctx, re, msg));
  },
};

const networkExfil: Rule = {
  id: "network-exfil",
  title: "Suspicious network exfil sink",
  severity: "high",
  description: "Calls out to paste/callback/tunnel hosts or raw IP URLs often used for exfiltration.",
  remediation: "Remove unexpected callback URLs; allowlist only trusted HTTPS endpoints you control.",
  test(ctx) {
    const patterns: Array<[RegExp, string]> = [
      [
        /https?:\/\/(?:webhook\.site|requestbin\.[a-z]+|pipedream\.net|hookbin\.com|beeceptor\.com|ngrok(?:-free)?\.(?:app|io|com)|loca\.lt|trycloudflare\.com|pastebin\.com|hastebin\.com|dpaste\.[a-z]+|oastify\.com|oast\.[a-z]+|burpcollaborator\.net|interact\.sh)/i,
        "Suspicious callback / paste host",
      ],
      [
        /https?:\/\/(?:discord(?:app)?\.com\/api\/webhooks|hooks\.slack\.com\/services)\//i,
        "Inbound webhook URL embedded in instructions",
      ],
      [
        /https?:\/\/(?:\d{1,3}\.){3}\d{1,3}(?::\d+)?(?:\/|\b)/,
        "Raw IP HTTP(S) callback",
      ],
    ];
    return patterns.flatMap(([re, msg]) => hitsFromRegex(ctx, re, msg));
  },
};

const overbroadMcp: Rule = {
  id: "mcp-overbroad",
  title: "Over-broad MCP permissions",
  severity: "high",
  description: "MCP server config grants unrestricted shell, filesystem roots, or wildcard tools.",
  remediation:
    "Scope MCP servers to least privilege: pin a non-shell command, avoid mounting `/`, drop `tools: \"*\"` / alwaysAllow, and require approval for high-impact tools.",
  kinds: ["mcp_config"],
  test(ctx) {
    const hits: FindingHit[] = [];
    // String or array form of command
    hits.push(
      ...hitsFromRegex(
        ctx,
        /"(?:command)"\s*:\s*(?:"(?:\/bin\/(?:ba)?sh|\/bin\/zsh|powershell(?:\.exe)?|cmd(?:\.exe)?|bash)"|\[[^\]]*(?:\/bin\/(?:ba)?sh|powershell|cmd\.exe))/i,
        "Shell-capable MCP command"
      )
    );
    hits.push(
      ...hitsFromRegex(
        ctx,
        /"(?:args)"\s*:\s*\[[^\]]*(?:\/bin\/(?:ba)?sh|powershell|cmd\.exe|-c)/i,
        "Shell-capable MCP args"
      )
    );
    // Root filesystem: "/", ["/"], or "/" anywhere in an args array
    hits.push(
      ...hitsFromRegex(
        ctx,
        /"(?:args|roots?|path|cwd)"\s*:\s*(?:"\/"|\[(?:[^\]]*,\s*)?"\/"(?:\s*,[^\]]*)?\])/,
        "Filesystem root access"
      )
    );
    hits.push(...hitsFromRegex(ctx, /"tools?"\s*:\s*(?:"\*"|\["\*"\])/, "Wildcard tools allowed"));
    hits.push(
      ...hitsFromRegex(
        ctx,
        /\b(?:alwaysAllow|autoApprove|auto_approve)\b[^\n]{0,80}\btrue\b/i,
        "Auto-approve enabled in MCP config"
      )
    );
    // Dangerous npx / uvx without pin
    hits.push(
      ...hitsFromRegex(
        ctx,
        /"(?:command)"\s*:\s*"(?:npx|uvx|bunx)"[\s\S]{0,200}"(?:args)"\s*:\s*\[[^\]]*(-y|--yes)/i,
        "Unpinned package runner with auto-yes"
      )
    );
    return hits;
  },
};

const remoteExec: Rule = {
  id: "remote-exec",
  title: "Remote script execution",
  severity: "high",
  description: "Pipes remote content into a shell (curl | bash and similar).",
  remediation: "Avoid remote pipe-to-shell in skills; pin, download, review, then run scripts instead.",
  test(ctx) {
    const patterns = [
      /\b(curl|wget)\b[^\n]{0,100}\|\s*(?:ba)?sh\b/i,
      /\b(iwr|Invoke-WebRequest)\b[^\n]{0,100}\|\s*iex\b/i,
      /\beval\s*\(\s*(?:curl|wget)\b/i,
      /\bbash\s+<\s*\(\s*(?:curl|wget)\b/i,
    ];
    return patterns.flatMap((re) => hitsFromRegex(ctx, re, "Remote content piped to shell"));
  },
};

const embeddedScriptDanger: Rule = {
  id: "embedded-script-danger",
  title: "Dangerous embedded script / payload",
  severity: "high",
  description: "Skill-bundled scripts or fenced code use eval, child_process, base64 decode+exec, or similar.",
  remediation:
    "Remove eval/child_process/decode-and-exec patterns from skill scripts. Prefer reviewed, pinned helpers without dynamic code execution.",
  kinds: ["skill", "prompt", "copilot_instructions", "copilot_agent", "cursor_rules", "agents_md", "script", "other"],
  test(ctx) {
    const patterns: Array<[RegExp, string]> = [
      [/\bchild_process\b|\b(?:exec|execSync|spawn|spawnSync)\s*\(/i, "Process spawn / child_process"],
      [/\beval\s*\(|\bFunction\s*\(|\bnew\s+Function\b/i, "Dynamic code evaluation"],
      [/\b(?:base64|b64decode|Buffer\.from\([^)]*base64)[\s\S]{0,80}(?:exec|eval|system|subprocess)/i, "Base64 decode then execute"],
      [/powershell[^\n]{0,60}-enc(?:odedcommand)?/i, "Encoded PowerShell"],
      [/\bos\.system\s*\(|\bsubprocess\.(?:call|run|Popen)\s*\(/i, "Python process execution"],
    ];
    return patterns.flatMap(([re, msg]) => hitsFromRegex(ctx, re, msg));
  },
};

const exfilChain: Rule = {
  id: "exfil-chain",
  title: "Covert exfiltration chain",
  severity: "critical",
  description: "Multi-step pattern: collect secrets/env then POST/upload/encode to an external sink in the same file.",
  remediation:
    "Break the chain: remove secret collection instructions and any outbound POST/webhook/encode-to-URL sinks from the same skill pack.",
  test(ctx) {
    const text = ctx.text;
    const collect =
      /\b(?:\.env|credentials|api[_-]?key|secret|token|password|id_rsa|AWS_SECRET|process\.env)\b/i.test(text) &&
      /\b(?:read|cat|load|collect|gather|extract|dump|print|Get-Content)\b/i.test(text);
    const sink =
      /\b(?:curl|wget|fetch|Invoke-WebRequest|requests\.(?:post|put)|http\.request|axios)\b/i.test(text) ||
      /https?:\/\/[^\s)"']+/i.test(text);
    const encode =
      /\b(?:base64|btoa|urlencode|encodeURIComponent|hexencode)\b/i.test(text) &&
      /\b(?:send|post|upload|exfil|webhook|callback)\b/i.test(text);

    if (!(collect && (sink || encode))) return [];

    // Point at first collect-ish line for location
    let startLine = 1;
    for (let i = 0; i < ctx.lines.length; i++) {
      if (/(?:\.env|credentials|api[_-]?key|secret|token|password)/i.test(ctx.lines[i])) {
        startLine = i + 1;
        break;
      }
    }
    return [
      {
        startLine,
        endLine: startLine,
        message: "Secret collection combined with outbound sink / encode-to-exfil pattern",
        snippet: ctx.lines[startLine - 1]?.trim().slice(0, 160),
      },
    ];
  },
};

const toolShadowing: Rule = {
  id: "tool-shadowing",
  title: "Cross-tool name shadowing",
  severity: "medium",
  description: "Duplicate MCP server keys or overlapping tool names that can shadow trusted tools.",
  remediation:
    "Rename conflicting MCP servers/tools so each name maps to one trusted implementation. Prefer explicit allowlists over wildcards.",
  kinds: ["mcp_config"],
  test(ctx) {
    const hits: FindingHit[] = [];
    // Duplicate JSON object keys for mcpServers entries (simple scan)
    const serverBlocks = [...ctx.text.matchAll(/"(mcpServers|servers)"\s*:\s*\{/gi)];
    if (serverBlocks.length > 1) {
      hits.push({
        startLine: lineOf(ctx.text, serverBlocks[1].index || 0),
        endLine: lineOf(ctx.text, serverBlocks[1].index || 0),
        message: "Multiple MCP server maps in one config (shadowing risk)",
        snippet: ctx.lines[lineOf(ctx.text, serverBlocks[1].index || 0) - 1]?.trim().slice(0, 160),
      });
    }

    const keyRe = /^\s*"([^"]+)"\s*:\s*\{/gm;
    const names = new Map<string, number[]>();
    // Limit to inside first mcpServers-ish region by scanning all object keys at indent depth
    let m: RegExpExecArray | null;
    while ((m = keyRe.exec(ctx.text)) !== null) {
      const name = m[1];
      if (["mcpServers", "servers", "command", "args", "env", "url", "type", "tools"].includes(name)) continue;
      const line = lineOf(ctx.text, m.index);
      const arr = names.get(name) || [];
      arr.push(line);
      names.set(name, arr);
    }
    for (const [name, lines] of names) {
      if (lines.length < 2) continue;
      hits.push({
        startLine: lines[1],
        endLine: lines[1],
        message: `Duplicate MCP entry name "${name}" (tool shadowing)`,
        snippet: ctx.lines[lines[1] - 1]?.trim().slice(0, 160),
      });
    }
    return hits;
  },
};

export const builtinRules: Rule[] = [
  hiddenUnicode,
  promptInjection,
  hideFromUser,
  credentialExfil,
  hardcodedSecret,
  networkExfil,
  overbroadMcp,
  remoteExec,
  embeddedScriptDanger,
  exfilChain,
  toolShadowing,
];
