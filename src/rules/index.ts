import type { FindingHit, Rule, RuleContext } from "../types.js";

function lineOf(text: string, index: number): number {
  return text.slice(0, index).split(/\r?\n/).length;
}

function hitsFromRegex(ctx: RuleContext, re: RegExp, message?: string): FindingHit[] {
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
  remediation: "Never instruct agents to read or transmit raw credentials; use proper secret managers.",
  test(ctx) {
    const patterns = [
      /\b(cat|type|Get-Content|print|read)\s+[^\n]*(?:\.env|credentials|id_rsa|\.aws\/credentials|secrets?\.(json|ya?ml)|\/etc\/shadow)/i,
      /\b(exfiltrate|steal)\s+(secrets?|credentials?|api\s*keys?|tokens?)\b/i,
      /\b(curl|wget|fetch|Invoke-WebRequest)\b[^\n]*(api[_-]?key|password|token|authorization|secret)\b/i,
      /\bsend\s+(?:the\s+)?(?:secrets?|credentials?|api\s*keys?|tokens?)\s+to\b/i,
    ];
    return patterns.flatMap((re) => hitsFromRegex(ctx, re, "Possible secret handling / exfil sink"));
  },
};

const hardcodedSecret: Rule = {
  id: "hardcoded-secret",
  title: "Hardcoded secret or API key",
  severity: "critical",
  description: "Likely embedded credentials (AWS, GitHub, OpenAI, Slack, private keys).",
  remediation: "Remove secrets from skills/instructions; use env vars or a secret manager.",
  test(ctx) {
    const patterns: Array<[RegExp, string]> = [
      [/\bAKIA[0-9A-Z]{16}\b/, "Possible AWS access key id"],
      [/\b(?:sk|rk)-[a-zA-Z0-9_-]{20,}\b/, "Possible OpenAI/Stripe-style secret key"],
      [/\bghp_[A-Za-z0-9]{20,}\b/, "Possible GitHub personal access token"],
      [/\bgithub_pat_[A-Za-z0-9_]{20,}\b/, "Possible GitHub fine-grained PAT"],
      [/\bxox[baprs]-[A-Za-z0-9-]{10,}\b/, "Possible Slack token"],
      [/\bAIza[0-9A-Za-z\-_]{20,}\b/, "Possible Google API key"],
      [/-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----/, "Embedded private key block"],
    ];
    return patterns.flatMap(([re, msg]) => hitsFromRegex(ctx, re, msg));
  },
};

const networkExfil: Rule = {
  id: "network-exfil",
  title: "Suspicious network exfil sink",
  severity: "high",
  description: "Calls out to paste/callback/tunnel hosts or raw IP URLs often used for exfiltration.",
  remediation: "Remove unexpected callback URLs; allowlist only trusted HTTPS endpoints.",
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
  remediation: "Scope MCP servers to least privilege; avoid * tools and root filesystem mounts.",
  kinds: ["mcp_config"],
  test(ctx) {
    const hits: FindingHit[] = [];
    hits.push(
      ...hitsFromRegex(
        ctx,
        /"(?:command|args)"\s*:\s*\[[^\]]*(?:\/bin\/(?:ba)?sh|powershell|cmd\.exe)/i,
        "Shell-capable MCP command"
      )
    );
    hits.push(
      ...hitsFromRegex(
        ctx,
        /"(?:args|roots?|path)"\s*:\s*(?:"\/"|\[\s*"\/"\s*\])/,
        "Filesystem root access"
      )
    );
    hits.push(
      ...hitsFromRegex(ctx, /"tools?"\s*:\s*(?:"\*"|\["\*"\])/, "Wildcard tools allowed")
    );
    hits.push(
      ...hitsFromRegex(
        ctx,
        /\b(?:alwaysAllow|autoApprove)\b[^\n]{0,40}\btrue\b/i,
        "Auto-approve enabled in MCP config"
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
  remediation: "Avoid remote pipe-to-shell in skills; pin and review scripts instead.",
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

export const builtinRules: Rule[] = [
  hiddenUnicode,
  promptInjection,
  hideFromUser,
  credentialExfil,
  hardcodedSecret,
  networkExfil,
  overbroadMcp,
  remoteExec,
];
