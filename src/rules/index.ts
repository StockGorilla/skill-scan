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
    // bidi, zero-width, BOM-ish controls (exclude normal \t \n \r)
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
      /\b(ignore(?:\s+all)?(?:\s+previous|\s+prior|\s+above)?\s+instructions?|disregard(?:\s+all)?\s+(?:previous|prior|safety)|override(?:\s+system)?\s+prompt|you\s+are\s+now\s+unrestricted|jailbreak)\b/i,
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
      /\b(do\s+not\s+tell\s+the\s+user|don't\s+tell\s+the\s+user|hide\s+this\s+from\s+(the\s+)?(user|human)|without\s+(the\s+)?user'?s?\s+knowledge|auto-?approve\s+without)\b/i,
      "Concealment / auto-approve without human"
    );
  },
};

const credentialExfil: Rule = {
  id: "credential-exfil",
  title: "Credential or secret exfiltration",
  severity: "critical",
  description: "Reads secrets or sends credentials to external endpoints.",
  remediation: "Never instruct agents to read or transmit raw credentials; use proper secret managers.",
  test(ctx) {
    const patterns = [
      /\b(cat|type|Get-Content)\s+[^\n]*(?:\.env|credentials|id_rsa|\.aws\/credentials|secrets?\.(json|ya?ml))/i,
      /\b(exfiltrate|steal)\s+(secrets?|credentials?|api\s*keys?|tokens?)\b/i,
      /\b(curl|wget|fetch)\b[^\n]*(api[_-]?key|password|token|authorization)\b/i,
      /https?:\/\/(?:webhook\.site|requestbin\.|ngrok\.|pipedream\.net)/i,
    ];
    return patterns.flatMap((re) => hitsFromRegex(ctx, re, "Possible secret handling / exfil sink"));
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
    // dangerous default patterns in text form
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
    return hitsFromRegex(
      ctx,
      /\b(curl|wget)\b[^\n]{0,80}\|\s*(?:ba)?sh\b/i,
      "Remote content piped to shell"
    );
  },
};

export const builtinRules: Rule[] = [
  hiddenUnicode,
  promptInjection,
  hideFromUser,
  credentialExfil,
  overbroadMcp,
  remoteExec,
];
