import type { ScanResult } from "../types.js";

const GATE_URL = "https://toolpause.fly.dev/";
const DOCS_URL = "https://toolpause.netlify.app/docs/scan-then-gate";
const SCAN_URL = "https://toolpause.netlify.app/scan";
const NPM_URL = "https://www.npmjs.com/package/toolfence-scan";

function esc(s: string): string {
  return s
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;");
}

export function formatHtml(result: ScanResult): string {
  const rows = result.findings
    .map(
      (f) => `
      <tr class="sev-${esc(f.severity)}">
        <td><span class="pill">${esc(f.severity)}</span></td>
        <td><code>${esc(f.ruleId)}</code></td>
        <td>${esc(f.path)}:${f.startLine}</td>
        <td>${esc(f.message)}${f.snippet ? `<div class="snip">${esc(f.snippet)}</div>` : ""}${
          f.remediation ? `<div class="fix"><strong>Fix:</strong> ${esc(f.remediation)}</div>` : ""
        }</td>
      </tr>`
    )
    .join("");

  const hasFindings = result.findings.length > 0;

  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>toolfence-scan report</title>
  <style>
    :root { --ink:#0a0a0a; --muted:#6b6b6b; --line:#e5e5e5; --navy:#0c1b3a; --signal:#0f9ea1; --deny:#b42318; --wash:#f7f7f8; }
    body { font-family: ui-sans-serif, system-ui, sans-serif; margin:0; color:var(--ink); background:var(--wash); }
    main { max-width: 960px; margin: 0 auto; padding: 2rem 1.25rem 3rem; }
    h1 { font-size: 1.5rem; letter-spacing: -0.03em; color: var(--navy); margin: 0 0 0.35rem; }
    .meta { color: var(--muted); font-size: 0.9rem; margin-bottom: 1.5rem; }
    table { width: 100%; border-collapse: collapse; background:#fff; border:1px solid var(--line); border-radius: 12px; overflow:hidden; }
    th, td { text-align:left; padding: 0.75rem 0.85rem; border-bottom:1px solid var(--line); vertical-align:top; font-size:0.9rem; }
    th { background:#fafafa; font-size:0.75rem; text-transform:uppercase; letter-spacing:0.06em; color:var(--muted); }
    .pill { display:inline-block; padding:0.15rem 0.5rem; border-radius:999px; font-size:0.72rem; font-weight:700; text-transform:uppercase; background:#eee; }
    .sev-critical .pill, .sev-high .pill { background:#fdecea; color:var(--deny); }
    .sev-medium .pill { background:#fff4d6; color:#9a6700; }
    .snip { margin-top:0.35rem; font-family: ui-monospace, monospace; font-size:0.78rem; color:var(--muted); }
    .fix { margin-top:0.4rem; font-size:0.82rem; color:var(--navy); }
    code { font-family: ui-monospace, monospace; font-size:0.82rem; }
    .cta {
      margin: 1.75rem 0 0;
      padding: 1.15rem 1.25rem;
      border-radius: 12px;
      background: var(--navy);
      color: #c8d4e4;
    }
    .cta h2 { margin: 0 0 0.4rem; font-size: 1.05rem; color: #fff; letter-spacing: -0.02em; }
    .cta p { margin: 0 0 0.75rem; font-size: 0.9rem; line-height: 1.45; }
    .cta pre {
      margin: 0 0 0.85rem; padding: 0.65rem 0.75rem; border-radius: 8px;
      background: rgba(0,0,0,0.35); color: #fff; font-size: 0.78rem; overflow-x: auto;
    }
    .cta .row { display: flex; flex-wrap: wrap; gap: 0.5rem; }
    .cta a.btn {
      display: inline-flex; align-items: center; padding: 0.45rem 0.85rem; border-radius: 999px;
      background: var(--signal); color: #fff; font-weight: 650; font-size: 0.85rem; text-decoration: none;
    }
    .cta a.ghost {
      display: inline-flex; align-items: center; padding: 0.45rem 0.85rem; border-radius: 999px;
      border: 1px solid rgba(255,255,255,0.25); color: #fff; font-weight: 600; font-size: 0.85rem; text-decoration: none;
    }
    footer { margin-top: 1.5rem; color: var(--muted); font-size: 0.8rem; }
    footer a { color: var(--signal); }
  </style>
</head>
<body>
  <main>
    <h1>toolfence-scan report</h1>
    <p class="meta">${result.targets.length} files · ${result.findings.length} findings · ${result.durationMs}ms · ${esc(result.scannedAt)}</p>
    ${
      hasFindings
        ? `<table><thead><tr><th>Severity</th><th>Rule</th><th>Location</th><th>Message</th></tr></thead><tbody>${rows}</tbody></table>`
        : `<p>No findings.</p>`
    }
    <section class="cta">
      <h2>${hasFindings ? "Next: Gate what can still hurt you" : "Stay gated at runtime"}</h2>
      <p>${
        hasFindings
          ? "Turn these findings into ToolFence Gate Rules (deny / require approval), then pause high-impact tool calls in Inbox or Slack."
          : "Scan was clean. Still wrap high-impact tools with ToolFence Gate so runtime actions stay bound and fail-closed."
      }</p>
      ${
        hasFindings
          ? `<pre>npx toolfence-scan . --emit-gate-rules --output gate-rules.json</pre>`
          : ""
      }
      <div class="row">
        <a class="btn" href="${GATE_URL}">Open Gate</a>
        <a class="ghost" href="${DOCS_URL}">Scan → Gate guide</a>
        <a class="ghost" href="${SCAN_URL}">Scan product</a>
        <a class="ghost" href="${NPM_URL}">npm</a>
      </div>
    </section>
    <footer>
      Part of the <a href="https://toolpause.netlify.app/#suite">ToolFence</a> suite — Scan · Gate · Radar.
    </footer>
  </main>
</body>
</html>`;
}
