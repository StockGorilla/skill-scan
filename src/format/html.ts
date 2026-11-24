import type { ScanResult } from "../types.js";

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
        <td>${esc(f.message)}${f.snippet ? `<div class="snip">${esc(f.snippet)}</div>` : ""}</td>
      </tr>`
    )
    .join("");

  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>skill-scan report</title>
  <style>
    :root { --ink:#0a0a0a; --muted:#6b6b6b; --line:#e5e5e5; --navy:#0c1b3a; --signal:#1aa6a8; --deny:#b42318; }
    body { font-family: ui-sans-serif, system-ui, sans-serif; margin:0; color:var(--ink); background:#f7f7f8; }
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
    code { font-family: ui-monospace, monospace; font-size:0.82rem; }
    footer { margin-top: 1.5rem; color: var(--muted); font-size: 0.8rem; }
    footer a { color: var(--signal); }
  </style>
</head>
<body>
  <main>
    <h1>skill-scan report</h1>
    <p class="meta">${result.targets.length} files · ${result.findings.length} findings · ${result.durationMs}ms · ${esc(result.scannedAt)}</p>
    ${
      result.findings.length
        ? `<table><thead><tr><th>Severity</th><th>Rule</th><th>Location</th><th>Message</th></tr></thead><tbody>${rows}</tbody></table>`
        : `<p>No findings.</p>`
    }
    <footer>
      Part of the <a href="https://toolpause.netlify.app/#suite">ToolFence</a> suite — Scan · Gate · Radar.
    </footer>
  </main>
</body>
</html>`;
}
