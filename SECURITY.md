# Security policy — skill-scan

## What this tool is

`skill-scan` is a **static** heuristic scanner for agent skills, MCP configs, and Cursor rules. It is not antivirus, not a sandbox, and not a guarantee that a skill is safe.

## Report a false positive

If a clean skill/rule is flagged incorrectly:

1. Note `ruleId`, file path, and a minimal snippet.
2. Open a GitHub issue (or email the maintainers listed on the npm package) with **false positive** in the title.
3. Include whether `# skill-scan-ignore` / `.skill-scanignore` is an acceptable workaround for your case.

## Report a missed malicious pattern

If you have a skill that should fail and doesn’t:

1. Share a **redacted** fixture (no real secrets).
2. Describe expected `ruleId` / severity.
3. Mark the issue **missed detection**.

We prioritize high-signal rules that stay low on false positives for common clean skills.

## Disclosure

Do not open public issues that include live credentials or exploit payloads aimed at third parties. Redact and describe.
