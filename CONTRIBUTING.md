# Contributing to skill-scan

## Add a rule

1. Open `src/rules/index.ts`.
2. Add a `Rule` with `id`, `title`, `severity`, `description`, `remediation`, and `test(ctx)`.
3. Export it from the `rules` array.
4. Add a fixture under `fixtures/` that must trigger the rule (and keep `fixtures/clean-skill` clean).
5. Run `npm test` — fixture scan must find issues and exit `1`.

### Rule shape

```ts
const myRule: Rule = {
  id: "my-rule-id",
  title: "Short title",
  severity: "high", // critical | high | medium | low | info
  description: "What this means for an operator.",
  remediation: "What to change.",
  test(ctx) {
    // return FindingHit[] using ctx.text / ctx.lines / ctx.path
    return [];
  },
};
```

Prefer specific patterns over broad keywords. Document the new `ruleId` in `RULES.md`.

## Dev loop

```bash
npm install
npm run build
node dist/cli.js fixtures --format text
npm test
```

## Scope

This package is a **static** pre-install scanner. Please don’t PR dynamic MCP execution, full AV engines, or Inbox UI work here — that belongs in Gate / Radar.
