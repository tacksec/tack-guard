# ADR-0001: Zero runtime dependencies

**Status:** Accepted
**Date:** 2026-06-15
**Decider:** Damien Aubry

## Context

tack-guard is a security product that sits in the critical path of AI agent tool calls. Any dependency we ship becomes part of our users' attack surface.

## Decision

Zero runtime dependencies. The `dependencies` field in `package.json` stays empty. Only `devDependencies` for build tooling (tsup, vitest, typescript).

## Consequences

- **Good:** No supply-chain risk. No transitive vulnerabilities. Tiny bundle size (~16 KB ESM / ~18 KB CJS, unminified; well under the < 50 KB minified target).
- **Good:** Works in any JS runtime (Node, Deno, Bun, CF Workers, browsers) without polyfills.
- **Bad:** Can't use convenience libraries (lodash, zod, etc.). Must implement everything ourselves.
- **Acceptable:** The scoring logic is simple math. We don't need libraries for it.

## Rejected alternatives

| Alternative | Why rejected |
|---|---|
| Allow vetted deps (e.g., zod) | Even vetted deps have transitive deps. One npm audit finding in tack-guard = credibility hit for a security product. |
| Bundle deps at build time | Hides the dep from users but doesn't eliminate the risk. |

## When to revisit

If we need crypto primitives (e.g., for API key hashing in `connect()`), consider vendoring a single well-audited function rather than adding a dep.
