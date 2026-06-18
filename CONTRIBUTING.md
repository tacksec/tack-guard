# Contributing to tack-guard

Thanks for helping make agents safer. tack-guard is small, deterministic, and dependency-free **on purpose** — contributions are very welcome as long as they keep it that way.

## Found a vulnerability or a detection bypass?

**Do not open a public issue or PR.** Follow [SECURITY.md](SECURITY.md) — use GitHub's private vulnerability reporting or email security@tacksec.com.

## Dev setup

```bash
npm ci
npm test            # vitest — all tests
npm run build       # tsup — ESM + CJS + types
npm run lint        # tsc typecheck (src + tests)
npm run benchmarks  # regenerate eval/RESULTS.md
```

Node >= 18.

## The two non-negotiables

1. **Zero runtime dependencies.** Nothing in `src/` may import from `node_modules` (dev deps are fine). See [ADR-0001](docs/decisions/0001-zero-dependencies.md).
2. **`evaluate()` stays synchronous and under ~1ms.** No network, no async, no allocation-heavy work in the hot path. See [docs/architecture.md](docs/architecture.md).

Also: no `any`, no `@ts-ignore`. If you can't type it, rethink the design.

## Changing a detection rule

A scoring or signature change isn't done until it's measured:

- Add at least one **triggering** and one **non-triggering** case to the [`eval/`](eval/) corpus.
- Run `npm run benchmarks` and include the before/after in your PR. A rule that raises recall must **not** regress FPR or benign-utility.

## Pull requests

- One logical change per PR; keep it focused.
- `npm test` and `npm run lint` pass.
- Add an entry under `[Unreleased]` in [CHANGELOG.md](CHANGELOG.md).
- Add or update tests for any behavior change.

By contributing, you agree your work is licensed under the project's [MIT License](LICENSE).
