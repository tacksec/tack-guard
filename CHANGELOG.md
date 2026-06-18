# Changelog

All notable changes to this project are documented here. The format is based on
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project
adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.2.0] - 2026-06-17

### Changed

- **Default mode is now `warn` (advisory), not `enforce`.** Dropping the guard in no longer blocks anything until you opt into `mode: 'enforce'` — observe what it flags on your real traffic first, then enforce. The API is unchanged; only the default behavior is.
- **Narrowed the default sensitive-target set** to unambiguous secrets (`credential`, `secret`, `password`, `api_key`, `private_key`, `token`, `ssn`, …). It no longer treats every `user_db.*` target as sensitive. Pass `sensitiveTargets` to widen it.
- Confidence is now a graded, clamped weighted sum — the `CREDENTIAL_CREEP_FLOOR` / `FULL_CREEP_FLOOR` constants were removed so the score varies with evidence (severity still carries enforcement).
- Behavioral `smash-and-grab` is now reachable via `rapid_burst` (not only the stateless signature).

### Added

- **MCP wrapper** (`@tacksec/guard/mcp`, new `./mcp` export): `guardMcpCallTool(guard, handler)` guards every tool an MCP server exposes; `guardMcpTool(guard, name, handler)` guards a single one. Structural typing — zero SDK import; a blocked call returns an `isError` result to the model.
- **Action canonicalization** (`canonicalizeAction`): synonyms, casing, and composite tool names ("update_row", "Exfiltrate", "export_all", "drop_table") fold to a canonical risk class — detection no longer hinges on the literal string "write". Money-movement verbs (`transfer` / `wire` / `remit`) and exfil synonyms (`exfil` / `siphon` / `smuggle`) now canonicalize too.
- **Framework adapters**: `inferToolCall({ name, arguments })` maps a provider tool call (OpenAI/Anthropic/Vercel AI SDK/MCP shape) to a `ToolCall`; `guard.wrapTool(fn, opts)` guards a tool function (throws `GuardBlockedError` or calls `onBlocked`).
- **Temporal scoring**: a `rapid_burst` signal (many calls in a short window) and an escalation time-span in the credential-creep evidence, using a new optional `at` (epoch ms) on `ToolCall`.
- **Egress / data-exfiltration detection** (opt-in): a `sensitive_egress` signal and a new `data-exfiltration` pattern catch the canonical exfil flow — a sensitive target is accessed, then an egress action (`send` / `upload` / `post` / …) targets a destination outside the `egressTargets` allowlist. Dormant unless `egressTargets` is configured (no destination guessing → no false positives by default).
- **Eval / benchmarks / latency harness**: `npm run benchmarks` reports recall / precision / FPR / AUC plus `benign_utility` (benign work that survives enforcement) on the internal corpus, validated against third-party **AgentDojo** and InjecAgent; `npm run latency` profiles per-call overhead (~3µs typical p99).

### Fixed

- **False-positive foot-gun**: benign writes to `user_db.*` targets (e.g. `user_db.preferences`) were flagged as credential-creep because the default sensitivity matched the whole prefix. Narrowing the defaults took the internal-corpus FPR from 5.6% → 0% and precision to 100%.
- **Egress noun ambiguity**: mailbox operations like `delete_email` were misread as data-exfiltration because `email` / `mail` were treated as egress verbs. They now count as egress only as a leading verb (`email_to`, `send_mail`), not as a noun target.

## [0.1.0] - 2026-06-15

### Added

- Initial release: zero-dependency runtime risk scoring for AI agent tool calls.
- `createGuard(config?)` factory with `enforce` / `warn` / `score-only` modes.
- Behavioral scoring engine: weighted signals with a per-agent baseline.
- Stateless signature layer: single-shot exfiltration / destructive-wipe detection.
- Attack-pattern classification: `credential-creep`, `smash-and-grab`, `behavioral-drift`.
- `guard.evaluate()` (synchronous, < 1ms) and `guard.evaluateAsync()` for async memory clients.
- Pluggable `MemoryClient` interface with a default in-memory client; `guard.setMemory()`.
- `guard.connect(apiKey)` API surface (reserved hook — not implemented, throws).
- Dual ESM + CJS builds with TypeScript declaration files.

[Unreleased]: https://github.com/tacksec/tack-guard/compare/v0.2.0...HEAD
[0.2.0]: https://github.com/tacksec/tack-guard/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/tacksec/tack-guard/releases/tag/v0.1.0
