# tack-guard

Runtime risk scoring for AI agent tool calls. Catch privilege escalation, baseline deviations, and data exfiltration **inline — under 1ms, zero dependencies, no LLM.**

[![npm version](https://img.shields.io/npm/v/@tacksec/guard)](https://www.npmjs.com/package/@tacksec/guard) [![CI](https://github.com/tacksec/tack-guard/actions/workflows/ci.yml/badge.svg)](https://github.com/tacksec/tack-guard/actions/workflows/ci.yml) ![zero dependencies](https://img.shields.io/badge/dependencies-0-brightgreen) [![minzipped size](https://img.shields.io/bundlephobia/minzip/@tacksec/guard)](https://bundlephobia.com/package/@tacksec/guard) ![latency](https://img.shields.io/badge/evaluate-%3C1ms-blue) ![license](https://img.shields.io/badge/license-MIT-green)

Every tool call your agent makes gets a graded **0→1 risk score** and a verdict (`allow` / `warn` / `deny` / `quarantine`) — computed from a per-agent baseline and stateless attack signatures. Deterministic and explainable: no model, no network, no magic in the hot path.

**Who it's for:** agents on a *susceptible* model (gpt-4o-mini, Llama, Qwen, DeepSeek, Kimi…) that touch *high-impact* tools — exfiltrate, delete, transfer, escalate. tack-guard is a deterministic **behavioral layer**: pair it with a prompt-injection firewall, it doesn't replace one. Early (v0.2) and open source — the protection is real and measured (see [benchmarks](https://tacksec.com/benchmarks)), though its cross-call layer is still validated mainly on our own corpus.

## Install

```bash
npm install @tacksec/guard
```

## Quick start

```typescript
import { createGuard } from '@tacksec/guard'

const guard = createGuard() // advisory by default (mode: 'warn') — observe before you block

// In your agent's tool-execution pipeline:
const call = { action: 'export_all', target: 'user_db.credentials' }
const { score, verdict, summary } = guard.evaluate(call)
// verdict: 'allow' | 'warn' | 'deny' | 'quarantine'   ·   score: 0 → 1
console.log(verdict, score, summary)

// When you trust it, flip to enforcement and gate on `blocked`:
const enforcing = createGuard({ mode: 'enforce' })
if (enforcing.evaluate(call).blocked) {
  // skip the tool call, hand `summary` back to the model
}
```

## No taxonomy homework

The catch with `{ action, target }` is mapping your real tool calls onto it. tack-guard does that for you, so synonyms and casing (`update`, `deleteUser`, `Exfiltrate`, `export_all`) can't slip past a literal string check.

**Infer from a provider tool call** (OpenAI / Anthropic function-calling, Vercel AI SDK, MCP — all `{ name, arguments }`):

```typescript
import { createGuard, inferToolCall } from '@tacksec/guard'

const guard = createGuard()

for (const call of response.tool_calls) {
  const verdict = guard.evaluate(inferToolCall(call)) // action ← tool name, target ← args
  if (verdict.blocked) continue // skip the tool, hand the refusal back to the model
  runTool(call)
}
```

**Or wrap a tool once** and forget about it:

```typescript
const safeQuery = guard.wrapTool(db.query, {
  action: 'read',
  target: (sql: string) => (sql.includes('credentials') ? 'user_db.credentials' : 'db'),
})
await safeQuery('SELECT …') // throws GuardBlockedError (or calls onBlocked) if the guard blocks it
```

## Guard an MCP server

`@tacksec/guard/mcp` wraps an MCP server's tool handler so every exposed tool is scored — **no SDK import, structural typing only:**

```typescript
import { createGuard } from '@tacksec/guard'
import { guardMcpCallTool } from '@tacksec/guard/mcp'

const guard = createGuard({ mode: 'enforce' })

// Wrap the whole call-tool handler — every tool the server exposes is now guarded:
server.setRequestHandler(CallToolRequestSchema, guardMcpCallTool(guard, handleCallTool))
// A blocked call returns an `isError` result to the model instead of executing.
```

`guardMcpTool(guard, name, handler)` guards a single named tool instead of all of them.

## How it works

Two complementary layers run on every call:

1. **Stateless signatures** (memory-independent): catch blatant single-shot attacks — a bulk credential export, a destructive wipe of sensitive data — on call 1, no history needed. Actions are canonicalized, so `Exfiltrate` / `export_all` / `drop_table` all match.
2. **Behavioral scoring** (memory-dependent): track a per-agent baseline and score deviations. This is what catches a slow credential-creep — read-only for days, then a first write, then a reach into sensitive data — where no single call is damning.

The score is the **weighted sum of the signals that fired** (clamped to 0–1) — it grades with the evidence, it is not a hardcoded constant:

| Signal | Weight | What it catches |
|--------|--------|----------------|
| `escalation_trajectory` | 0.25 | Read-only baseline violated, scope grew to sensitive/admin |
| `sensitive_write` | 0.22 | Access to a sensitive target (credentials, PII) |
| `sensitive_egress` | 0.30 | Sensitive data then sent to an untrusted destination — *opt-in via `egressTargets`* |
| `volume_spike` | 0.15 | Call volume ≥ 3× baseline |
| `rapid_burst` | 0.15 | Many calls in a short window (automated burst) — *temporal* |
| `new_write_access` | 0.10 | First mutation after a read-only baseline |
| `after_hours` | 0.08 | Activity outside business hours |
| `admin_attempt` | 0.07 | Admin access or admin target touched |

Detected patterns: **credential-creep** (escalation → sensitive, CRITICAL, reports the escalation time-span), **data-exfiltration** (sensitive access → egress to an untrusted destination, CRITICAL — opt-in via `egressTargets`), **smash-and-grab** (single-shot signature, or a rapid burst), **behavioral-drift** (other anomalies over threshold).

## Detection quality

**Internal corpus** — a *regression gate*, not an efficacy claim: we wrote it and tune the weights against it, so treat it as a floor, not a headline. Run `npm run benchmarks`:

```
cases          : 26 attack / 19 benign
recall         : 88.5%   precision: 100%   FPR: 0%   AUC: 0.951
benign utility : 100%   (enforce mode — no benign work blocked)
```

It includes deliberately **hard cases it gets wrong** (3 of 26 — e.g. a destructive op on an innocuously-named table) — reported as-is, not cooked. See [`eval/`](eval/) and tune `weights` / `detectionThreshold` for your traffic.

**Third-party efficacy — the number that actually counts.** Across [AgentDojo](https://tacksec.com/benchmarks)'s 4 suites (ETH Zürich, gpt-4o-mini), targeted attack-success fell **47% → 27%**. On the workspace exfil scenario, the opt-in sensitive→egress rule blocked the inbox-exfiltration in all 4 runs (**4/4 → 0/4**), inline in ~3µs. The cross-call trajectory scoring is validated on our internal regression corpus; third-party validation of that layer is in progress. A capable model (Claude) largely self-resists, so the value concentrates on susceptible models. Reproduce it yourself with the harness in [`eval/agentdojo/`](eval/agentdojo/); full methodology + per-suite breakdown: **[tacksec.com/benchmarks](https://tacksec.com/benchmarks)**.

**A benchmark we deliberately "lose" — and why we publish it anyway.** On [InjecAgent](https://github.com/uiuc-kang-lab/InjecAgent), tack-guard scores ~0–5% recall ([`eval/RESULTS.md`](eval/RESULTS.md)) — and that's *expected*, not hidden. InjecAgent measures whether an *injected prompt* succeeds; tack-guard scores **behavior** (what the agent did), not prompt *content*, so single-shot prompt-injection is outside its threat model by design. That's exactly why you pair it with a prompt-injection filter — Meta's **Llama Guard / Prompt Guard**, or **Rebuff**: the input filter catches the injected content; tack-guard catches the privilege-escalation / exfiltration *behavior* if something slips through. Two layers, different jobs.

## How it compares

| Property | tack-guard | Other OSS agent guards |
|---|---|---|
| Decision | Graded `0→1` score + verdict | Often binary allow / block |
| Mechanism | Deterministic heuristics + per-agent baseline, **no LLM** | Policy rules, proxies, or an LLM reasoning pass |
| Cross-call behavior | Tracks the escalation trajectory across a session | Varies (many are per-call / per-prompt) |
| Latency | Inline, sync, < 1ms (no model, no network) | Varies (LLM pass or proxy hop) |
| Dependencies | Zero | Varies |

> Some tools go deeper than tack-guard — e.g. LlamaFirewall's AlignmentCheck does LLM-based reasoning-trace analysis. tack-guard trades that depth for determinism, sub-millisecond latency, and zero dependencies. It is a fast first line, not a replacement for defense in depth.

> tack-guard is a narrow, deterministic, JS-native guard that complements policy/identity platforms like Microsoft's Agent Governance Toolkit — not a replacement for one.

## API

### `createGuard(config?)`

```typescript
const guard = createGuard({
  sensitiveTargets: ['payments', 'api_keys', 'credentials'], // string[] or (target) => boolean
  egressTargets: ['mycorp.com'],  // opt-in allowlist of trusted egress destinations (string[] or predicate)
  businessHours: [9, 18],         // [start, end) — default [9, 18)
  mode: 'warn',                   // "warn" (default, advisory) | "enforce" | "score-only"
  baselineMin: 5,                 // calls before a baseline is established
  detectionThreshold: 0.5,        // score below this = no detection
  weights: { rapid_burst: 0.2 },  // partial override of signal weights
})
```

### `guard.evaluate(call)` → `GuardResult`

```typescript
const result = guard.evaluate({
  action: 'update_row',        // any string — canonicalized internally
  target: 'user_db.accounts',  // what it's touching
  agentId: 'sales-bot',        // optional, default "default"
  hour: 14,                    // optional, default current hour (after-hours signal)
  at: Date.now(),              // optional epoch ms, default now (temporal signals)
})

// {
//   verdict: 'quarantine', score: 0.57, severity: 'CRITICAL',
//   pattern: 'credential-creep',
//   signals: { escalation_trajectory: true, sensitive_write: true, ... },
//   evidence: ['1 mutation(s) after a read-only baseline',
//              'access to sensitive target: user_db.accounts',
//              'trajectory: read-only -> mutate -> sensitive/admin over 3d'],
//   summary: 'Agent escalated from read-only to sensitive/admin access. Credential-creep detected.',
//   quarantined: true, blocked: true,
// }
```

### `guard.evaluateAsync(call)`

Same as `evaluate()`, but `await`s an asynchronous `MemoryClient` (Redis, a network DB, a cloud store). Scoring stays synchronous and local — only the memory I/O is awaited. `evaluate()` throws on an async client rather than silently degrading.

### `guard.wrapTool(fn, opts)`

Wrap a tool so every call is evaluated first; blocked calls don't run (`onBlocked` runs, or a `GuardBlockedError` is thrown). `action`/`target` can be static or functions of the args. Synchronous (needs a sync `MemoryClient`); a blocked call **throws synchronously** (not a rejected promise) — use `try/catch`, not `.catch()`, when wrapping async tools.

### `inferToolCall(rawToolCall, overrides?)`

Map a provider `{ name, arguments }` tool call to a `ToolCall`. Action ← tool name (canonicalized), target ← arguments. Override either explicitly.

### `guard.connect(apiKey)` *(reserved — not implemented)*

Reserved hook for a future hosted persistence backend; it currently **throws**. For persistent or cross-session baselines today, implement a custom [`MemoryClient`](#custom-memory) and plug it in with `guard.setMemory()`.

### `guard.reset(agentId?)` · `guard.setMemory(client)` · `guard.getAgentState(agentId)`

Clear state, plug in a custom backend, inspect an agent.

## Modes

| Mode | Behavior |
|------|----------|
| `warn` (default) | Reports threats + verdict, never blocks — observe first, then enforce |
| `enforce` | Quarantines on CRITICAL / signature; blocks risky calls while quarantined |
| `score-only` | Always allows, just returns the score |

The default is **advisory** on purpose: drop it in, watch what it flags on your real traffic, then switch to `enforce` once you trust the verdicts.

## Custom memory

Implement the four-method `MemoryClient` interface. **Synchronous** backends (in-process cache, `better-sqlite3`) use `evaluate()`; **async** backends (Redis, a network DB) use `evaluateAsync()`:

```typescript
import { createGuard, type MemoryClient } from '@tacksec/guard'

class RedisMemory implements MemoryClient {
  async push(agentId, event) { /* ... */ }
  async getEvents(agentId) { /* returns Promise<StoredEvent[]> */ }
  async clear(agentId) { /* ... */ }
  async clearAll() { /* ... */ }
}

const guard = createGuard()
guard.setMemory(new RedisMemory())
await guard.evaluateAsync({ action: 'write', target: 'users' })
```

The default in-memory client loses baselines on restart — by design. For persistence across restarts or sessions, back a `MemoryClient` with your own store (Redis, SQLite, a network DB) and plug it in with `guard.setMemory()`.

## Limitations & threat model

tack-guard **advises**; your pipeline **enforces** (it returns a verdict — you must actually skip the blocked tool call). It is a fast heuristic layer, not a complete defense. Known limits, by design:

- **Sensitivity is name-based.** Targets are matched by substring (or your `sensitiveTargets`), so a destructive op on an innocuously-named table can be missed, and a benign write to a `user_db.*` table can over-flag. Pass a `sensitiveTargets` predicate for precision.
- **Behavioral detection needs a read-only baseline.** An agent that mutates from call 1 has no "normal" to deviate from; it relies on the signature layer.
- **Single session only.** Baselines live in memory and reset on restart; multi-day / cross-session persistence is your `MemoryClient`'s job (`guard.setMemory()`).
- **Not a prompt-injection filter.** It scores *behavior* (what the agent did), not prompt content. Use it alongside input/output guards.

See [`docs/architecture.md`](docs/architecture.md) for the full model.

## License

MIT — see [LICENSE](LICENSE).

---

[Changelog](CHANGELOG.md) · [Security policy](SECURITY.md) · [Architecture](docs/architecture.md) · [Examples](examples/) · [Contributing](CONTRIBUTING.md)
