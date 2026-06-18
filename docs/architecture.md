# Architecture -- tack-guard scoring model

> Deep-dive into how tack-guard detects threats. Read MEMORY.md for constants and thresholds.

---

## Overview

tack-guard has two detection layers that complement each other:

```
  Tool call arrives
       │
       ▼
  ┌─────────────────────────┐
  │  Stateless signatures   │  Memory-INDEPENDENT
  │  (signatures.ts)        │  Catches blatant single-shot attacks
  │                         │  e.g., bulk_export credentials
  └────────────┬────────────┘
       │ no match
       ▼
  ┌─────────────────────────┐
  │  Behavioral scoring     │  Memory-DEPENDENT
  │  (score.ts)             │  Builds baseline, catches deviations
  │                         │  e.g., read-only agent starts writing
  └────────────┬────────────┘
       │
       ▼
  ┌─────────────────────────┐
  │  Guard policy           │  Combines both, applies mode
  │  (guard.ts)             │  Returns verdict + score
  └─────────────────────────┘
```

---

## Layer 1: Stateless signatures

**File:** `src/signatures.ts`

Per-call rules that need no history. The action is canonicalized first (`src/actions.ts`), so casing and synonyms are handled (`Exfiltrate`, `export_all`, `drop_table` all match):

| Canonical action | Trigger condition | Severity |
|---|---|---|
| `exfiltrate` (export / dump / bulk_export / scrape / leak …) | + sensitive target | CRITICAL |
| `destroy` (drop / wipe / delete_all / truncate / purge …) | + sensitive target | CRITICAL |

**Key property:** fires on the very first call if it matches. No baseline needed. This is the safety net for the "smash-and-grab" attack pattern where the agent tries one devastating action. (It still requires the *target* to look sensitive — see "Detection reachability".)

**Latch behavior:** once a signature fires, the agent is quarantined for the rest of the guard instance's lifetime. This survives even if behavioral scoring is reset.

---

## Layer 2: Behavioral scoring

**File:** `src/score.ts`

Scores a growing stream of events against a per-agent baseline. Actions are canonicalized (so `update`/`delete`/`patch` count as mutations, not just the literal "write"). The model:

### Phase 1: Baseline establishment

The first `BASELINE_MIN` (default: 5) calls are recorded but not scored. During this phase, `evaluate()` returns `score: 0` with summary "establishing baseline".

The baseline captures one key property: **was the agent read-only?** This determines whether the mutation / escalation signals are meaningful.

### Phase 2: Signal evaluation

After baseline, each call triggers a rescore of ALL accumulated events. Eight boolean signals are evaluated (`mutations` = canonical write/admin/exfiltrate/destroy):

```
escalation_trajectory = baselineReadOnly AND mutations > 0 AND (sensitive > 0 OR admin > 0)
sensitive_write       = any event targets a sensitive resource
sensitive_egress      = (opt-in) a sensitive access, then an egress (send/upload/…) to a destination outside egressTargets
volume_spike          = total events >= BASELINE_MIN * 3
rapid_burst           = >= RAPID_BURST_MIN events within RAPID_BURST_WINDOW_MS  (temporal)
new_write_access      = baselineReadOnly AND mutations > 0
after_hours           = any event outside business hours
admin_attempt         = any event involves admin access
```

### Phase 3: Confidence calculation

Confidence is the weighted sum of fired signals, clamped to [0, 1]:
```
confidence = clamp01( sum(weight[signal] for signal in fired_signals) )
```

There are **no constant floors** — the score grades with evidence. A bare
read→write→sensitive escalation scores ~0.57; an admin probe, after-hours
timing, or a rapid burst each push it higher. If confidence < `DETECTION_THRESHOLD`
(0.5): no detection, "within baseline".

### Phase 4: Pattern classification

| Pattern | Trigger |
|---|---|
| `data-exfiltration` | sensitive_egress (sensitive access → egress to a destination outside `egressTargets`) |
| `credential-creep` | escalation_trajectory AND sensitive_write |
| `smash-and-grab` | (rapid_burst OR volume_spike) AND NOT escalation_trajectory |
| `behavioral-drift` | anything else above threshold |

The credential-creep evidence also reports the **time-span** of the escalation
(from the event timestamps), e.g. "over 3d".

### Phase 5: Severity

| Severity | When |
|---|---|
| CRITICAL | credential-creep or data-exfiltration detected |
| HIGH | confidence >= 0.6, not credential-creep |
| MEDIUM | confidence >= 0.5, < 0.6 |

---

## Guard policy (guard.ts)

The guard wraps scoring with state management and enforcement:

### Quarantine

Quarantine = `signatureTripped OR (behavioral.severity === CRITICAL)`.

Recomputed on every call (never stuck latched from behavioral scoring alone). If behavioral scoring drops below CRITICAL (hypothetically), quarantine lifts. Signature latch is permanent.

### Verdict policy by mode

| Mode | On detection | On quarantine + risky call |
|---|---|---|
| `warn` (default) | warn | warn (not blocked) |
| `enforce` | warn | quarantine (blocked) |
| `score-only` | allow | allow (not blocked) |

A "risky call" = write, admin_access, sensitive target, or admin target.

### Multi-agent isolation

Each `agentId` has independent state (events, quarantine, signature latch). Agent A being quarantined does not affect Agent B.

---

## Memory architecture

```
  guard.evaluate()
       │
       ├──▶ memory.push(agentId, event)     // store
       ├──▶ memory.getEvents(agentId)        // recall for scoring
       │
       ▼
  ┌─────────────────────────┐
  │  MemoryClient interface │
  ├─────────────────────────┤
  │  InMemoryClient         │  Default: Map<string, Event[]>
  │  (lost on restart)      │  Single-session, zero config
  ├─────────────────────────┤
  │  Custom (user-provided) │  guard.setMemory(new RedisMemory())
  │  Implement 4 methods    │  push, getEvents, clear, clearAll
  └─────────────────────────┘
```

### Sync vs async clients

`MemoryClient` methods may return either a value or a `Promise`. The default `InMemoryClient` is synchronous, so `guard.evaluate()` stays synchronous and < 1ms.

If you plug in an **async** client (Redis, a network DB), call `guard.evaluateAsync()` — it awaits `push`/`getEvents`, then runs the identical scoring/verdict logic. The synchronous `evaluate()` deliberately **throws** on an async client rather than silently skipping the behavioral layer (which would degrade detection to signatures-only without telling you).

---

## Detection reachability (honest limits)

The scoring model is deliberately conservative — a security tool's credibility dies on false positives. Things worth knowing (see `npm run eval` for measured precision/recall, including the cases below):

1. **Sensitivity is name-based.** A target is "sensitive" by substring match (or your `sensitiveTargets`). So a destructive op on an innocuously-named table (`drop production_database`) is **missed** by the signature layer, and a benign write to a `user_db.*` table can **over-flag**. Pass a `sensitiveTargets` predicate to tighten this.

2. **The behavioral layer needs a read-only baseline.** `escalation_trajectory` (0.25) and `new_write_access` (0.10) only fire if the first `baselineMin` calls were all reads. An agent that mutates from call 1 has no read-only norm to deviate from, so a single later sensitive write only reaches `sensitive_write` (0.22) and stays under threshold. This is by design (it relies on the signature layer for blatant cases), but it is a real gap for write-baseline agents.

3. **A pure volume spike still doesn't auto-block.** `volume_spike` (0.15) + `after_hours` (0.08) = 0.23, under 0.5. But a **rapid burst** (the temporal `rapid_burst`, 0.15) of sensitive access *can* cross the threshold and classify as a behavioral `smash-and-grab` — e.g. `rapid_burst` + `volume_spike` + `sensitive_write` = 0.52. The blatant single-shot smash-and-grab is still caught immediately by the stateless signature layer.

4. **Egress detection is opt-in and destination-based.** The `sensitive_egress` signal (pattern `data-exfiltration`) only fires when `egressTargets` is configured — tack-guard never guesses whether a destination is "external", so there are **no egress false positives by default**. The destination is the egress call's `target` (a recipient / URL), so the integration must surface it (`inferToolCall` pulls it from the args). Limitation: an agent that legitimately sends sensitive data to non-enumerable destinations (e.g. emailing each customer their own data) can't be covered by a simple allowlist — use `mode: 'warn'` there.

To trade precision for sensitivity, tune `weights` / `detectionThreshold`. The default posture favors precision.

---

## Scaling

`score()` rescans the agent's **entire** event history on every call (it filters writes / sensitive / admin / after-hours and inspects the baseline window). That is O(history) per `evaluate()`.

- For typical agent sessions (hundreds to a few thousand calls) this is microseconds — comfortably < 1ms.
- For very long-running, never-reset sessions the per-call cost grows linearly and the `InMemoryClient` array grows unbounded. Bounding/windowing history is a responsibility of custom `MemoryClient` implementations, which can cap or roll up events. The core stays simple and exact.
