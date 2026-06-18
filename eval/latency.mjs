/**
 * Latency micro-benchmark for guard.evaluate() — the <1ms inline claim.
 *
 *   npm run build && node eval/latency.mjs
 *
 * evaluate() is synchronous, zero network. We time it (a) in a typical session
 * (fresh guard, ~20-call stream — the per-call latency a dev actually sees) and
 * (b) with a large accumulated history (worst case for the O(n) behavioral passes).
 * Reported as p50/p95/p99 over many samples; deterministic timestamps so the
 * result doesn't depend on wall-clock.
 */
import { createGuard } from "../dist/index.js";

const pct = (arr, p) => {
  const s = arr.slice().sort((a, b) => a - b);
  return s[Math.min(s.length - 1, Math.floor((p / 100) * s.length))];
};
const fmt = (ms) => (ms < 0.001 ? `${(ms * 1000).toFixed(1)}µs` : `${ms.toFixed(4)}ms`);
const report = (label, times) => {
  console.log(`  ${label}`);
  console.log(
    `    n=${times.length}  p50 ${fmt(pct(times, 50))}  p95 ${fmt(pct(times, 95))}  ` +
      `p99 ${fmt(pct(times, 99))}  max ${fmt(Math.max(...times))}`,
  );
};

console.log("\ntack-guard — evaluate() latency (single core, warm dist)\n");

// ── Scenario 1: typical session — fresh guard, 20-call stream, per-call timing ──
{
  const calls = [
    { action: "read", target: "customers" },
    { action: "write", target: "orders" },
    { action: "read", target: "user_db.profile" },
    { action: "send", target: "ops@mycorp.com" },
    { action: "admin_access", target: "ops_dashboard" },
  ];
  for (let s = 0; s < 2000; s++) {
    const g = createGuard();
    for (let i = 0; i < 20; i++) g.evaluate({ ...calls[i % calls.length], at: 1e6 + i });
  }
  const times = [];
  for (let s = 0; s < 5000; s++) {
    const g = createGuard();
    for (let i = 0; i < 20; i++) {
      const c = { ...calls[i % calls.length], at: 1e6 + i };
      const t0 = performance.now();
      g.evaluate(c);
      times.push(performance.now() - t0);
    }
  }
  report("typical session (fresh guard → 20 calls)", times);
}

// ── Scenario 2: large accumulated history (~10k events) — worst case ──
{
  const g = createGuard();
  for (let i = 0; i < 10000; i++) g.evaluate({ action: "read", target: "customers", at: 1e6 + i });
  const times = [];
  for (let i = 0; i < 500; i++) {
    const c = { action: "read", target: "customers", at: 2e6 + i };
    const t0 = performance.now();
    g.evaluate(c);
    times.push(performance.now() - t0);
  }
  report("large history (evaluate at ~10k accumulated events)", times);
}
console.log("");
