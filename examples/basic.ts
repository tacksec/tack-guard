/**
 * Minimal tack-guard example — a blatant exfiltration is blocked on call 1.
 *
 * Run from the repo root:  npx tsx examples/basic.ts
 * In your own app, import from the published package instead:
 *   import { createGuard } from '@tacksec/guard'
 */
import { createGuard } from "../src/index.js";

const guard = createGuard();

const result = guard.evaluate({
  action: "exfiltrate",
  target: "user_db.credentials",
});

console.log(`verdict: ${result.verdict}  (score ${result.score})`);
console.log(`summary: ${result.summary}`);

if (result.blocked) {
  console.log("→ deny the tool call");
  process.exitCode = 0;
}
