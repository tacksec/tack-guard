# Examples

Runnable from the repo root with [`tsx`](https://github.com/privatenumber/tsx)
(no install needed — `npx` fetches it on first run):

```bash
npx tsx examples/basic.ts
npx tsx examples/crm-bot-credential-creep.ts
npx tsx examples/openai-tool-guard.ts
```

| File | What it shows |
|---|---|
| [basic.ts](basic.ts) | The 10-line quick start: a blatant exfiltration blocked on call 1 by a stateless signature. |
| [crm-bot-credential-creep.ts](crm-bot-credential-creep.ts) | The flagship scenario: a read-only CRM agent that slowly escalates to a credential grab over 3 days, caught by the behavioral baseline. |
| [openai-tool-guard.ts](openai-tool-guard.ts) | Wiring into an OpenAI/Anthropic function-calling loop with `inferToolCall()` — no hand-mapping of `action`/`target`. |

These examples import from `../src/index.js` so they run against the source.
In your own app, install the package and import from `@tacksec/guard` instead:

```ts
import { createGuard } from "@tacksec/guard";
```
