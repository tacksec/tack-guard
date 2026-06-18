/**
 * Canonical action vocabulary.
 *
 * Real agents name tool calls in countless ways — "update_row", "deleteUser",
 * "POST", "exportAll", "drop_table". Detection must NOT hinge on the caller
 * passing the exact string "write". `canonicalizeAction()` folds an arbitrary
 * action / tool name into a small, stable set the scoring engine reasons about,
 * case-insensitively and with synonym + composite-name handling, so an attacker
 * (or just a real framework) can't slip past by renaming the verb.
 *
 * This is the layer that turns a brittle string-equality check into something
 * that survives `update` / `delete` / `Exfiltrate` / `export_all`.
 */
export type CanonicalAction =
  | "read"
  | "write"
  | "admin"
  | "exfiltrate"
  | "destroy"
  | "other";

// Order matters: a name is classified by the most dangerous verb it contains.
// Deliberately conservative: only verbs whose dangerous sense dominates. Benign-
// common verbs (send, upload, format, flush) are intentionally NOT here — they'd
// quarantine email/upload/formatting agents on a single sensitive-named target.
const EXFIL = new Set([
  "exfiltrate", "exfil", "export", "exportall", "export_all", "bulk_export", "bulkexport",
  "dump", "download_all", "scrape", "leak", "copy_all", "egress", "siphon", "smuggle",
]);
const DESTROY = new Set([
  "destroy", "drop", "wipe", "delete_all", "deleteall", "truncate", "purge",
  "rm", "rmrf", "rmdir", "unlink", "shred", "expunge", "erase",
  "destroy_all", "drop_table", "droptable",
]);
const ADMIN = new Set([
  "admin", "admin_access", "adminaccess", "grant", "revoke", "sudo", "escalate",
  "assume_role", "set_permission", "setpermission", "chmod", "chown",
  "add_user", "create_user", "elevate", "impersonate",
]);
const WRITE = new Set([
  "write", "create", "insert", "update", "upsert", "patch", "put", "post",
  "modify", "edit", "set", "append", "delete", "remove", "del", "save", "store",
]);
const READ = new Set([
  "read", "list", "get", "fetch", "select", "query", "scan", "describe",
  "head", "view", "search", "find", "lookup", "show", "count",
]);

function tokenize(raw: string): string[] {
  return raw
    .replace(/([a-z0-9])([A-Z])/g, "$1 $2") // split camelCase
    .toLowerCase()
    .split(/[^a-z0-9]+/)
    .filter(Boolean);
}

/**
 * Map a raw action or tool name to its canonical action.
 *
 * @example
 * canonicalizeAction("update_row")   // "write"
 * canonicalizeAction("Exfiltrate")   // "exfiltrate"
 * canonicalizeAction("drop_table")   // "destroy"
 * canonicalizeAction("listCustomers")// "read"
 */
export function canonicalizeAction(raw: string): CanonicalAction {
  const norm = raw.trim().toLowerCase();

  // 1. Whole-string match catches known compounds (delete_all, bulk_export, …)
  if (EXFIL.has(norm)) return "exfiltrate";
  if (DESTROY.has(norm)) return "destroy";
  if (ADMIN.has(norm)) return "admin";
  if (WRITE.has(norm)) return "write";
  if (READ.has(norm)) return "read";

  // 2. Token match handles composite tool names (update_row, deleteUser, …),
  //    classified by the most dangerous verb present.
  const tokens = tokenize(raw);
  if (tokens.some((t) => EXFIL.has(t))) return "exfiltrate";
  if (tokens.some((t) => DESTROY.has(t))) return "destroy";
  if (tokens.some((t) => ADMIN.has(t))) return "admin";
  if (tokens.some((t) => WRITE.has(t))) return "write";
  if (tokens.some((t) => READ.has(t))) return "read";

  return "other";
}

/** A canonical action that mutates state (write, admin, exfiltrate, destroy). */
export function isMutating(action: CanonicalAction): boolean {
  return action === "write" || action === "admin" || action === "exfiltrate" || action === "destroy";
}

// Egress verbs — moving data toward a destination. Deliberately NOT in the
// canonical risk classes above: a bare "send"/"upload" is benign on its own
// (that was the single-shot false-positive trap). They matter only
// CONTEXTUALLY — an egress to an untrusted destination AFTER a sensitive access
// is the data-exfiltration trajectory the behavioral layer scores. See score.ts.
const EGRESS = new Set([
  "send", "sendmail", "sendemail", "emailto", "upload", "post",
  "share", "publish", "transmit", "push", "webhook", "forward", "deliver",
  "notify", "sms", "fax", "sync", "export", "exfiltrate", "dump", "leak",
  // money movement is egress too: a transfer to a non-allowlisted destination after a
  // sensitive read is the financial exfil flow (send_money already matches via "send").
  // Opt-in (dormant unless egressTargets is set), so this adds no default FP surface.
  "transfer", "wire", "remit",
]);

// "email" / "mail" are both a verb (to email someone = egress) and a noun (an
// email = an object you read / delete / archive). Treat them as egress ONLY when
// they LEAD the action — its verb slot — so `email_alice` / `mail_report` fire
// while `delete_email` / `read_email` / `archive_email` (mailbox ops on an
// object) do not. FP-first: a mislabeled mailbox op is worse than a missed bare
// `email(...)` verb, which `send` already covers in practice (`send_email`).
const EGRESS_AMBIGUOUS = new Set(["email", "mail"]);

/**
 * Does this raw action / tool name move data toward a destination (an egress)?
 * Case- and synonym-aware, like {@link canonicalizeAction}. Orthogonal to the
 * canonical action class — used only by the egress / data-exfiltration signal.
 */
export function isEgressAction(raw: string): boolean {
  const norm = raw.trim().toLowerCase();
  if (EGRESS.has(norm) || EGRESS_AMBIGUOUS.has(norm)) return true;
  const tokens = tokenize(raw);
  if (tokens.some((t) => EGRESS.has(t))) return true;
  // Ambiguous noun-verbs count only in the leading (verb) position.
  return tokens.length > 0 && EGRESS_AMBIGUOUS.has(tokens[0]);
}
