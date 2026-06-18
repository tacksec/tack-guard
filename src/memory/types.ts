import type { StoredEvent } from "../types.js";

/**
 * MemoryClient interface — the pluggable persistence layer.
 *
 * tack-guard ships with InMemoryClient (default, single-session). Implement
 * this interface to back baselines with your own store — Redis, SQLite, a
 * network DB — and plug it in with guard.setMemory() (async backends use
 * guard.evaluateAsync()).
 */
export interface MemoryClient {
  /** Store a new event for the given agent. */
  push(agentId: string, event: StoredEvent): void | Promise<void>;

  /** Get all stored events for the given agent (oldest first). */
  getEvents(agentId: string): StoredEvent[] | Promise<StoredEvent[]>;

  /** Clear all events for the given agent. */
  clear(agentId: string): void | Promise<void>;

  /** Clear everything. */
  clearAll(): void | Promise<void>;
}
