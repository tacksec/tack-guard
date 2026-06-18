import type { StoredEvent } from "../types.js";
import type { MemoryClient } from "./types.js";

/**
 * Default in-memory client. Events live in a Map, lost on process restart.
 * This is what tack-guard uses out of the box — zero config, zero deps.
 *
 * Baselines reset when the process restarts — by design. For persistence
 * across restarts or sessions, implement a {@link MemoryClient} backed by your
 * own store and plug it in with guard.setMemory().
 */
export class InMemoryClient implements MemoryClient {
  private store = new Map<string, StoredEvent[]>();

  push(agentId: string, event: StoredEvent): void {
    const events = this.store.get(agentId) ?? [];
    events.push(event);
    this.store.set(agentId, events);
  }

  getEvents(agentId: string): StoredEvent[] {
    return this.store.get(agentId) ?? [];
  }

  clear(agentId: string): void {
    this.store.delete(agentId);
  }

  clearAll(): void {
    this.store.clear();
  }
}
