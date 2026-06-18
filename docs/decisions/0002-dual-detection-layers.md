# ADR-0002: Dual detection layers (behavioral + stateless)

**Status:** Accepted
**Date:** 2026-06-15
**Decider:** Damien Aubry

## Context

AI agents can attack in two ways:
1. **Slow escalation** (credential-creep): read-only for days, then slowly introduce writes, then access sensitive data. No single call is damning.
2. **Blatant attack** (smash-and-grab): one call dumps the credential store or wipes the database.

A purely behavioral system misses blatant attacks during baseline establishment. A purely rule-based system misses slow escalation.

## Decision

Two complementary layers:
- **Behavioral scoring** (`score.ts`): memory-dependent, builds baselines from observed calls, catches slow escalation.
- **Stateless signatures** (`signatures.ts`): memory-independent, flat rules, catches blatant attacks instantly.

## Consequences

- **Good:** Catches both attack styles.
- **Good:** Stateless layer works even during baseline establishment (first N calls).
- **Good:** Demonstrates value immediately (blatant attacks blocked on call 1) while the behavioral layer builds up.
- **Bad:** Two codepaths to maintain and test.

## Validation

A memory kill-switch experiment proves both layers are doing distinct work:
- Memory ON: behavioral scoring catches credential-creep. Memory OFF: the creep sails through (no baseline to compare against) — confirming the behavioral layer is what catches slow escalation.
- Memory ON or OFF: stateless signatures always catch the smash-and-grab (bulk export of credentials), independent of any baseline.

This duality is the core thesis: each layer covers the attack style the other structurally misses.
