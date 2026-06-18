# Security Policy

tack-guard is a security tool, so we take reports seriously and aim to respond quickly.

## Reporting a vulnerability

**Please do not open a public issue for security vulnerabilities.**

- Use GitHub's [private vulnerability reporting](https://github.com/tacksec/tack-guard/security/advisories/new) on this repository, or
- Email **security@tacksec.com** with a description, reproduction steps, and impact.

We'll acknowledge within 72 hours, keep you updated on remediation, and credit you (if you wish) once a fix ships.

## Scope

In scope:

- Detection bypasses (an attack pattern tack-guard claims to catch but doesn't), within the documented threat model — see the "Limitations & threat model" section of the [README](README.md).
- Crashes, ReDoS, or unbounded resource use in `evaluate()` / `evaluateAsync()`.
- Issues in the published package contents.

Out of scope (by design — documented, not vulnerabilities):

- Missed attacks on innocuously-named targets (sensitivity is name-based; pass a `sensitiveTargets` predicate).
- Missed behavioral detection for agents with no read-only baseline (relies on the signature layer).
- Anything in dev-only dependencies that does not reach the published tarball (which ships `dist/` only, zero runtime deps).

## Supported versions

Pre-1.0: only the latest published version is supported.
