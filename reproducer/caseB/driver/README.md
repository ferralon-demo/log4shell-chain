# Case B driver — uncontrolled-recursion DoS (CVE-2021-45105)

> Authored but **not live-executed** this pass. Correct in principle; live Docker
> build + canary timing tuning is a TODO for the live pass (see repo-root
> `NOTES.md`).

## What it does

`CaseBDriver` sets a self-referential Context/Map value
(`${ctx:x}` whose value itself contains `${ctx:x}`) and logs a message that
resolves it. On 2.16.0 the `StrSubstitutor` recurses without bound; on 2.17.0
recursion is depth-bounded and the event logs normally.

## Observable side-effect

A **DoS canary**: a `StackOverflowError` (caught, then `halt(42)` so the sandbox
records the non-zero failure), or — if recursion instead pegs the CPU — the
sandbox watchdog times the process out. Either is the observable. **No code is
executed.**

| Checkpoint | Version | Expected observable |
|---|---|---|
| `vulnerable` | 2.16.0 | `CANARY_TRIPPED` / watchdog timeout → PoE |
| `real_fix` | 2.17.0 | `CANARY_CLEAR`, lookup bounded → PoNE |

The Dockerfiles run with `-Xss512k` so unbounded recursion trips fast and
deterministically instead of thrashing the sandbox.

## Why this is its own Case

2.16.0 is the Case A *real_fix* — it closed the JNDI RCE class — yet it is the
Case B *vulnerable* build. A fix can trade one vuln class for another, so each
CVE is modeled as its own Case with its own reproducer and observable rather than
mashed into one verdict.

## Effect-only stance (RFC 0003 / RFC 0001 inv. 8)

This reproducer demonstrates the DoS **effect** (resource-exhaustion canary)
only. It performs no code execution and serves no payload.
