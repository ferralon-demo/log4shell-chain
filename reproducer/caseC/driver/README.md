# Case C driver — JDBC Appender config RCE (CVE-2021-44832)

> Authored but **not live-executed** this pass. Correct in principle; the live
> Docker build + collaborator JNDI/DataSource wiring is a TODO for the live pass
> (see repo-root `NOTES.md`).

## What it does

`CaseCDriver` initializes log4j with an **attacker-controlled** configuration
(`log4j2-jdbc.xml`) whose JDBC Appender resolves its `DataSource` from a JNDI name
pointing at the controlled collaborator. Touching the logger materializes the
appender, which attempts to resolve that DataSource.

## Observable side-effect

The **outbound connection attempt to the collaborator-controlled source** when
log4j initializes the JDBC Appender. The collaborator only records the attempt.
**No code is executed and no payload is served.**

| Checkpoint | Version | Expected observable |
|---|---|---|
| `vulnerable` | 2.17.0 | DataSource JNDI resolves → outbound connection attempt → PoE, `conditional-on([attacker_controlled_logging_config])` |
| `real_fix` | 2.17.1 | DataSource restricted to `java:` protocol, JNDI refused → dark → PoNE (same condition recorded) |

## The precondition

This vuln requires `attacker_controlled_logging_config` — the attacker must
supply or tamper with the logging config. That is a **recorded precondition** on
the conditions axis, carried on both the PoE and the PoNE so the two traces are
compared like-for-like. It is a recorded condition, not a hedge: the verdict is
still `proven`.

## Effect-only stance (RFC 0003 / RFC 0001 inv. 8)

This reproducer demonstrates the **effect** (the outbound connection attempt
proving the JDBC DataSource resolution fired), never weaponization. The
collaborator is a passive recorder; no RCE payload is delivered.
