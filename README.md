# log4shell-chain

A Tegron demo: the **Log4Shell / Log4j vulnerability family** modeled as three
Cases, each proving a **PoE → incomplete-patch → PoNE** chain. It separates *"the
version number says fixed"* from *"the exploit actually fires"* — a CVSS feed or
an SBOM scanner marks the first fix as done; Tegron proves whether the exploit
still fires.

The Log4j story is the canonical example: the first fix (2.15.0) was incomplete,
and the fix that closed the JNDI RCE (2.16.0) **opened a different class** (a DoS),
which in turn was followed by yet another config-RCE. So this is modeled as
**three Cases**, one per vuln class, so each chain stays honest instead of being
mashed into one verdict.

## The three Cases

### Case A — JNDI lookup RCE (CVE-2021-44228, also CVE-2021-45046)

| Role | Version | Git ref | Commit | Expected verdict |
|---|---|---|---|---|
| Vulnerable | 2.14.1 | `rel/2.14.1` | `d2d40d51efeb033f961882b79cddd05b54337fed` | `proven exploitable` (PoE) |
| **Failed fix** | 2.15.0 | `rel/2.15.0` | `636ce10d676202b2ea4aa2bab9924a5a8c6dd401` | **incomplete-patch**, `exploitable, conditional-on([non_default_pattern_layout])` (PoE) |
| Real fix | 2.16.0 | `rel/2.16.0` | `70638718e0db900552c062b98956a05409d70058` | `proven not_exploitable` (PoNE) for the JNDI RCE class |

### Case B — uncontrolled-recursion DoS (CVE-2021-45105)

| Role | Version | Git ref | Commit | Expected verdict |
|---|---|---|---|---|
| Vulnerable | 2.16.0 | `rel/2.16.0` | `70638718e0db900552c062b98956a05409d70058` | `proven exploitable` (PoE) |
| Real fix | 2.17.0 | `rel/2.17.0` | `8285c82d998164dccfb2e57889b9dfb73dc27533` | `proven not_exploitable` (PoNE) |

### Case C — JDBC Appender config RCE (CVE-2021-44832)

| Role | Version | Git ref | Commit | Expected verdict |
|---|---|---|---|---|
| Vulnerable | 2.17.0 | `rel/2.17.0` | `8285c82d998164dccfb2e57889b9dfb73dc27533` | `proven exploitable, conditional-on([attacker_controlled_logging_config])` (PoE) |
| Real fix | 2.17.1 | `rel/2.17.1` | `d1c64aa458c20b101a8dd5f4491848f087155e08` | `proven not_exploitable, conditional-on([attacker_controlled_logging_config])` (PoNE) |

## What this proves

- **2.15.0 is "past the first fix" yet still exploitable.** The advisory's first
  fixed version restricted JNDI and disabled message lookups — an SBOM/CVSS view
  marks it fixed. Tegron proves it is **still exploitable** under a non-default
  `PatternLayout` that resolves a Context/Map lookup, and records that as
  `conditional-on([non_default_pattern_layout])`. The condition is the precise
  precondition (CVE-2021-45046), surfaced on the **conditions axis**, not hidden.

- **A fix can trade one vuln class for another.** 2.16.0 closes the JNDI RCE class
  (Case A real_fix) but is the **vulnerable** build for Case B's DoS. 2.17.0 closes
  the DoS but is the vulnerable build for Case C's config RCE. Modeling each CVE as
  its own Case — with its own reproducer and its own observable — keeps every chain
  to one vuln class. That is why this is three Cases, not one.

- **The conditions axis is a recorded precondition, still `proven` — not a hedge.**
  `conditional-on([...])` means the exploit *provenly* fires when the recorded
  precondition holds (a non-default layout for Case A; attacker-controlled logging
  config for Case C). The same condition is carried on the PoNE so the two traces
  compare like-for-like. It is not "maybe"; it is "yes, under exactly this stated
  condition".

## How the proof is produced

Unlike the Go (Gogs) demo, this repo carries **no OSS scanner binary** and runs
**no in-repo OSS scan**. The Tegron OSS scanner's `baseline` verb is **Go-only**
(it requires a `go.mod` target); its verbs are `baseline | pr-inherit | cve-watch
| state` and none of them analyze Java. There is also **no `bin/tegron prove` /
`assert` CLI** — the Prove tier is not exposed in the OSS surface.

This demo's target is **Java** (`org.apache.logging.log4j:log4j-core`), so the
entire PoE → incomplete-patch → PoNE evidence chain is produced by **Tegron's
platform Prove tier** (the Java plugin, Phase 2, live-proven), which runs
**platform-side** (with-account). This repository's job is to carry that tier's
input:

- `cases/*.yaml` — the three Cases with ordered checkpoints and the expected
  verdict per checkpoint (schema `tegron.case.v1`, grounded in RFC 0003 / 0010).
- `reproducer/` — the per-Case, **effect-only** reproducer apps + drivers, and the
  controlled collaborator the sandbox runs as the observability sink.

The mapping onto Tegron primitives (RFC 0003 *Proof of Exploitability*, RFC 0010
*Verdict Lifecycle*, RFC 0009 *Sandbox/Observability*):

| Checkpoint | Tegron mechanism | Verdict |
|---|---|---|
| `vulnerable` | plain assessment; reproducer fires, canary side-effect observed | `proven exploitable` → PoE |
| `failed_fix` | two-trace patch validation vs predecessor; **negative control also fires** | **incomplete-patch finding** (RFC 0010) — not a PoNE |
| `real_fix` | two-trace; positive control fires, negative control dark; observability delta | `proven not_exploitable` → PoNE |

The in-repo CI (`.github/workflows/prove.yml`) builds each reproducer image to
prove the reproducers are real and documents the chain in the job summary. It does
**not** invoke any prove/assert step, because no such CLI exists in the OSS
surface.

## Effect-only reproducers (RFC 0003 / RFC 0001 inv. 8)

Every reproducer demonstrates the **effect**, never the weaponization recipe:

- **Case A** — the observable is the **outbound JNDI callback** to the controlled
  collaborator carrying a per-trial token. The collaborator only **records** the
  connection; it serves no Java class and no code-exec payload.
- **Case B** — the observable is a **DoS canary** (stack/CPU exhaustion from
  unbounded `${ctx:...}` lookup recursion). No code is executed.
- **Case C** — the observable is the **outbound connection attempt** to the
  collaborator when the attacker-controlled JDBC Appender resolves its DataSource.
  No code is executed; no payload is served.

The published artifact carries the *effect* (image digest + driver + observability
record), never the weaponizable technique.

## Layout

- `bin/` — `README.md` only. **No OSS scanner binary** (the OSS `baseline` is
  Go-only; the Java evidence chain is produced platform-side by Tegron's Prove tier).
- `cases/` — `cve-2021-44228.yaml` (Case A), `cve-2021-45105.yaml` (Case B),
  `cve-2021-44832.yaml` (Case C).
- `reproducer/caseA|caseB|caseC/` — `Dockerfile.<checkpoint>` + `driver/` per Case.
- `reproducer/collaborator/` — the controlled, passive callback recorder.
- `.github/workflows/prove.yml` — builds the reproducer images; documents the chain.

## Provenance

Reproducer images pin the **released Maven artifact**
(`org.apache.logging.log4j:log4j-core` at the version in each Dockerfile), not a
build from the apache git commit. The corresponding upstream git SHA from
`apache/logging-log4j2` is recorded in each `cases/*.yaml` and in each Dockerfile
comment for provenance.

> Status: files authored; not yet live-executed (Docker builds + driver runs +
> collaborator wiring are a live-pass TODO). See `NOTES.md`.
