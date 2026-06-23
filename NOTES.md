# NOTES — log4shell-chain build

Build notes: deviations from the spec (`docs/demo-poe-chain-projects.md`),
uncertainties, and what needs a live pass. Authored 2026-06-23.

## Deviations from the spec (intentional, documented)

1. **No `bin/tegron prove` / `assert` step.** The spec §5 sample `prove.yml`
   invokes `bin/tegron prove` and `bin/tegron assert`. Those CLIs do **not exist**
   in the OSS surface (verbs are `baseline | pr-inherit | cve-watch | state`; the
   Prove tier runs platform-side, with-account). The workflow here does NOT invoke
   them. Instead it builds the reproducer images and documents the chain. The spec
   §6 itself flags "Confirm against the shipped Prove CLI/API surface before first
   run" — this build resolves that as: there is no such surface to call from repo CI.

2. **No in-repo OSS scan, and no committed scanner binary.** The spec §4 layout
   shows `bin/tegron` (a prebuilt CLI, like nucleon's `bin/nucleon`). The OSS
   scanner `baseline` is **Go-only** and Log4j is **Java**, so there is nothing for
   it to scan here. `bin/` therefore contains only `bin/README.md` explaining this.
   The Java evidence chain is produced by the platform Prove tier.

3. **Maven-artifact pinning instead of git-commit builds.** The spec §4 says each
   `Dockerfile.<checkpoint>` fetches the pinned commit/tag and builds it. Building
   log4j from the apache git commit pulls a large multi-module Gradle build. For an
   effect-only reproducer we only need a tiny app depending on the **released**
   `log4j-core` artifact at the exact version (2.14.1 / 2.15.0 / 2.16.0 / 2.17.0 /
   2.17.1). So each Dockerfile pins the released Maven artifact and records the
   corresponding upstream git SHA (from the Case file) in a comment for provenance.
   This keeps the repo small and the build fast while staying honest about which
   version is under test.

4. **`prove.yml` job shape differs from §5.** §5's matrix is over checkpoints with
   a `prove` + `assert` + artifact-upload + SARIF pipeline. Since there is no
   prove/assert CLI and no SARIF output here, the workflow is two honest jobs:
   `build-reproducers` (matrix over all per-Case checkpoints) and `chain` (renders
   the three chain tables + the "produced platform-side" note to the job summary).
   `build-reproducers` uses `continue-on-error: true` because historic Maven +
   JDK-8 builds can be finicky (Maven Central availability, plugin pinning).

5. **Repro tree organized per-Case** (`reproducer/caseA|caseB|caseC/` + shared
   `reproducer/collaborator/`), as the dispatch directed, rather than the flat
   `reproducer/Dockerfile.<checkpoint>` of §4 — because three Cases of three
   different vuln classes each need their own driver/observable.

6. **Case condition representation.** The dispatch asked to represent conditions in
   the `expect` block. Case A `failed_fix` uses
   `expect: { finding: incomplete_patch, conditions: [non_default_pattern_layout] }`;
   Case C uses `conditions: [attacker_controlled_logging_config]` on both the PoE
   and PoNE expects. The spec §4 schema example does not show a `conditions` field;
   this is an additive field consistent with the conditions axis (RFC 0003). Confirm
   the exact field name against the shipped Prove case schema before a live run.

7. **"inv. 8" citation.** The dispatch and spec say "RFC 0003 inv. 8" for the
   effect-only stance. The actual safety invariant (source non-disclosure / effect
   over weaponization) is **RFC 0001 invariant 8**, referenced from RFC 0003
   §"Disclosing exploit source vs. effect-only reproducer". Prose cites it as
   "RFC 0003 / RFC 0001 inv. 8" to be accurate.

## Uncertainties / open items

- **JDK base per era.** All reproducers use `eclipse-temurin:8` (build + runtime).
  Rationale: Case A is the JNDI class-load era. For an EFFECT-ONLY proof we only
  need the **outbound** JNDI callback, which fires regardless of the
  `com.sun.jndi.ldap.object.trustURLCodebase` default, so JDK choice does not gate
  the observable. JDK 11 would also work; 8 is closest to the historic deployment.
  Confirm log4j-core 2.17.x runs cleanly on temurin:8 during the live pass (it
  targets Java 8, so it should).

- **2.15.0 bypass layout string.** Case A `failed_fix` uses a non-default
  `PatternLayout` whose pattern resolves `${ctx:attack}`, with the driver routing
  the JNDI string through `ThreadContext`. This is the modeled CVE-2021-45046 path
  (non-default lookup in the layout). The **exact** layout/lookup combination that
  reliably reproduces the 2.15.0 bypass needs live confirmation — the public PoCs
  vary (some use `$${ctx:...}` / Thread Context Map patterns / `MapMessage`).
  Tune the pattern in `log4j2-nondefault.xml` during the live pass.

- **Collaborator protocol (LDAP vs TCP).** The collaborator is a **plain TCP
  passive recorder** (records the connection + first-packet bytes, serves nothing).
  This is deliberate: it avoids any referral/class-serving path (weaponization).
  Open question: whether each JNDI/JDBC client opens the TCP connection and emits
  the token in the first packet *before* needing a protocol reply. If a live pass
  shows the connection opens but the token isn't captured, the recorder may need a
  minimal **non-referral** LDAP bind response (still serving no class). Tracked in
  `reproducer/collaborator/README.md`.

- **Case C JDBC DataSource wiring.** `log4j2-jdbc.xml` resolves the JDBC Appender
  DataSource from `${env:COLLABORATOR_JNDI}`. The exact form that makes 2.17.0
  attempt the outbound resolution (and 2.17.1 refuse it) needs live confirmation —
  log4j-core 2.17.x may require the `log4j-jdbc-dbcp2` / a JNDI DataSource on the
  classpath for the appender to initialize. May need an extra dependency in
  `reproducer/caseC/driver/pom.xml`.

- **Condition field name** in the case schema — see deviation 6.

## What needs a live pass (NOT done this pass)

- Build all 7 reproducer Dockerfiles (Maven resolves the pinned log4j artifacts;
  JDK-8 images build the fat jars). Confirm green or fix.
- Build + run the collaborator; attach it on a network with the reproducers.
- Run each driver and confirm the observable per the per-driver README tables:
  Case A callback fires on 2.14.1/2.15.0 and is dark on 2.16.0; Case B canary trips
  on 2.16.0 and is clear on 2.17.0; Case C outbound attempt fires on 2.17.0 and is
  dark on 2.17.1.
- Tune the 2.15.0 non-default layout and the Case C JDBC wiring until the observable
  is deterministic.
- Feed `cases/*.yaml` + the reproducer images + collaborator into the platform Prove
  tier (Java plugin) and confirm the realized verdicts equal the `expect` blocks.
