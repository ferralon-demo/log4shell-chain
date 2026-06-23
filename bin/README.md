# bin/ — intentionally empty of binaries

Unlike the Go (Gogs) demo repo, **no Tegron OSS scanner binary ships here.**

The Tegron OSS scanner's `baseline` verb is **Go-only**: it requires a `go.mod`
target and produces a reachability candidate set for Go code. Its verbs are
`baseline | pr-inherit | cve-watch | state` — none of them analyze Java.

This repo's target is **Java** (`org.apache.logging.log4j:log4j-core`), so there
is no in-repo OSS scan to run, and therefore no scanner binary to commit. The
entire PoE → incomplete-patch → PoNE evidence chain for this demo is produced by
**Tegron's platform Prove tier** (the Java plugin, Phase 2, live-proven), which
runs platform-side (with-account) — not in this repository's CI.

What this repo *does* carry as the Prove tier's input:

- `cases/*.yaml` — the three Cases (A/B/C) with ordered checkpoints and the
  expected verdict per checkpoint.
- `reproducer/` — the per-Case, effect-only reproducer apps + drivers + the
  controlled collaborator the sandbox runs.

The in-repo CI (`.github/workflows/prove.yml`) builds the reproducer images to
prove they are real, and documents the chain. It deliberately does **not**
invoke any `bin/tegron prove` / `assert` step, because no such CLI exists in the
OSS surface — the Prove tier is not exposed there.
