# LEARNING_LOG

Generalized, reusable lessons extracted from completed authorized tasks and from
research — stripped of secrets, credentials, PII, and target-specific detail.
Written by `/skills-learn-from-task` and `/skills-learn`. Newest first.

Each lesson:
- **Lesson:** the generalizable statement.
- **Evidence class:** `verified` (reproduced / primary source) · `hypothesis`
  (plausible, untested) · `failed` (tried, did not hold).
- **Applies to:** skill(s).
- **Provenance:** where it came from (task id / source), de-identified.
- **How to apply:** concrete change to make.

---

## 2026-10-17

- **Lesson:** Passive and active recon are complementary, not competing — keep both. A
  passive/API engine (keyless, sandbox-safe, gives source-provenance) and an active engine
  (Go toolchain: brute-force, crawl, live-probe, classify) are different tools: best
  practice is passive for breadth, then active for depth on the resolved in-scope set.
  Don't retire the passive one just because the active one is "stronger".
  **Evidence class:** verified (integration of user's recon.sh alongside recon.py) ·
  **Applies to:** recon-engine · **How to apply:** two-engine SKILL.md with an explicit
  "which engine when" table; the active engine's `logs/*.log`+`run_config.txt` are the
  provenance equivalent of passive `providers.json` — read what ran before concluding.

- **Lesson:** When adding an engine that only runs on the user's own machine (needs an
  external toolchain installed), state that caveat up front and never execute it for the
  user from the sandbox — document the exact command instead and interpret its outputs.
  **Evidence class:** verified · **Applies to:** recon-engine, any tool-dependent skill ·
  **How to apply:** SKILL.md + reference carry a "runtime caveat — read first" block;
  required-vs-optional tool list so a missing optional = absent-because-not-run, not clean.

## Seed lessons (from source analysis, 2026-10-10)

- **Lesson:** Two skills can ship byte-identical reference assets; dedupe to one shared
  reference to cut maintenance and size.
  **Evidence class:** verified (md5 match) · **Applies to:** bb-xss, bb-domxss ·
  **Provenance:** archive inventory · **How to apply:** move payloads to
  `references/xss-payloads.txt`, reference from both.

- **Lesson:** A distributable skill bundle can accidentally carry live credentials in an
  `.env`. Always keep keys in the environment / git-ignored local files and scan bundles
  before packaging.
  **Evidence class:** verified · **Applies to:** recon-engine, packaging/audit ·
  **Provenance:** archive `recon-engine/keys.env` · **How to apply:** `/skills-audit`
  greps for secret-shaped strings; packaging step refuses `*.env` with non-placeholder
  values.

- **Lesson:** "Self-learning" claims are only credible if backed by persistent artifacts
  and an approval gate; otherwise they are prompt theater.
  **Evidence class:** verified (design review of Ai-Hunting) · **Applies to:** whole
  self-learning layer · **How to apply:** every learned item is written to a ledger with
  an evidence class and routed through IMPROVEMENT_QUEUE before touching a skill.

---

## How a lesson gets promoted
`hypothesis` → `verified` only after an actual check (reproduction, primary source, or a
passing regression test recorded in TEST_RESULTS.md). A single success does NOT make a
technique universal — note the environment it held in.
