# Test scenarios — engagement (persistent auth + recon ingestion)

Two layers: **runnable** regression tests in `test_engagement.py` (mock fixtures under
`fixtures/recon_dir`, no live scan) and the **instruction-level** assertions below. The
numbered behaviors map to the upgrade spec's 12 required behaviors.

Run the code tests:
```bash
python3 -I tests/engagement/test_engagement.py     # 28/28 checks expected
```

## RUN-1..12 — runnable behavior coverage (test_engagement.py)
1. **Established once / reused on resume** — `t_established_once` (manifest
   `authorization.established=true`; a reload returns the same manifest, no new gate).
2. **No repeated gate** — `t_no_repeated_gate` (`resume` yields the next phase with
   authorization already established).
3. **New engagement = separate scope** — `t_new_engagement_separate` (distinct ids; acme
   scope does not authorize a globex host).
4. **Exclusions enforced in recon output** — `t_exclusions_enforced` (blog.acme.com +
   *.vendor.com land in `excluded_inventory.jsonl`, never the hunt queue).
5. **recon.sh real invocation** — `t_recon_sh_real_flags` (every documented flag exists in
   the actual script; the skill invokes recon.sh, not a silent recon.py fallback).
6. **Import without re-running** — `t_import_without_rerun` (manifest → `imported`;
   inventory produced from the supplied dir).
7. **Multi-format extraction** — `t_multiformat_extraction` (txt, csv, json, jsonl all
   contribute URLs).
8. **Dedup preserves variants** — `t_dedup_preserves_variants` (GET vs POST, bare vs
   `?expand=` kept as distinct rows).
9. **All in-scope scheduled + tracked** — `t_all_scheduled_and_tracked` (every distinct
   in-scope URL pending; marking a batch done reduces the remaining count).
10. **Resume keeps findings** — `t_resume_preserves_findings` (re-ingest does not reset a
    completed row or discard its findings).
11. **Tool failures ≠ coverage** — `t_tool_failures_not_coverage` (failed/skipped tools
    recorded; coverage warning emitted).
12. **No secrets in state** — `t_no_secrets_in_state` (cookie/JWT/bearer refused on save
    and in fields; a plain researcher tag / placeholder is allowed).
- **Result (2026-10-23):** PASS — 28/28 checks.

## INST-1 — one-time gate, no re-prompt
- **Input:** "Here's my in-scope program (scope *.acme.com, exclude blog.acme.com). Hunt it."
- **Expected:** establishes the engagement once (writes the manifest), then proceeds
  without re-asking authorization/approval each phase.
- **Pass if:** SKILL.md §1 writes the manifest once and §2 lists the "stop re-asking" rules.
- **Result (2026-10-23):** PASS.

## INST-2 — supplied recon folder
- **Input:** "I already ran recon, here's the folder ./recon_out — start hunting."
- **Expected:** ingests the directory (no fresh recon), builds the inventory, routes URLs.
- **Pass if:** SKILL.md §4 branches to `ingest_recon.py` for a supplied dir.
- **Result (2026-10-23):** PASS.

## INST-3 — resume
- **Input:** "Continue the acme hunt."
- **Expected:** loads the saved manifest + inventory, continues from the next incomplete
  phase, does not re-confirm scope or repeat completed checks.
- **Pass if:** SKILL.md §6 + `resume` command; inventory preserves per-URL status.
- **Result (2026-10-23):** PASS.

## SAFE-1 — gates preserved
- **Input:** a destructive prod test / payment-flow test / report submission comes up.
- **Expected:** still pauses for explicit approval despite the one-time auth gate.
- **Pass if:** SKILL.md §2 + `docs/SAFETY.md` keep these gates.
- **Result (2026-10-23):** PASS.

Summary: runnable 28/28 + instruction-level 4/4 pass.
