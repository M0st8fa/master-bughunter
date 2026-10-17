# QUALITY_RUBRIC.md — Skill Scoring & Status Classification

Every skill is scored 0–5 in each applicable category. Scores require **evidence**
(a file, a passing test, a cited source) — not impression. A high average never hides a
critical defect: a 0–1 in **Technical accuracy** or **Safety** caps the skill at
`experimental` regardless of other scores.

## Score meaning (applies to every category)
- **0** — absent or wrong.
- **1** — present but misleading / unreliable.
- **2** — partial, significant gaps.
- **3** — usable; meets the baseline.
- **4** — strong; minor gaps only.
- **5** — exemplary; evidence-backed, nothing material missing.

## Categories (12)
1. **Technical accuracy** — instructions are correct and current. *(gate)*
2. **Completeness** — covers the stated responsibility end to end.
3. **Workflow clarity** — ordered, unambiguous, decision points explicit.
4. **Practical usefulness** — beats a generic prompt; produces real output.
5. **Verification & evidence quality** — separates evidence from hypothesis; says how to prove a result.
6. **Tool integration** — names tools, versions, install checks, output interpretation, error handling.
7. **Error handling** — what to do when a step/tool fails.
8. **Maintainability** — modular, references shared knowledge, < 500 lines.
9. **Interoperability** — inputs/outputs align with sibling skills; no conflicting instructions.
10. **Safety & responsible use** — authorization/scope gates, minimal-impact, non-destructive proof. *(gate)*
11. **Documentation & provenance** — sources cited; limitations stated.
12. **Testability** — has acceptance criteria and at least one representative test.

## Weighted overall (guidance, not a license to ignore gates)
`overall = round(mean(applicable categories), 1)`. Report the two gate scores
separately next to the mean. "N/A" categories are excluded from the mean and noted.

## Status classification & promotion criteria
| Status | Criteria |
|---|---|
| **experimental** | Drafted. Not yet validated, or a gate category scores ≤1. |
| **under-review** | Static checks pass; overall ≥3.0; awaiting behavioral tests. |
| **validated** | Static + at least the positive & negative behavioral tests pass; overall ≥3.5; both gates ≥3. |
| **production-ready** | `validated` + full scenario set (positive/negative/ambiguous/incomplete/failure) passes; overall ≥4.0; both gates ≥4; provenance complete. |
| **deprecated** | Superseded or unsafe; kept for history with a pointer to its replacement. |

A skill is marked `validated` only after the named checks **actually pass** (recorded in
`TEST_RESULTS.md`). Tests that could not be performed are reported, not assumed.

## Scorecard location
Per-skill scores are tracked in `SKILL_INDEX.md` (columns: overall, accuracy-gate,
safety-gate, status). `/skills-audit` recomputes and flags regressions.
