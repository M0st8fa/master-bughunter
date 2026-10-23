# ARCHITECTURE.md

How skills, references, commands, and shared resources interact.

## Target runtime
Claude Code. A **skill** = a directory under `skills/` with a `SKILL.md` (optional
supporting files). A **command** = a `.md` file under `commands/`. Frontmatter is kept
**portable** (`name, description, license, compatibility, metadata, allowed-tools`) so
every skill also loads on claude.ai upload and the Skills API.

## The six layers
```
          ┌─────────────────────────────────────────────┐
Layer 1   │  security-hunt  (orchestration / router)     │  ← entry point
          │  Step0 authorization+scope gate → classify →  │
          │  dispatch → track findings → deliverables     │
          └───────────────┬─────────────────────────────┘
                          │ routes to
Layer 2   ┌───────────────▼─────────────────────────────┐
          │  specialist skills (recon, per-bug-class,    │
          │  pipeline, reporting, disclosure corpora)     │
          └───────────────┬─────────────────────────────┘
                          │ draw on
Layer 3   ┌───────────────▼─────────────────────────────┐
          │  references/  — deduped shared knowledge,      │
          │  checklists, taxonomies, payload sets          │
          └───────────────────────────────────────────────┘
Layer 4   tool integration — documented tools + install/version/output notes
Layer 5   QA — docs/QUALITY_RUBRIC.md, scripts/validate_skills.py, tests/
Layer 6   self-learning — commands/skills-*  over the persistent ledgers
```

## Data contracts
- **Findings** conform to `schemas/finding.schema.json` (evidence-first; `status`
  starts at `hypothesis`; `authorization` required).
- **Lessons** conform to `schemas/lesson.schema.json` (de-identified; evidence class).
- **Engagement state** conforms to `schemas/engagement.schema.json` — the persistent
  per-engagement manifest (authorization established once, scope, rate limits,
  restrictions, recon status, phase, completed work; never secrets). Owned by the
  `engagement` skill; format + resume rules in `docs/ENGAGEMENT.md`. The orchestrator and
  every specialist read it so authorization is gated once, not re-asked per action.

## The self-learning loop (Layer 6)
`Observe → Collect → Verify → Compare → Propose → Test → Approve → Update → Measure`.
- Observations/lessons → `LEARNING_LOG.md`; research → `RESEARCH_LOG.md`.
- Every proposed change → `IMPROVEMENT_QUEUE.md` (status `proposed`).
- Only `/skills-update` writes a skill, and only for an `approved` item.
- Promotion of a skill's status requires tests that actually passed
  (`TEST_RESULTS.md`).
This is a **human-approved, file-based** loop — not autonomous background learning. The
runtime gives the library no scheduler of its own; see `docs/SAFETY.md` and
`docs/KNOWN_LIMITATIONS.md`.

## Routing rules (summary)
`security-hunt` maps objective → phase → skill (setup → scope → recon|import → inventory →
intel → routing → validation → evidence → report → coverage), establishes the
authorization/scope gate **once** (persisted via the `engagement` skill), reuses it on
resume, and then runs continuously — choosing the next stage automatically and pausing
only for the human-judgment gates in `docs/SAFETY.md`. Fresh targets go to `recon.sh`;
a supplied recon folder is ingested without re-running recon. Full map in
`skills/security-hunt/SKILL.md`.

## Naming conventions
- Web bug-class hunters: `bb-<class>`. Recon/intel: descriptive (`recon-engine`,
  `target-intelligence`). New domains: `<domain>-security` / `<domain>-assessment`.
- Commands: `skills-<verb>` for the meta/self-learning layer.
