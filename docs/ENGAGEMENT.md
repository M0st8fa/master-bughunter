# ENGAGEMENT.md — persistent engagement state & resume

The **engagement manifest** (`engagement.json`) is the durable record that lets the
ecosystem run a hunt continuously: establish authorization and scope **once**, then work
without re-asking. Owned by the `engagement` skill
(`skills/engagement/scripts/engagement.py`); schema at
`schemas/engagement.schema.json`.

## Where it lives
One manifest per engagement workspace (default `recon/engagement.json`). **One workspace
per program** — a new or materially changed scope gets its own workspace and its own
manifest. Authorization is never shared across programs.

## What it stores (and never stores)
Program id + platform, scope source (provenance), in-scope roots, exclusions, rate limit,
required headers (non-secret, e.g. `X-Intigriti: <tag>`), testing restrictions, posture
(production/lab), recon status + engine + dir + inventory paths + per-tool status, current
phase, and timestamped completed work.

**Never stored:** raw credentials, session cookies, API secrets, bearer/JWT tokens, or
private keys. `engagement.py` runs every written value through a secret-shape guard and
**refuses** (exit 2) anything that looks like a real secret, so credentials cannot leak
into persistent state. Sessions/cookies for authenticated testing stay in the user's
tooling (jar files, Burp, Cookie-Editor), referenced by label, never copied here.

## Lifecycle
```
init (once) ── establishes authorization.established=true, writes scope
   │
   ├─ resume ─ reuse the manifest, continue from the saved phase (NO re-gate)
   ├─ classify ─ in_scope | out_of_scope | needs_clarification (exclusions win)
   └─ set ─ advance phase / recon status / add completed-work entries
```

`init` is **idempotent**: a second call for the same program returns `reused`, not a new
gate. A different program in the same workspace is a `conflict` (use a new workspace).

## Phases (resume continues from the next incomplete one)
`setup → scope → recon → import → inventory → intel → routing → validation → evidence →
report → coverage → complete`

## Scope classification rules
- Wildcards: `*.acme.com` matches subdomains **and** the apex; `*.cloud.acme.com` matches
  anything ending in `.cloud.acme.com`. A bare apex (`acme.com`) matches only itself.
- **Exclusions beat inclusions** — an excluded host is never tested even when it appears
  inside an in-scope app's crawl output.
- A host matching no in-scope root is `needs_clarification` and is **not** tested.

## Recon state & resume
- `recon.status`: `none | running | complete | imported | stale | failed`. Before a fresh
  run, check it — never launch a duplicate over a `running`/existing job (`recon.sh
  --resume` or ingest the existing dir instead).
- Fresh recon → `recon.sh` (standard active engine) writes an output dir → ingest it.
- Supplied recon dir → `ingest_recon.py <dir>` builds `inventory.jsonl` (+ separate
  `excluded_inventory.jsonl`) without re-running recon.
- The inventory tracks per-URL `test_status`, `checks_done`, `evidence`, and `findings`.
  Re-ingesting or resuming preserves these — completed checks are not repeated and
  findings are not discarded.

## Commands (run isolated)
```bash
python3 -I skills/engagement/scripts/engagement.py --workspace recon init --program <id> \
    --scope-source <url|path> --roots "<a,b>" --exclude "<x,y>" [--rate-limit N] \
    [--restrictions "..."] [--header "Name:tag"] [--posture production|lab]
python3 -I skills/engagement/scripts/engagement.py --workspace recon resume
python3 -I skills/engagement/scripts/engagement.py --workspace recon classify <host|url>...
python3 -I skills/engagement/scripts/engagement.py --workspace recon set --phase routing \
    --add-completed "inventory built"
python3 -I skills/engagement/scripts/ingest_recon.py <recon_dir> --workspace recon
python3 -I skills/engagement/scripts/ingest_recon.py <recon_dir> --workspace recon --next-batch 50
```

Regression tests: `tests/engagement/test_engagement.py` (runnable, mock fixtures, no live
scan). See also `docs/SAFETY.md` (the approval gates that remain) and `docs/KNOWN_LIMITATIONS.md`.
