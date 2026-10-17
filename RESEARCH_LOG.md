# RESEARCH_LOG

Research findings and references, with verification status. Newest first.
Each entry: what was learned · which skill benefits · why valuable · date · verified?
· licensing/attribution.

---

### 2026-10-17 · User's recon.sh active-enumeration pipeline (analyzed, integrated)
- **Learned:** A well-built Bash bug-bounty recon framework chaining the Go toolchain
  (subfinder all-sources+recursive → dnsx brute-force/resolve/CNAME/wildcard → waybackurls
  +gau+katana+gospider → in-scope filter → httpx JSON probing → ~30-bucket URL
  classification), plus opt-in nuclei/gowitness/gitleaks/arjun/naabu/subzy and active
  CORS/.git/open-redirect checks, resume, and Slack/Discord notify. Two design points worth
  keeping: (a) snapshot original roots BEFORE enumeration appends discovered subs, then
  filter crawled URLs against that snapshot to drop third-party/CDN noise; (b) parse httpx
  from JSON with jq and split by EXACT `status_code` field, not bracket-substring grep,
  so a content-length of 200 can't land in `httpx200.txt`.
- **Benefits:** `recon-engine` (now its active engine), and the triage/handoff pattern for
  all hunt skills (class buckets → matching specialist).
- **Source:** user upload `recon.sh` (read, NOT executed) · **Verified:** code reviewed
  statically; not run here (needs the Go tools + an authorized target; out of sandbox).
  No secrets present. · **Attribution:** user-authored, used with permission in their project.

### 2026-10-10 · Claude Code Agent Skills specification
- **Learned:** SKILL.md frontmatter is all-optional; portable keys outside Claude Code
  are limited to `name, description, license, compatibility, metadata, allowed-tools`
  (any other key is a hard error on claude.ai upload / Skills API). Skills double as
  `/` commands via `name`; `.claude/commands/*.md` also supported; keep SKILL.md < 500
  lines; supporting files referenced, not inlined; scripts executed not loaded.
- **Benefits:** every skill + the command layer (defines the authoring contract).
- **Source:** code.claude.com/docs/en/skills · **Verified:** yes (primary docs).

### 2026-10-10 · Ai-Hunting learning_engine design
- **Learned:** A workable learning loop = ingest finding + triage (incl. false
  positives) → recall relevant lessons → distill analytics into patterns → bounded
  signal scoring; persisted ledgers separate evidence from hypothesis. Session hooks:
  before_recon / during_testing / after_finding / before_summary / after_triage.
- **Benefits:** `/skills-learn-from-task`, `/skills-learn`, LEARNING_LOG design.
- **Source:** github.com/0xmannaf/Ai-Hunting (read, not executed) · **Verified:** design
  reviewed; we reimplement as file-based + human-approved, not as their SQLite runtime.

### 2026-10-10 · Haddix heat-map application-analysis methodology
- **Learned:** Manual "heat map" of high-signal areas (uploads, multipart, APIs,
  profile fields, third-party integrations, error pages) + questions on data flow,
  identifiers, multi-tenancy, prior writeups — pairs with tool chains.
- **Benefits:** `target-intelligence`, `bb-pipeline`, footprinting.
- **Source:** mcpmarket red-team-bug-bounty-methodology page · **Verified:** NO —
  provenance caution (author mismatch, unverified repo). Methodology adopted; the
  page's unscoped/unrate-limited Nuclei scripts NOT adopted.

---

## Open research questions (highest-impact gaps first)
1. Cloud/IAM privilege-escalation testing methodology (authorized) — primary sources:
   AWS/GCP/Azure IAM docs, cloud pentest guides.
2. Container/Kubernetes security assessment (CIS benchmarks, k8s RBAC).
3. Detection engineering & log analysis (MITRE ATT&CK mappings, Sigma rules).
4. Threat hunting / incident investigation methodology (hypothesis-driven).
5. Confirm current Claude Code slash-command + subagent + hooks docs before finalizing.
