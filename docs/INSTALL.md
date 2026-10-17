# INSTALL.md

## Prerequisites
- **Claude Code** (CLI, desktop, web, or IDE extension). Skills also load on claude.ai
  upload and via the Skills API because frontmatter is kept portable.
- Python 3.8+ for `scripts/validate_skills.py` and the few skill scripts (stdlib only for
  the validator). Individual skills may call external security tools (subfinder, httpx,
  nuclei, etc.) — each skill documents its own tool needs; none are bundled and none are
  assumed present.

## Install the skills
Skills live in a `.claude/skills/<name>/SKILL.md` scope. Choose one:

- **Personal (all projects):**
  ```sh
  cp -r cybersecurity-skills/skills/* ~/.claude/skills/
  ```
- **Project (this repo only):**
  ```sh
  mkdir -p .claude/skills && cp -r cybersecurity-skills/skills/* .claude/skills/
  ```

Run `/reload-skills` in Claude Code if a newly created top-level skills directory isn't
picked up. Verify with `/skills` (or just ask Claude to use `security-hunt`).

## Install the self-learning commands
```sh
mkdir -p ~/.claude/commands && cp cybersecurity-skills/commands/*.md ~/.claude/commands/
# or project scope: .claude/commands/
```
Then `/skills-help` lists them.

## Keep the ledgers writable
The `/skills-*` commands read and write the ledgers and queue. Keep the whole
`cybersecurity-skills/` directory together (or point the commands at it) so they can
update `IMPROVEMENT_QUEUE.md`, `CHANGELOG.md`, etc. Running the commands from the project
root is simplest.

## API keys (optional, for recon-engine)
`recon-engine` can use VirusTotal/Shodan if keys are present. Provide them via
environment variables (`VT_API_KEY`, `SHODAN_API_KEY`) **or** a git-ignored
`skills/recon-engine/keys.env` copied from `keys.env.example`. **Never commit real keys.**
Without keys, those providers are skipped; the rest of recon runs.

## Validate the install
```sh
python3 -I cybersecurity-skills/scripts/validate_skills.py
```
Expect `0 error(s)`. A non-zero exit lists what to fix.
