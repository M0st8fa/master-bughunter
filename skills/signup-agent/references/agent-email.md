# agent-email — the core inbox methodology (command reference)

Source of truth: https://github.com/zaddy6/agent-email (npm `@zaddy6/agentemail`).
`agent-email` is a Bun CLI that gives the agent a real disposable email inbox
powered by Mail.tm. Every command returns JSON by default, aliases resolve the
active account as `me`/`default`/`active`, and `read --wait N` blocks until
mail lands so scripts never sleep-loop.

This skill uses agent-email as THE inbox engine for every signup (Phase 2) and
every verification-mail retrieval (Phase 4). Non-inbox paths (user-forwarded
mail, manual verification) are fallbacks only.

## Install (once per machine)

```bash
npm install -g @zaddy6/agentemail
# or
bun install -g @zaddy6/agentemail
agent-email about   # verify install + version
```

## The core loop (one inbox per account)

```bash
# 1. Create a disposable inbox
agent-email create
# → { "email": "xxxx@some-domain", "password": "…", "accountId": "…" }

# 2. Read mail — blocks until something arrives, up to N seconds
agent-email read me --wait 40

# 3. Get full bodies — ALWAYS before parsing links/codes
agent-email read me --full --limit 1

# 4. Open one specific message by id
agent-email show me <messageId>
```

Rules the workflow depends on:

- The short `read` listing has NO HTML body. `--full` is mandatory before any
  link/code extraction.
- `--wait N` blocks until a new message arrives (poll every `--interval N`
  seconds). Prefer it over shell sleep loops.
- Aliases: any `<email|alias>` slot accepts the raw address, `default`,
  `active`, or `me`. `agent-email read me --full` is the normal call.
- One inbox per account. Name the inbox in the hunt workspace credential file
  so verification trails stay auditable.

## Full command set

| Command | Description |
|---|---|
| `agent-email create` | Create a new disposable inbox (email + password + accountId) |
| `agent-email read <email\|alias> [--limit N] [--full] [--wait N] [--interval N]` | List messages; `--wait N` blocks until new mail; `--full` includes complete bodies |
| `agent-email show <email\|alias> <messageId>` | Print one message in full |
| `agent-email delete <email\|alias> <messageId>` | Delete a message |
| `agent-email accounts list` | List every saved inbox account |
| `agent-email accounts add <email> --password <pwd> [--set-default]` | Save an existing inbox (e.g. created on another machine) |
| `agent-email accounts remove <email\|alias>` | Forget a saved account |
| `agent-email use <email\|alias>` | Set the active account for alias resolution (`me`) |
| `agent-email config path` | Print the config file location |
| `agent-email about` | Version + provider info |

## Multi-account campaigns

Multiple targets in one campaign → keep one inbox per account and manage them
with the accounts subcommands:

```bash
agent-email accounts list                                # JSON inventory
agent-email --human accounts list                        # readable table
agent-email use <email|alias>                            # switch active
agent-email accounts add <email> --password <pwd> --set-default
agent-email accounts remove <email|alias>                # cleanup after engagement
```

Cross-check `accounts list` against `<target>/recon/credentials.txt` (Phase 6)
so every account maps to a live inbox. Do not `accounts remove` mid-engagement.

## Configuration

- Config file: `~/.config/agent-email/config.json` (0600 on Unix)
- Override location: `AGENT_EMAIL_CONFIG=/custom/path/config.json agent-email accounts list`
- Do not hand-edit credentials in the config; use `accounts add/remove`.

## Provider & terms

Inboxes are powered by Mail.tm — respect their terms of use and attribution
requirements. Disposable inboxes are for authorized testing only; this skill's
prime directive (in-scope targets only) applies to every `create`.
