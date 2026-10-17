# Patterns That Actually Paid — distilled from 11,338 disclosures

Read this when planning tests or building chains. Each pattern: what it is, real paid examples, and the delta between the cheap and expensive version. Query the corpus for fresh angles (`scripts/query.py`).

## 1. Account takeover family (the top of the market)
| Paid | What it was |
|---|---|
| $35,000 | Password reset takeover **without user interaction** |
| $20,000 | ATO via **leaked session cookie** |
| $15,300 | Token leak in security-challenge flow → victim PayPal email |
| $13,000 | Mass ATO via **alternate auth path** (TaxJar) |
| $12,000 | Auth bypass in **account recovery** (TikTok) |
| $10,500 | DoS an org's SSO → ATO door |

Deltas that carried the money: **no victim interaction**, **mass/scale** ("any account"), **recovery/reset paths** instead of login. A reset-flow bug with interaction needed pays a fraction of the same bug with none. Alternate auth paths (mobile API, legacy endpoint, SSO bypass) are where mass-ATO lives.

## 2. IDOR / access control with an object twist
| Paid | What it was |
|---|---|
| $22,300 | **RepositoryPipeline imports local git repos** (import feature = authz gap) |
| $20,000 | Read **all CD keys of any game** (vendored redeemable codes) |
| $20,000 | Steal private objects of other projects **via project import** (IDOR) |
| $15,250 | Bypass partner email confirmation → take over any store given an employee email (TOCTOU) |

Pattern: **import/export/migration features** keep paying six-figure-adjacent bounties because they move objects across tenant boundaries server-side. Test import-from-URL, project copy, workspace transfer with cross-tenant IDs. Anything that **vends codes/keys/tickets** (gift cards, CD keys, invites) is a payday if the batch ID is swappable.

## 3. Race / TOCTOU money bugs
| Paid | What it was |
|---|---|
| $10,000 | **Double Payout via PayPal** (payout endpoint raced) |
| $12,000 | Run pipeline jobs **as arbitrary user** (logic flaw in job identity) |
| $15,250 | Partner email-confirmation **bypass** (TOCTOU on confirmation state) |

The paid races are on **money-out and entitlement-grant** endpoints (payout, redeem, confirm, grant), not on views. Check-then-act + concurrent burst = multiplier impact ("one payment, N credits").

## 4. Credential/token exposure (highest single bounty in corpus)
| Paid | What it was |
|---|---|
| $50,000 | **GitHub access token exposure** |
| $15,000 | Leaked **JFrog Artifactory** user+password on GitHub |
| $10,000 | Config files with **VPN pre-shared-key** |
| $5,000 | Disclosed **ServiceNow** credentials → data leak |

Delta vs your average "internal IP disclosure" ($0–500): the leaked secret has **reach** (token that can write, cred that opens a VPN/registry). Hunt secrets in: public repos of the org, client bundles, CI config, error pages, archived URLs (wayback captures tokens in query strings).

## 5. Path traversal / arbitrary file read (import pipelines again)
| Paid | What it was |
|---|---|
| $29,000 | File read via **bulk imports UploadsPipeline** |
| $20,000 | File read via **UploadsRewriter** when moving an issue |
| $16,000 | File read **during project import** |
| $6,500 | Arbitrary file read on **SSL VPN** |

Every big one is an upload/move/import feature resolving a user-controlled path. Test `filename`, `path`, `attachment_url` params with `../../` in **import, export, move, copy, migrate** flows.

## 6. Command execution via features, not params
| Paid | What it was |
|---|---|
| $33,510 | RCE via **DecompressedArchiveSizeValidator** + BulkImports |
| $33,510 | RCE via **GitHub import** |
| $25,000 | **Exposed Kubernetes API** — RCE/creds |
| $20,160 | Pre-auth RCE on **Twitter VPN** |

Archives (zip/tar/tar.gz) and VCS imports are the modern RCE front door: decompression bombs, symlink members, path members. An exposed k8s API/Argo CD **with** credentudual access = the $25k tier; UI-only exposure = the $0 tier (our ArgoCD findings).

## 7. CSRF that mattered
| Paid | What it was |
|---|---|
| $10,000 | CSRF bypass in **GitHub Enterprise management console** |
| $7,500 | CSRF via **DNS rebinding** (Starlink dish) |
| $4,660 | **Argo CD CSRF → Kubernetes cluster compromise** |

CSRF pays when the target is an **admin/control plane** (mgmt console, Argo CD, infra dashboards). Consumer-web CSRF is mostly dead/dupe; pivot to internal tools exposed publicly.

## 8. GraphQL / mutation authz
| Paid | What it was |
|---|---|
| $12,500 | View any hacker email via **/SaveCollaboratorsMutation** |
| $25,000 | `/reports/:id.json` discloses sensitive user attributes (REST sibling) |

One mutation missing an ownership check on an ID argument. The names to probe: Save*/Invite*/Collaborat*/Transfer*/Accept*.

## 9. Subdomain takeover / smuggling / XXE (small n, steady pay)
Fastly takeover $3,000 · CloudFront distribution takeover $1,000 · hex-escape HTTP request smuggling in transform rules $6,000 · Tomcat client-side desync $4,660 · blind XXE $500. These pay modestly but consistently — good filler when the main surface is hardened.

## Cross-cutting lessons
1. **Import/export/migration flows** are the single richest feature family (RCE + traversal + IDOR + SSRF all congregate there).
2. **Interaction-free + mass-scale** is what separates $35k from $500 in the same bug class.
3. **Secrets with reach** (tokens, registry creds, VPN keys) beat topology leaks every time.
4. **Control planes exposed** (k8s API, Argo CD, mgmt consoles) pay when you can touch state, not when you can see the login page.
5. Platforms: HackerOne dominates the corpus (10k of 11.3k) — Bugcrowd/Intigriti writeups are rarer but the patterns transfer.
