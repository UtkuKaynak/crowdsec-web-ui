# CLAUDE.md

Personal fork of `crowdsec-web-ui` (upstream: TheDuffman85). Adds local analytics
features. Hobby project, not security-expert reviewed.

## Architecture
- **server/** — Hono (Node) API. Talks to CrowdSec **LAPI as a watcher** (password or
  mTLS). Caches alerts/decisions in **SQLite** (`server/database.ts`); a background loop
  syncs from LAPI. `server/app.ts` = all routes. `server/analytics.ts` = local read-only
  analytics (incidents, IP/ASN/subnet overviews, allowlist conflicts, insights).
- **client/** — React + Vite + Tailwind v4 SPA. Pages in `client/src/pages/`, API wrapper
  `client/src/lib/api.ts`, types re-exported from `shared/contracts.ts`.
- **shared/contracts.ts** — API types (source of truth for client+server).

## Hard constraints (don't propose features that need these)
- Auth is **watcher-only** over LAPI: no cscli/admin, no bouncer/machine listing, no hub.
- **No host filesystem/log access** (runs as a container) — no raw-log evidence, no config-file editing.
- **Allowlists are read-only via LAPI** (`GET /v1/allowlists`, `/v1/allowlists/check/:ip`).
  No write endpoint exists (CrowdSec issue #3681) — writes are surfaced as `cscli allowlists add` commands.
- The app authenticates *itself*; there is **no end-user identity** (reverse-proxy only). Audit-log actor comes from a forwarded header (`AUDIT_USER_HEADER`).

## Commands (Windows / PowerShell, pnpm)
- `pnpm run typecheck` · `pnpm run lint` · `pnpm run test:server` · `pnpm run test:client` · `pnpm run build`
- **Always run typecheck + lint + both test suites + build before shipping.**
- Local run without CrowdSec (fake LAPI + seeded SQLite), two terminals:
  - `$env:DB_DIR="$PWD\.localtest"; pnpm exec tsx screenshots/seed-demo-data.ts; $env:PORT="3000"; pnpm exec tsx screenshots/demo-server.ts`
  - `pnpm exec vite`  (proxies `/api` → :3000)
  - Demo gotchas: Incidents needs **Min alerts = 1** to show seed data; allowlist/conflicts show "unavailable" (fake LAPI has no allowlist methods).

## Conventions / gotchas
- i18n: **flat dotted keys** in `client/src/locales/*.json`; `en.json` is authoritative, others fall back to en. Interpolation uses single braces `{x}`.
- Lint rule `react-hooks/set-state-in-effect`: don't call setState synchronously in an effect — defer with `window.setTimeout(() => ..., 0)` (see existing pages).
- better-sqlite3 rejects **missing/undefined** named params — coalesce optional columns to `null` (see `database.insertAlert`).
- DB migrations run in `initSchema` on startup (idempotent: `ADD COLUMN` if missing, `CREATE TABLE IF NOT EXISTS`, then backfill). Additive + rollback-safe.
- Adding a page: page in `pages/`, route in `App.tsx`, nav in `Sidebar.tsx`, title in `Layout.tsx`, i18n keys in `en.json`.

## Git / deploy
- Workflow: branch → commit → `gh pr create` → `gh pr merge --merge` → sync `main`. One PR per feature batch. Never commit straight to `main`.
- Commit trailer: `Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>`.
- Distribution is a **container image only** (no RPM/npm). VPS deploy = build from source via `deploy/update.sh` (`cd /opt/crowdsec-web-ui && sudo bash update.sh`).

## Status / next
Shipped: audit log, IP investigation page, incidents, self-protection (allowlist conflicts),
ASN/subnet pages, bulk ban, insights, themes, CSV export.
Next phase: **cscli companion** on the engine host so the UI can actually control cscli allow more useful features. Also how to establish that with container approach is a question.
Open idea: selectable incident clustering granularity (/24·/16·ASN) — currently fixed /24. or a proper incident identification tool with the companion.
