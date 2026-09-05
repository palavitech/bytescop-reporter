# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Overview

BytesCop is a self-hosted security findings management platform. It consolidates pen tests, malware analysis, digital forensics, and manual assessments into a single multi-tenant workspace. The repo contains a Django REST API (`api/`), an Angular frontend (`ui/`), Docker orchestration, and operational shell scripts.

Licensed under Elastic License 2.0 (source-available, not OSS). Version is tracked in `VERSION`; releases are cut via the `bytescop-onprem-release` skill.

## Commands

### Development (hybrid: Docker infra + local code)

```bash
# Start everything (two terminals):
./api-devrun.sh    # Docker infra → migrations → seed → Django dev server at :8000
./ui-devrun.sh     # npm install → Angular dev server at :4200 (proxies /api to :8000)
./stop-devrun.sh   # Stop all (Docker + local servers)

# Or manually start just Docker infra:
docker compose -f docker-compose.yml -f docker-compose.dev.yml up -d
```

`api-devrun.sh` requires `.env` at the repo root and a venv at `api/.venv/`. It runs
`migrate`, then the `ensure_install_state` and `ensure_subscription_plans` seed commands.

### API (Django)

```bash
cd api
DJANGO_SETTINGS_MODULE=bytescop.settings.dev POSTGRES_PASSWORD=<from .env> \
  .venv/bin/python manage.py runserver 0.0.0.0:8000

# Tests (no Docker needed — uses SQLite in-memory):
.venv/bin/python manage.py test engagements accounts -v 2 --settings=bytescop.settings.test

# Single test class:
.venv/bin/python manage.py test engagements.tests.TestEngagementCreate --settings=bytescop.settings.test

# E2E tests (requires Docker infra running):
.venv/bin/python manage.py test -v 2 --settings=bytescop.settings.e2e

# Coverage:
.venv/bin/coverage run --source='.' manage.py test --settings=bytescop.settings.test
.venv/bin/coverage report --skip-empty
```

Test files do not follow a single naming convention — alongside `tests.py` there are
`tests_views.py`, `tests_services.py`, `tests_gap.py`, `core/tests/`, etc. Prefer running a
whole app label unless you know the exact module.

### UI (Angular 21)

```bash
cd ui
npm install
npx ng serve --host 0.0.0.0 -c local    # dev server, proxies via src/proxy.conf.json
npx ng test --watch=false                # unit tests (Karma/Jasmine)
npx ng test --include='**/some.spec.ts'  # single test file

npm run e2e                              # Playwright (auth-setup + chromium projects)
npm run e2e:noauth                       # unauthenticated flows only
npm run e2e:headed / e2e:ui / e2e:debug  # interactive variants
```

The default `serve` configuration uses `src/proxy.conf.dev.json`; `-c local` switches to
`src/proxy.conf.json`.

### Reset & Maintenance

```bash
./flush_dev.sh        # Drop DB, flush Redis, clear media, re-migrate (prompts "FLUSH")
./backup.sh           # Timestamped backup of DB + media → ./backups/
./install.sh          # First-time on-prem install
./update.sh           # Upgrade an existing install
./reset-password.sh   # Reset a user's password
./reset-mfa.sh        # Clear a user's MFA enrollment
```

### CI

`.github/workflows/ci.yml` runs API and UI test suites on PRs to `main` and `development`.
`.github/workflows/release.yml` runs on `v*` tags.

## Architecture

### Docker Services (production: 8 containers)

PostgreSQL 16, Redis 7, Django API (gunicorn), 2 Celery workers (`worker-notify`, `worker-jobs`),
Celery Beat, UI builder, Nginx. Dev mode (`docker-compose.dev.yml`) disables the api/ui/nginx
containers and exposes DB (5432) and Redis (6379) to the host.

### API (`api/`)

**Stack:** Python 3.13+, Django 6, DRF, Celery + Redis, PostgreSQL (prod) / SQLite (test)

**Auth is session-based, not JWT.** See "Authentication" below.

**Django Apps** (all in `INSTALLED_APPS`):

| App | Purpose |
|---|---|
| `accounts` | Email-based User model (`USERNAME_FIELD = 'email'`), MFA enforcement middleware |
| `account_settings` | Tenant-scoped key-value settings, logo upload, MFA policy |
| `api` | Auth/login views, profile, MFA self-service, dashboard, invites, password reset |
| `assets` | Asset CRUD (HOST, WEBAPP, API, CLOUD, NETWORK_DEVICE, MOBILE_APP, OTHER) |
| `audit` | Audit trail + `AuditedModelViewSet` base class |
| `authorization` | Permission/TenantGroup RBAC, engagement-scoped visibility |
| `clients` | Customer/client management |
| `comments` | Comments on entities |
| `core` | InstallState singleton, SetupGateMiddleware, request-ID middleware, validators, rate limiting |
| `engagements` | Engagements, SoW, scope, stakeholders, engagement settings |
| `events` | `events.publisher` — dispatches domain events to Celery queues |
| `evidence` | Attachments, MalwareSample, EvidenceSource, storage backends, signed URLs |
| `feedback` | User feedback / feature requests |
| `findings` | Findings, classification reference data, malware/PE analysis executors |
| `jobs` | `BackgroundJob` model (exports, purges) |
| `licensing` | Signed license key validation (`public_key.pem`), feature gating |
| `projects` | Project grouping — a Project owns many Engagements |
| `subscriptions` | Plan limits + feature flags, enforced via `subscriptions/guard.py` |
| `tenancy` | Tenant, TenantMember, TenantMiddleware |

**Not Django apps** — `api/email_processor/` and `api/job_processor/` are plain Python packages
(Celery task handlers, email sender/templates). They are not in `INSTALLED_APPS` and have no models.

**Settings modules** (`api/bytescop/settings/`): `base.py` (shared) → `dev.py` (local PG, relaxed
CORS) | `test.py` (SQLite in-memory, no Docker) | `e2e.py` (extends dev, fast hasher) |
`production.py` (Docker PG, full stack). Always set `DJANGO_SETTINGS_MODULE`.

`test.py` and `e2e.py` both use the MD5 password hasher for speed. `e2e.py` also sets
`TEST_RUNNER = 'core.test_runner.BytesCopTestRunner'`, which bootstraps `InstallState` so
`SetupGateMiddleware` doesn't block the suite.

**Key patterns:**
- Domain models inherit `TimeStampedModel` (UUID pk, created_at, updated_at,
  `ordering = ['-created_at']`). Deliberate exceptions that subclass `models.Model` directly:
  `AuditLog`, `BackgroundJob`, `TenantClosure`, `InstallState`, `RateLimitEntry`.
- All querysets are tenant-scoped via FK + `get_queryset()` filtering on `request.tenant`
- `perform_create()` injects `tenant=request.tenant`, `created_by=request.user`
- CRUD viewsets extend `audit.base.AuditedModelViewSet` and set `audit_resource_type` — this
  auto-logs create/update/delete on 2xx. `perform_*` hooks stay free for business logic.
- Celery routes by queue: `process_notification` → `notifications`, `process_job` /
  `cleanup_expired_jobs` → `jobs`. Beat runs `cleanup_expired_jobs` daily.
- `bytescop/tasks.py` lives in the project package, so `celery.py` imports it explicitly —
  `autodiscover_tasks()` only scans installed apps.

### Authentication

Django **session** authentication with CSRF — there is no JWT anywhere in this codebase.

- `REST_FRAMEWORK.DEFAULT_AUTHENTICATION_CLASSES = ['core.authentication.SessionAuthWith401']`.
  This subclass exists to (a) return 401 instead of DRF's default 403 so the frontend interceptor
  can redirect to `/login`, and (b) actually respect `@csrf_exempt`, which DRF's
  `SessionAuthentication` ignores.
- Session cookie `bc_session`, HttpOnly, SameSite=Lax, 14-day age, `SESSION_SAVE_EVERY_REQUEST`
  (sliding expiry). DB-backed session engine.
- CSRF cookie `bc_csrf`, **not** HttpOnly (the frontend reads it), header `X-CSRFToken`.
- Two-step login: `POST /api/auth/login/` then `/api/auth/login/select-tenant/`. Also
  `/api/auth/tenants/`, `/api/auth/switch-tenant/`, `/api/auth/logout/`.
- MFA (pyotp + qrcode): `MfaEnforcementMiddleware` reads `mfa_enabled` from the session; if false
  it checks `TenantMember` + `is_mfa_required()` and returns 403. `EXEMPT_PREFIXES` lets
  `/api/me/mfa/`, `/api/me/profile/`, `/api/auth/`, `/api/health/`, `/api/users/`,
  `/api/attachments/` through so setup can complete.
- No self-signup on-prem — admins create users via invite.

**Middleware chain** (order matters):
`VersionHeader → Security → WhiteNoise → RequestId → CORS → SetupGate → Session → Common →
CSRF → Auth → Tenant → MfaEnforcement → Messages → XFrameOptions`

`X-Tenant-Slug` header identifies the tenant; resolved by `tenancy.middleware.TenantMiddleware`.

### Authorization (RBAC)

Two layers — don't confuse them:

1. **`TenantRole`** on `TenantMember` is only `OWNER` or `MEMBER`. It is a coarse role, not the
   permission system.
2. **`authorization` app** holds the real model: global `Permission` rows (49, codenames like
   `finding.create`, `user.view`, categories `model` / `system`) M2M'd onto tenant-scoped
   `TenantGroup`s. Seeded by `authorization/seed.py` (`seed_permissions` management command).

Default groups: **Administrators** (everything except `OWNER_ONLY_PERMISSIONS` —
`tenant.close`, `billing.manage`, `group.*` writes, `user.delete`), **Analysts** (findings +
evidence CRUD, read-only on clients/assets/engagements/SoW/scope), **Collaborators**.

**Engagement scoping** (`authorization/scoping.py`): members without the `user.view` permission
see only engagements they're assigned to via `EngagementStakeholder`, plus the clients/assets
linked to those. Owners bypass by role; Administrators bypass because they hold `user.view`.

### UI (`ui/`)

**Stack:** Angular 21.1.0 (standalone components), TypeScript 5.9, Bootstrap 5.3, RxJS 7.8,
Milkdown/Crepe (markdown editor), Chart.js, marked + DOMPurify

Note: `dompurify` is imported directly (markdown pipe, findings view, report service) but is **not**
declared in `package.json` — only `@types/dompurify` is. It currently resolves as a transitive
dependency. Add it as a direct dependency before relying on it further.

```
src/app/
├── components/    # breadcrumb, toast, pipes, directives, tenant-menu, mfa-setup-card
├── features/      # admin, assets, comments, engagements, organizations, profile, projects
├── pages/         # login, setup, dashboard, accept-invite, verify-email, mfa-setup,
│                  # forgot-password, reset-password, closing, privacy, terms
└── services/core/ # auth, guards, jobs, loading, notify, profile, setup, date-format, version
```

**Key patterns:**
- Standalone components only (no NgModules), OnPush change detection
- `inject()` for dependency injection, signals for reactive state
- Bootstrap 5 first — custom CSS only for cyber theme (dark bg `#070a0f`, accent green `#00ffb3`,
  accent blue `#00b7ff`)
- CSS variables prefixed `--bc-*` in `src/styles.css`
- Fonts: IBM Plex Mono (body), Orbitron (headings)
- Functional HTTP interceptors in `app.config.ts`: `withInterceptors([loadingInterceptor, authInterceptor])`
- Two `APP_INITIALIZER`s bootstrap setup state and auth before the app renders
- Route data for breadcrumbs: `data: { breadcrumb: 'Label' }`, `hideBreadcrumb: true` to suppress
- Coding standards: single quotes, 2-space indent, `const` by default, no `any`

**Conventions are documented in `ui/memory/`** — read these before adding screens:
`permission-guard-rules.md` (every route needs `canActivate: [requirePermission(...)]`, every
action button needs `*bcHasPermission`, 403s are handled globally in `authInterceptor`),
`list-screen-pattern.md`, `screen-patterns.md`. `ui/CLAUDE.md` holds general Angular style guidance.

### Domain Model

```
Tenant (name, slug, status)
├── TenantMember → User (role: OWNER | MEMBER)
├── TenantGroup (name, is_default) → M2M Permission
├── Client (name, website, notes, status)
│   └── Asset (name, asset_type, environment, criticality, target, attributes)
├── Project (name, client, status, start_date, end_date)
│   └── Engagement (engagement_type, client, status, dates)
│       ├── Sow (OneToOne, auto-created with the engagement, status: draft|approved)
│       │   └── SowAsset (asset, in_scope)
│       ├── EngagementStakeholder (member → TenantMember, role)  ← drives scoping
│       ├── EngagementSetting (also auto-created)
│       ├── MalwareSample (original_filename, safe_filename, sha256, storage_uri)
│       ├── EvidenceSource (evidence_type, source_path, acquisition_*, chain_of_custody)
│       └── Finding (title, severity, status, description_md, recommendation_md)
│           └── Attachment (status: draft|active|orphaned, filename, sha256, storage_uri)
├── AccountSetting (key, value, updated_by)
├── AuditLog / BackgroundJob
└── TenantSubscription → SubscriptionPlan (limits + feature flags)
```

`Engagement.engagement_type` drives UI behaviour: `web_app_pentest`, `external_pentest`,
`mobile_pentest`, `internal_pentest`, `wifi`, `malware_analysis`, `digital_forensics`,
`active_directory`, `linux_audit`, `windows_audit`, `general`.

**`Finding`** is the widest model. Beyond the pentest fields it carries:
- Scope FKs — exactly one of `asset`, `sample`, or `evidence_source` is typically set
- Classification — `assessment_area`, `owasp_category`, `cwe_id`, validated against
  `ClassificationEntry` (DB-backed reference data seeded by migration). The `ASSESSMENT_AREAS`
  and `OWASP_CATEGORIES` constants on the model are **dead** — kept for reference only.
- Forensics — `mitre_tactic`, `mitre_technique`, `ioc_type`, `ioc_value`, `occurrence_date`,
  `confidence`
- Analysis lifecycle — `analysis_check_key` (links to a check definition, empty for manual
  findings), `execution_status` (pending → running → completed/failed), `analysis_type`,
  `is_draft`

### Malware & Forensics Analysis

`findings/analysis_checks.py` defines the check catalogue (`ANALYSIS_CHECKS`, keyed by
`analysis_check_key`): `report`, `hash_identification`, `extract_strings`, `special_strings`,
`file_type`, `pe_headers`, `pe_imports`, `pe_exports`, `pe_packer_detection`, `pe_resources`,
`compile_time`.

Executors live in `findings/analysis_executors.py` (generic) and `findings/pe_executors.py`
(PE-specific, the largest module in the app). They take `(storage, sample, finding)`, are
side-effect free apart from reading sample bytes, and return a markdown string that becomes
`description_md`. Irrelevant checks are skipped via magic-byte file-type detection.

Dependencies: `pefile`, `python-magic` (needs `libmagic1`, installed in the Dockerfile),
`pyzipper`.

**Samples are never executed.** `MalwareSample` files are stored with a neutralized `.sample`
extension and read-only permissions.

### Storage System

Abstract `AttachmentStorage` (`evidence/storage/base.py`) with `save` / `open` / `delete`.

**Only the local backend exists.** `evidence/storage/factory.py` unconditionally returns
`LocalAttachmentStorage()` — it does not read any environment variable. The `BC_STORAGE_BACKEND`
and `BC_S3_*` entries in `api/.env.example` are aspirational and currently have no effect.

- Upload validates content type (magic bytes, `core/validators.py`), enforces
  `BC_MAX_UPLOAD_BYTES` (10 MB default) / `BC_MAX_SAMPLE_BYTES` (200 MB default), computes SHA256
- Attachments are served through HMAC-signed URLs (`evidence/signing.py`) — markdown `<img src>`
  can't send auth headers, so URLs carry `?sig=<hmac>&tid=<tenant_id>`, with the tenant id bound
  into the signature to prevent cross-tenant access
- `findings/services/attachment_reconcile.py` syncs DRAFT→ACTIVE on save and cleans orphans

## Environment Variables

Root `.env` drives Docker Compose (see `.env.example`); `api/.env.example` documents the API's own
variables. Variables actually read by `bytescop/settings/`:

```
POSTGRES_DB, POSTGRES_USER, POSTGRES_PASSWORD, POSTGRES_HOST, POSTGRES_PORT,
POSTGRES_CONN_MAX_AGE
DJANGO_SECRET_KEY, DJANGO_ALLOWED_HOSTS, DJANGO_DEBUG, DJANGO_MEDIA_ROOT, DJANGO_MEDIA_URL
CORS_ALLOWED_ORIGINS, NUM_PROXIES (1)
CELERY_BROKER_URL, CELERY_RESULT_BACKEND
BC_MAX_UPLOAD_BYTES (10 MB), BC_MAX_SAMPLE_BYTES (200 MB)
BC_LICENSE_KEY, BC_CONTACT_EMAIL, BC_INVITE_EXPIRY_HOURS, BC_INVITE_COOLDOWN_MINUTES
EMAIL_HOST, EMAIL_PORT, EMAIL_HOST_USER, EMAIL_HOST_PASSWORD, EMAIL_USE_TLS, DEFAULT_FROM_EMAIL
BYTESCOP_LOG_LEVEL (INFO), DJANGO_LOG_LEVEL (WARNING), BYTESCOP_LOG_DIR,
BYTESCOP_LOG_FORMAT, BYTESCOP_LOG_MAX_BYTES, BYTESCOP_LOG_BACKUP_COUNT, BYTESCOP_SQL_LOG (0|1)
```

Compose-only: `BC_PORT` (443).

**Stale entries in `api/.env.example`** — `BYTESCOP_JWT_ACCESS_MINUTES`,
`BYTESCOP_JWT_REFRESH_DAYS`, `BC_STORAGE_BACKEND`, `BC_S3_*`. None are read by any code.
