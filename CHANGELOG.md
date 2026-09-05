# Changelog

All notable changes to BytesCop-Reporter will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/), and this project adheres to [Semantic Versioning](https://semver.org/).

## [1.2.5] - 2026-04-22

### Added
- Add Send to Report workflow for Malware Analysis — per-sample Report finding with "Send to Report" action on each executable finding
- Add Domains, File Names, and Registry Keys categories to the Special Strings finding
- Auto-expand finding drawer when Execute is clicked

### Changed
- Fold PE Sections table into the Packer Detection finding; remove the standalone PE Sections check

## [1.2.4] - 2026-04-16

### Added
- Add scope-entity filter to findings list (Asset, Sample, Evidence Source) with active filter pills
- Add Findings navigation button to View Finding page header
- Add expandable full import lists to PE Imports finding
- Skip irrelevant analysis checks based on sample file type via magic byte detection
- Add entry-point byte signature matching for FSG packer detection

### Fixed
- Add libmagic1 to Dockerfile for python-magic file type detection
- Fix PE executor crash on section names with leading null bytes
- Fix seed analysis tests to mock file-type detection

## [1.2.3] - 2026-04-15

### Fixed
- Fix seed_analysis_findings to create findings for all samples (d070fad)
- Add locked-scope hint to SoW scope cards for all engagement types (6beaa8f)
- Show 'Save finding' instead of 'Create finding' on edit pages (b704bc1)

## [1.2.2] - 2026-04-14

### Fixed
- Fix update.sh to handle fresh installs automatically (b16ddf1)
- Add seed_permissions management command for update.sh (f379d9b)

## [1.2.1] - 2026-04-14

### Fixed
- Fix 22 spec files to match updated Engagement and Subscription types (1280378)

## [1.2.0] - 2026-04-14

### Added
- Project feature to group related engagements with client/date inheritance
- Project assignment card on engagement view (assign/remove from project)
- Setup Wizard action on project engagements table for planned engagements
- Projects can be created without engagements (add/assign later)
- Digital forensics engagement type with evidence source model and metadata fields
- Engagement type registry with NgComponentOutlet for type-specific components
- Interactive widget grid for engagement visualize section
- Engagement type filter on engagements list page
- Expandable description panel on findings list tables
- PE analysis templates: File Type, Compile Time, Packer Detection, PE Sections, Special Strings, Extract Strings
- Overlay anomaly detection for PE Sections and Packer Detection analysis checks

### Changed
- Engagement type components moved to `types/` directory with registry pattern
- SoW scope, findings tables, and finding forms extracted into composable type-specific components
- Wizard returns to project view when launched from project context
- Success toast notifications removed where result is visually obvious
- Duration field in wizard shows calendar days and work days
- Community Edition limit set to 5 users per workspace

### Fixed
- Project card: hide current project from dropdown, separate remove action
- Drop zone hover and clicks blocked by bc-card::before overlay
- Visual gap between stacked bar segments in charts
- Horizontal bar charts inheriting wrong height
- Oversized bar chart when dashboard has few items
- Markdown heading font sizes in expand panel
- Wizard evidence table showing raw JSON instead of type label

### Tests
- 476 new API unit tests (87% → 93% coverage)
- 399 new UI unit tests (85% → 97% coverage)

## [1.1.0] - 2026-03-31

### Added
- Engagement type selection screen before wizard (b25d099)
- Engagement type shown in wizard header footer (29fa8a7)
- Malware sample upload in engagement wizard with drag-over highlight (d0a7bd3, 30aff64)
- Separate BC_MAX_SAMPLE_BYTES setting for malware uploads (2f84980)
- Analysis type field (static/dynamic) on malware findings (b8f238d)
- Composed findings list tables and finding forms per engagement type (e220b54, 60006bf)
- Automated static analysis for malware samples (26d9e65)
- Executable finding placeholders — per-finding Execute button replaces batch analysis (4421b93)
- Initialize Analysis button to seed analysis checks idempotently (4421b93)
- Per-row delete with inline Yes/No confirmation on malware findings table (7c6b315)
- Engagement-type-specific report titles for Open/Closed reports (cfca8b3)

### Changed
- Production config updated for 200 MB malware sample uploads (0512944)
- Static analysis runs in background thread for real-time progress (2ead752)
- CI: remove push-to-main trigger, rely on release workflow for tag-based testing (5a9c8a6)

### Fixed
- KeyError when JobService returns 'job_id' not 'id' (c394ba4, bd40c40, 5aeaaa6)

## [1.0.2] - 2026-03-27

### Changed
- CI: also run on push to main (8265037)
- CI: only run on pull requests, not on every push (9eda2a8)
- CI: only run on development push and PRs, not main push (314260d)
- Docs: update README environment variables table and community limits

## [1.0.1] - 2026-03-26

### Fixed
- Health check tests now pass in CI environments without Redis or media storage

## [1.0.0] - 2026-03-26

### Added
- Multi-tenant workspace with role-based access (Owner, Admin, Analyst, Viewer)
- Client and asset management (HOST, WEBAPP, API, CLOUD, NETWORK_DEVICE, MOBILE_APP)
- Engagement lifecycle with Statement of Work and scope management
- Security findings with severity tracking (Critical, High, Medium, Low, Info)
- Evidence management with local and S3 storage backends
- Markdown editor for finding descriptions
- Image upload and attachment support
- Dashboard with KPIs, findings trends, and activity feed
- JWT authentication with token rotation and blacklisting
- MFA (TOTP) support
- Setup wizard for first-run configuration
- Email notifications via Celery workers
- Automated backup and restore scripts
- Self-signed SSL certificate generation
- Docker Compose orchestration (PostgreSQL, Redis, Django, Celery, Nginx)
- Version-aware update system with rollback support
