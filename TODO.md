# Penelope Development To-Do & Commit Log

Tasks are checked off only after implementation and tests pass.

---

## Phase 0: Setup & Assets
- [x] Clone repository and establish workspace layout
- [x] Define product requirements, architecture, design tokens, and security baseline
- [x] Bundle fonts (`JetBrains Mono`, `Fira Code`, `Comfortaa`, `Public Sans`, `Schibsted Grotesk`, `Martian Mono`), `Phosphor` icons, and logos in `frontend/public/assets/` and `assets/logo/`
- [x] Configure `.gitignore`, `.sample_env.env` (dual runtime/migration roles and placeholder keys), and `THIRD_PARTY_NOTICES.md`
- [x] Configure `unit_test/` runner with modular backend targets and zero-test protection
- [x] Update `README.md` and `LICENSE` (Apache 2.0)

## Module 1: Database Schema, Cryptographic Core & Backend Foundation
- [x] Add `docker-compose.yml` and `backend/docker/init-db.sh` for PostgreSQL 16 (`postgres` bootstrap, non-superuser `penelope_owner` migration role, `penelope_app` runtime role)
- [x] Initialize Rust crate (`backend/Cargo.toml` and `backend/Cargo.lock`) with exact dependency pins
- [x] Write `0001_initial_schema.sql` with schema lock-down, MWA cost columns (`total_cost_basis_eur`, `unit_cost_eur`), column-restricted `products` grants, `SELECT`-only ledger/audit grants, `SECURITY DEFINER` ledger & audit functions (`P0409` idempotency check, `(entity_type, action)` whitelist), and append-only triggers
- [x] Implement `config.rs` (`AppConfig::from_pairs`/`from_lookup`, distinct `MIGRATION_DATABASE_URL`, role verification, 64-char hex `SESSION_SECRET`, multi-key `KeyRing`, initial admin password check) and `error.rs` (`AppError` JSON responses)
- [x] Implement `crypto.rs` (`Argon2id` password hashing, versioned `AES-256-GCM` field encryption with header/contextual AAD, `pen_live_<64_hex>` API keys & `SHA-256` session tokens)
- [x] Implement separated `*Record` and `*Response` models with normalized `Decimal` validation, `AppState`, and `/api/v1/health/live` + `/api/v1/health/ready`
- [x] Pass `cargo fmt --check`, `cargo clippy -- -D warnings`, crypto unit tests, and PostgreSQL integration tests (`db_role_boundaries`, `db_concurrency_and_idempotency`, `db_mwa_and_append_only`, `http_health`)

## Module 2: Authentication, RBAC Guards, Scoped API Keys & Audit Service
- [x] Implement `guards/` (HttpOnly session cookie extractor, CSRF checks, `X-API-Key` extractor, `Admin`/`Manager`/`Operator` guards, rate limiting, security headers)
- [x] Implement initial admin bootstrap and `services/audit.rs` calling `public.record_audit_event` transactionally
- [ ] Implement `/api/v1/auth/*` (`/login`, `/logout`, `/me`) and `/api/v1/admin/*` (users and API keys)
- [ ] Pass Module 2 unit and PostgreSQL security boundary integration tests

## Module 3: Catalog Engine, ACID Stock Ledger & Data Exchange (`data_io`)
- [ ] Implement `services/catalog.rs` and `/api/v1/products/*` (SKU CRUD, encrypted notes, barcode `/lookup`)
- [ ] Implement `services/ledger.rs` and `/api/v1/inventory/*` (idempotent stock movements and MWA valuation summary)
- [ ] Implement `services/data_io.rs` and `/api/v1/data-io/*` (CSV and JSON import/export with formula escaping)
- [ ] Implement seed runner and pass Module 3 unit and integration tests

## Module 4: Frontend Shell, Design System, Auth & Operational Overview
- [ ] Initialize React 18 + Vite + TypeScript + Tailwind CSS + TanStack Query/Table in `frontend/`
- [ ] Configure Tideline palette tokens (`#326E6E`, `#CE7D36`, `#C5CFCB`) and local `@font-face` rules
- [ ] Build app shell (sidebar navigation, quick barcode search, mobile bottom bar)
- [ ] Build Sign-In screen and Overview dashboard (summary metrics, valuation chart, low-stock table, recent movements)
- [ ] Pass Module 4 frontend unit tests and UI checks

## Module 5: Interactive Catalog, Barcode Labels, Stock Ledger, `data_io` & Audit UI
- [ ] Build Catalog view (SKU table, filters, create/edit drawer, printable SVG Code-128/QR labels)
- [ ] Build Stock Ledger view and stock adjustment modal
- [ ] Build Data Exchange (`data_io`) CSV/JSON import-export modal
- [ ] Build Audit Log viewer and Admin Access & API Keys management screen
- [ ] Run end-to-end public and local test suites

---

## Commit History

| Commit | Date | Message |
| :--- | :--- | :--- |
| `3e59364` | 2026-10-30 | `Initial commit` |
| `4ad8aa7` | 2026-11-01 | `setup: initialize base project structure` |
| `ba32cbc` | 2026-11-01 | `Updated README.md` |
| `d297bc2` | 2026-11-01 | `Updated LICENSE` |
| `2451bd0` | 2026-11-01 | `setup: configure unit_test layout and update documentation` |
| `c3cb51b` | 2026-11-01 | `init: add project TODO tracker and harden test runner & env template` |
| `17b8b6e` | 2026-11-01 | `fix: separate DB migration/runtime roles, fix test runner path, and sync docs` |
| `97701fb` | 2026-11-01 | `fix: harden test runner boundaries and align MWA/security specs in docs` |
| `87a0f1f` | 2026-11-03 | `feat(backend): initialize Rust crate, PostgreSQL 16 compose stack, and dual-role init script` |
| `847b3c4` | 2026-11-04 | `fix(infra): make penelope_owner non-superuser, replace zero-key placeholder, and ignore test reports` |
| `bead170` | 2026-11-04 | `feat(db): add initial PostgreSQL 16 schema, SECURITY DEFINER ledger functions, and concurrency tests` |
| `b3109dd` | 2026-11-04 | `Updated README.md` |
| `4f15928` | 2026-11-04 | `fix(db): align api_keys check in record_stock_movement with role_scope column` |
| `67f739e` | 2026-11-04 | `feat(backend): implement AppConfig, multi-key KeyRing, and AppError envelope` |
| `ab58a29` | 2026-11-05 | `docs: Updated Test_Info.md` |
| `1387e2d` | 2026-11-05 | `fix(config): align AppConfig parser with .sample_env.env and add SESSION_SECRET` |
| `f106be3` | 2026-11-05 | `test(infra): updated README.md and modified test comments` |
| `a9855db` | 2026-11-05 | `test(infra): split integration tests into modular targets and granular runner` |
| `ea19e88` | 2026-11-06 | `fix(test): validate -Target parameter and enforce strict role identity in test pools` |
| `2249505` | 2026-11-06 | `fix(config): reject placeholder secrets and enforce session secret and admin password policies` |
| `9088686` | 2026-11-06 | `refactor(config): decouple AppConfig parser from OS environment for isolated unit tests` |
| `8e5612e` | 2026-11-06 | `fix(config): require distinct MIGRATION_DATABASE_URL when startup migrations are enabled` |
| `122421c` | 2026-11-06 | `docs: sync TODO commit log, README config docs, and Test_Info target notes` |
| `34c7da3` | 2026-11-09 | `fix(config,test): enforce db role principals and verify mig_pool identity` |
| `1bc94a9` | 2026-11-21 | `fix(backend): tighten config checks, split db tests, and clean up schema` |
| `6f4b7f0` | 2026-11-21 | `chore: drop duplicate assets and update docs` |
| `53b4443` | 2026-11-24 | `feat(backend): add crypto helpers for argon2id, aes-gcm, and api keys` |
| `4122157` | 2026-11-25 | `feat(backend): add domain models, app state, and health endpoints` |
| `3afb33e` | 2026-11-27 | `feat(backend): add audit service, admin bootstrap, and security guards` |
