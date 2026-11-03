# Penelope Development To-Do & Commit Log

This document tracks the modular implementation progress and version control history of **Penelope**. Tasks are marked `[x]` only when their implementation and automated verification tests pass.

---

## Phase 0: Project Setup, Governance & Asset Mirroring
- [x] Clone repository and establish workspace boundaries
- [x] Define product requirements, architecture, Tideline design system, and security baselines
- [x] Mirror licensed fonts (`JetBrains Mono`, `Fira Code`, `Comfortaa`, `Public Sans`, `Schibsted Grotesk`, `Martian Mono`) and `Phosphor` icons into `assets/` and `frontend/public/assets/`
- [x] Configure `.gitignore` (excluding `.env`, `unit_test/.private_tests/`, `backend/tests/private_suite.rs`, and `frontend/**/*.private.test.{ts,tsx}`), `.sample_env.env` (with `penelope_owner` / `penelope_app` separation), and `THIRD_PARTY_NOTICES.md`
- [x] Configure `unit_test/` (public) and `unit_test/.private_tests/` (gitignored) test runner with explicit `--test private_suite` / `vitest.private.config.ts` targets and non-zero executed test count verification
- [x] Update `README.md` (with clear Phase 0 implementation status and Planned Capabilities) and `LICENSE` (Apache 2.0, Copyright 2026 Senuke Weragama)

## Module 1: Database Schema, Cryptographic Core & Backend Foundation
- [x] Add `docker-compose.yml` and role initialization script (`backend/docker/init-db.sh`) for PostgreSQL 16 (`penelope_owner` migration role and `penelope_app` least-privilege runtime role)
- [x] Initialize Rust backend crate (`backend/Cargo.toml` and tracked `backend/Cargo.lock`) with exact version pins
- [ ] Write initial SQLx schema migration (`0001_initial_schema.sql`) with `CREATE ON SCHEMA public` revoked, global `ALTER DEFAULT PRIVILEGES FOR ROLE penelope_owner REVOKE EXECUTE ON FUNCTIONS FROM PUBLIC`, `NUMERIC(14,4)` quantities, `total_cost_basis_eur NUMERIC(28,6)` + `unit_cost_eur NUMERIC(18,6)` MWA costing with `prev_total_cost_basis_eur / prev_qty` cycle-count rules and line-item `NUMERIC(22,2)` reporting rounding, column-restricted `INSERT`/`UPDATE` on `products` (enforcing zero initial stock), `SELECT`-only grants on `stock_ledger`/`audit_logs`, `SECURITY DEFINER SET search_path = pg_catalog` functions (`public.record_stock_movement` & `public.record_audit_event`) with explicit `REVOKE EXECUTE ... FROM PUBLIC; GRANT EXECUTE ... TO penelope_app;`, internal `SHA-256` `request_hash` calculation (`ERRCODE = 'P0409'` on mismatch) under `READ COMMITTED`, finite `(entity_type, action)` whitelist in `record_audit_event`, and `UPDATE`/`DELETE`/`TRUNCATE` append-only triggers
- [ ] Implement `config.rs` (`DATABASE_URL` + `MIGRATION_DATABASE_URL`, multi-key `KeyRing`, controlled migration flag, initial admin bootstrap) and standardized JSON `AppError` (`error.rs` mapping `P0409` -> `409` and `P0422` -> `422`)
- [ ] Implement `crypto.rs` (`Argon2id` password hashing, versioned `AES-256-GCM` field encryption with contextual AAD `[0x01 | key_id (2B) | nonce (12B) | ciphertext + tag]`, 256-bit API keys `pen_live_<64_hex>` & `SHA-256` hashing)
- [ ] Implement separated persistence (`*Record`, non-serializable) and public API (`*Response`) models with normalized (`.normalize()`) decimal scale validation, `AppState`, and `/api/v1/health/live` + `/api/v1/health/ready`
- [ ] Pass `cargo fmt --check`, `cargo clippy -- -D warnings`, crypto unit tests, and PostgreSQL integration & concurrent stock movement tests (`tests/db_integrity_and_concurrency.rs`)

## Module 2: Authentication, RBAC Guards, Scoped API Keys & Audit Service
- [ ] Implement `guards/` (HttpOnly session cookie extractor, CSRF `X-Requested-With` & `Origin` verification, `X-API-Key` extractor, `Admin`/`Manager`/`Operator` RBAC guards, rate limiting, and HTTP security headers)
- [ ] Implement initial administrator bootstrap and `services/audit.rs` calling `public.record_audit_event` inside the same database transaction as catalog/admin mutations
- [ ] Implement `/api/v1/auth/*` (`/login`, `/logout`, `/me`) and `/api/v1/admin/*` (user & scoped API key management)
- [ ] Pass Module 2 unit and PostgreSQL security boundary integration tests

## Module 3: Catalog Engine, ACID Stock Ledger & Data Exchange (`data_io`)
- [ ] Implement `services/catalog.rs` and `/api/v1/products/*` (SKU CRUD, versioned `AES-256-GCM` + AAD note encryption, barcode scanner `/lookup`)
- [ ] Implement `services/ledger.rs` and `/api/v1/inventory/*` (idempotent stock adjustments via `public.record_stock_movement` and MWA valuation summary summing rounded line-item valuations)
- [ ] Implement `services/data_io.rs` and `/api/v1/data-io/*` (RFC 4180 CSV & JSON bulk import/export with formula-injection escaping)
- [ ] Implement warehouse seed runner and pass Module 3 unit and transactional integration tests

## Module 4: Frontend Shell, Tideline Design System, Auth & Operational Overview
- [ ] Initialize React 18 + Vite + TypeScript + Tailwind CSS + TanStack Query/Table in `frontend/` (with `vitest.config.ts` excluding `**/*.private.test.{ts,tsx}` and `vitest.private.config.ts` selecting only `**/*.private.test.{ts,tsx}`)
- [ ] Configure Tideline palette tokens (`#326E6E`, `#CE7D36`, `#C5CFCB`) and local `@font-face` declarations
- [ ] Build application layout shell (neutral sidebar, quick barcode scanner bar, mobile bottom bar)
- [ ] Build Sign-In screen and Operational Overview dashboard (ruled 4-figure KPI strip, valuation chart, low-stock triage, recent ledger movements)
- [ ] Pass Module 4 frontend unit tests and UI verification checks

## Module 5: Interactive Catalog, Barcode Label Printer, Stock Ledger, `data_io` & Audit UI
- [ ] Build interactive Catalog screen (tabular SKU table, filters, create/edit drawer, printable SVG Code-128/QR label sheet)
- [ ] Build Stock Ledger view and atomic stock adjustment modal
- [ ] Build Data Exchange (`data_io`) CSV/JSON import-export modal
- [ ] Build Security Audit Log viewer and Admin Access & API Keys management screen
- [ ] Run full end-to-end public and private unit and integration test suites

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
