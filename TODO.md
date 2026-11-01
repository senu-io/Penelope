# Penelope Development To-Do & Commit Log

This document tracks the modular implementation progress and version control history of **Penelope**. Tasks are marked `[x]` only when their implementation and automated verification tests pass.

---

## Phase 0: Project Setup, Governance & Asset Mirroring
- [x] Clone repository and establish workspace boundaries
- [x] Define product requirements, architecture, Tideline design system, and security baselines
- [x] Mirror licensed fonts (`JetBrains Mono`, `Fira Code`, `Comfortaa`, `Public Sans`, `Schibsted Grotesk`, `Martian Mono`) and `Phosphor` icons into `assets/` and `frontend/public/assets/`
- [x] Configure `.gitignore`, `.sample_env.env`, and `THIRD_PARTY_NOTICES.md`
- [x] Configure `unit_test/` (public) and `unit_test/.private_tests/` (gitignored) test runner and report pipeline
- [x] Update `README.md` and `LICENSE` (Apache 2.0, Copyright 2026 Senuke Weragama)

## Module 1: Database Schema, Cryptographic Core & Backend Foundation
- [ ] Add `docker-compose.yml` for PostgreSQL 16 with healthchecks and persistent volume
- [ ] Initialize Rust backend crate (`backend/Cargo.toml` and tracked `backend/Cargo.lock`) with exact version pins
- [ ] Write initial SQLx schema migration (`0001_initial_schema.sql`) with `NUMERIC(14,4)` fixed-point quantities, `base_unit` / `allow_fractional`, ISO 4217 `currency_code`, `ck_ledger_math` (`new_qty = previous_qty + delta`), `sync_product_balance_from_ledger` trigger, and `UPDATE`/`DELETE`/`TRUNCATE` append-only triggers
- [ ] Implement `config.rs` (multi-key `KeyRing`, controlled migration flag, initial admin bootstrap) and standardized JSON `AppError` (`error.rs`)
- [ ] Implement `crypto.rs` (`Argon2id` password hashing, versioned `AES-256-GCM` field encryption with contextual AAD `[0x01 | key_id (2B) | nonce (12B) | ciphertext + tag]`, 256-bit API keys `pen_live_<64_hex>` & `SHA-256` hashing)
- [ ] Implement separated persistence (`*Record`, non-serializable) and public API (`*Response`) models, `AppState`, and `/api/v1/health/live` + `/api/v1/health/ready`
- [ ] Pass `cargo fmt --check`, `cargo clippy -- -D warnings`, crypto unit tests, and PostgreSQL integration & concurrent stock movement tests (`tests/db_integrity_and_concurrency.rs`)

## Module 2: Authentication, RBAC Guards, Scoped API Keys & Audit Service
- [ ] Implement `guards/` (HttpOnly session cookie extractor, CSRF `X-Requested-With` & `Origin` verification, `X-API-Key` extractor, `Admin`/`Manager`/`Operator` RBAC guards, rate limiting, and HTTP security headers)
- [ ] Implement initial administrator bootstrap and `services/audit.rs` for append-only security and activity logging
- [ ] Implement `/api/v1/auth/*` (`/login`, `/logout`, `/me`) and `/api/v1/admin/*` (user & scoped API key management)
- [ ] Pass Module 2 unit and PostgreSQL security boundary integration tests

## Module 3: Catalog Engine, ACID Stock Ledger & Data Exchange (`data_io`)
- [ ] Implement `services/catalog.rs` and `/api/v1/products/*` (SKU CRUD, versioned `AES-256-GCM` + AAD note encryption, barcode scanner `/lookup`)
- [ ] Implement `services/ledger.rs` and `/api/v1/inventory/*` (transactional `SELECT ... FOR UPDATE` stock adjustments and currency-aware valuation summary)
- [ ] Implement `services/data_io.rs` and `/api/v1/data-io/*` (RFC 4180 CSV & JSON bulk import/export with formula-injection escaping)
- [ ] Implement warehouse seed runner and pass Module 3 unit and transactional integration tests

## Module 4: Frontend Shell, Tideline Design System, Auth & Operational Overview
- [ ] Initialize React 18 + Vite + TypeScript + Tailwind CSS + TanStack Query/Table in `frontend/`
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
