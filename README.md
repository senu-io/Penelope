<p align="center">
  <img src="assets/logo/logo_128.png" alt="Penelope logo" width="88">
</p>

<h1 align="center">Penelope</h1>

<p align="center">
  Warehouse inventory, stock ledger, and audit management system.<br>
  <a href="LICENSE"><img src="https://img.shields.io/badge/license-Apache%202.0-326E6E" alt="Apache 2.0 License"></a>
  <img src="https://img.shields.io/badge/status-active%20development-CE7D36" alt="Status: Active Development">
</p>

---

Penelope is a self-hosted warehouse inventory management system backed by Rust (`Axum` + `SQLx`), PostgreSQL 16, and a planned React 18 web client. Progress and open tasks are tracked in [TODO.md](TODO.md).

## Features (Planned & In Progress)

- Product and SKU catalog supporting barcodes, categories, units of measure (`ea`, `box`, `pallet`, `kg`, `l`, `m`), bin locations, reorder thresholds, and Moving Weighted Average (MWA) EUR cost tracking (`total_cost_basis_eur` + `unit_cost_eur`).
- Idempotent, locked stock movements (`receive`, `dispatch`, `cycle_count`, `damage`) written through append-only ledger and audit triggers in PostgreSQL.
- Role-based access control (`admin`, `manager`, `operator`) backed by Argon2id password hashing, HttpOnly sessions (HMAC-SHA256 hashed with `SESSION_SECRET`) with Origin/Referer CSRF checks, SHA-256 scoped API keys, and versioned AES-256-GCM field encryption for private product notes.
- Three-tier PostgreSQL privilege separation (`postgres` bootstrap superuser, non-superuser `penelope_owner` migration role, and least-privilege `penelope_app` runtime role).
- CSV/JSON bulk import and export (`data_io`), low-stock overview reporting, and printable Code-128/QR SKU labels.

## Technology Stack

| Layer | Technology |
| :--- | :--- |
| Backend | Rust, Axum, Tokio, SQLx, Tower, Rust Decimal |
| Database | PostgreSQL 16 |
| Cryptography | Argon2id, Versioned AES-256-GCM + AAD, SHA-256 |
| Frontend | React 18, Vite, TypeScript, Tailwind CSS, TanStack Table & Query |

## Repository Structure

```text
.
├── assets/                 # Project logos
├── backend/                # Rust backend (Axum, SQLx migrations, integration tests)
├── frontend/               # Web assets and planned React + Vite client
├── unit_test/              # Test runner script and fixtures
├── .sample_env.env         # Environment configuration template
├── docker-compose.yml      # PostgreSQL 16 service
├── TODO.md                 # Task checklist and commit history
├── THIRD_PARTY_NOTICES.md  # Licenses for bundled fonts and icons
└── LICENSE                 # Apache License 2.0
```

## Quick Start

Copy `.sample_env.env` to `.env`, replace the `CHANGE_ME_*` secrets, and start PostgreSQL:

```powershell
cp .sample_env.env .env
docker compose up -d
```

Run backend formatting, clippy, unit tests, and database integration tests:

```powershell
.\unit_test\scripts\run_tests.ps1 -Suite backend
```

For individual test targets, see [unit_test/Test_Info.md](unit_test/Test_Info.md).

## Configuration

Set these values in `.env` (never commit `.env` to Git):

- `POSTGRES_USER` and `POSTGRES_PASSWORD`: Bootstrap superuser (`postgres`) used by `backend/docker/init-db.sh` only when the PostgreSQL volume is empty. Re-create the volume with `docker compose down -v && docker compose up -d` if role settings change.
- `POSTGRES_OWNER_USER`, `POSTGRES_OWNER_PASSWORD`, and `MIGRATION_DATABASE_URL`: Non-superuser schema owner (`penelope_owner`) used for migrations (required when `RUN_MIGRATIONS_ON_STARTUP=true` and rejected if equal to `DATABASE_URL`).
- `POSTGRES_APP_USER`, `POSTGRES_APP_PASSWORD`, and `DATABASE_URL`: Least-privilege runtime connection (`penelope_app`) used by the backend.
- `SESSION_SECRET`: 256-bit (64-character hex) secret generated via `openssl rand -hex 32` (placeholders, non-hex, and all-zero values are rejected).
- `PENELOPE_ACTIVE_KEY_ID` and `PENELOPE_ENCRYPTION_KEYS`: Versioned `<id>:<64_hex_chars>` keyring for `AES-256-GCM` field encryption.
- `BOOTSTRAP_INITIAL_ADMIN`, `INITIAL_ADMIN_EMAIL`, and `INITIAL_ADMIN_PASSWORD`: Optional first-run admin bootstrap (enforces a minimum 12-character password and valid email when enabled).
- `FRONTEND_ORIGIN` and `COOKIE_SECURE`: Allowed comma-separated CORS/CSRF origins (`http://localhost:5173` by default) and `Secure` cookie + HSTS toggle (`false` locally, `true` behind HTTPS).
- `SESSION_IDLE_TTL_HOURS`, `SESSION_ABSOLUTE_TTL_HOURS`, `RATE_LIMIT_AUTH_PER_MIN`, and `RATE_LIMIT_API_PER_MIN`: Session timeout windows (`24` / `168` hours) and IP rate-limit buckets (`10` / `120` requests per minute).

## License

Licensed under the [Apache License, Version 2.0](LICENSE). Third-party font and icon licenses are listed in [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md).
