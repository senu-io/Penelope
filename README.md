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

> [!NOTE]
> **Implementation Status:** Penelope is currently in **Module 1 (Step 1 Complete: Infrastructure & Crate Initialization)**. The PostgreSQL 16 Docker Compose stack (`postgres` bootstrap superuser, non-superuser `penelope_owner` migration role, and least-privilege `penelope_app` runtime role) and the `penelope-backend` Rust crate (`backend/Cargo.toml` and `backend/Cargo.lock`) have been initialized, while database SQL migrations (`backend/migrations/`), the application HTTP server and business logic (`backend/src/`), and the React web client (`frontend/src/`) remain unimplemented and are tracked module-by-module in [TODO.md](TODO.md).

Penelope is a self-hosted warehouse inventory management system designed around a Rust (`Axum` + `SQLx`) backend, a PostgreSQL 16 relational ledger, and a React 18 web interface.

## Planned Capabilities

- **Catalog and SKU Control:** Track SKUs, barcodes, categories, base units of measure (`ea`, `box`, `pallet`, `kg`, `l`, `m`), fixed-point `NUMERIC(14, 4)` quantities, bin coordinates, reorder thresholds, and Moving Weighted Average (MWA) `EUR` cost tracking (`total_cost_basis_eur NUMERIC(28, 6)` and `unit_cost_eur NUMERIC(18, 6)`).
- **Transactional Stock Ledger:** Execute every stock change (`Receive`, `Dispatch`, `Cycle Count`, `Damage`) idempotently through a locked PostgreSQL transaction that atomically updates the product balance and cost basis, records an append-only ledger entry, and writes a security audit event.
- **Operational Overview:** Monitor total inventory valuation, low-stock items below their reorder threshold, and recent stock movements from a single screen.
- **Data Exchange (`data_io`):** Import and export catalog records, ledger history, and audit trails in RFC 4180 CSV and JSON formats.
- **Barcode and Label Workflow:** Fast keyboard-wedge barcode lookup paired with printable Code-128 and QR bin labels.
- **Security and Access Control:** Argon2id password hashing, HttpOnly session cookies with CSRF protection, role-based access control (`Admin`, `Manager`, `Operator`), 256-bit SHA-256 scoped API keys, three-tier PostgreSQL role separation (`postgres` bootstrap superuser, non-superuser `penelope_owner` schema owner, and least-privilege `penelope_app` runtime role), and versioned AES-256-GCM field encryption with contextual AAD for confidential product notes.

## Technology Stack

| Layer | Technology |
| :--- | :--- |
| **Backend** | Rust, Axum, Tokio, SQLx, Tower, Rust Decimal |
| **Database** | PostgreSQL 16 |
| **Cryptography** | Argon2id, Versioned AES-256-GCM + AAD, SHA-256 |
| **Frontend** | React 18, Vite, TypeScript, Tailwind CSS, TanStack Table & Query |

## Repository Structure

```text
.
├── assets/                 # Fonts, icons, schematics, and brand logos
├── backend/                # Rust (Axum + SQLx) crate scaffold and Docker DB init script
├── frontend/               # React + Vite + TypeScript web client (planned)
├── unit_test/              # Public unit test scripts, fixtures, and local reports
├── .sample_env.env         # Environment configuration template
├── docker-compose.yml      # PostgreSQL 16 container stack
├── TODO.md                 # Modular development checklist and commit log
├── THIRD_PARTY_NOTICES.md  # Licenses and attributions for bundled assets
└── LICENSE                 # Apache License 2.0
```

## Configuration

Copy `.sample_env.env` to `.env` before starting the backend or container stack:

```bash
cp .sample_env.env .env
```

Configure the following in `.env`:
- `POSTGRES_USER` and `POSTGRES_PASSWORD`: Bootstrap superuser (`postgres`) used by the PostgreSQL container entrypoint on first volume initialization (`backend/docker/init-db.sh`). Note that `/docker-entrypoint-initdb.d/` scripts run only when the `penelope_postgres_data` volume is initially empty; run `docker compose down -v && docker compose up -d` if re-initializing roles.
- `POSTGRES_OWNER_USER`, `POSTGRES_OWNER_PASSWORD`, and `MIGRATION_DATABASE_URL`: Non-superuser schema owner connection (`penelope_owner`) used exclusively for running database migrations.
- `POSTGRES_APP_USER`, `POSTGRES_APP_PASSWORD`, and `DATABASE_URL`: Least-privilege runtime connection (`penelope_app`) used by the Axum server.
- `PENELOPE_ACTIVE_KEY_ID` and `PENELOPE_ENCRYPTION_KEYS`: Versioned 256-bit (64-character hex) keyring for `AES-256-GCM` field encryption. Generate a real key via `openssl rand -hex 32` (missing, malformed, or all-zero keys are rejected at startup).

Never commit `.env` files to version control.

## License

Licensed under the [Apache License, Version 2.0](LICENSE). Third-party font and icon notices are listed in [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md).
