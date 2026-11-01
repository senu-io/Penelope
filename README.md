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
> **Project Status:** Penelope is currently under active development. Interfaces, database schemas, and API endpoints are subject to change prior to the initial stable release.

Penelope is a self-hosted warehouse inventory management system built with a Rust backend, a PostgreSQL relational ledger, and a React web interface. It tracks catalog SKUs, bin locations, stock movements, and security audit logs with strict transactional integrity.

## Capabilities

- **Catalog and SKU Control:** Track SKUs, barcodes, categories, base units of measure (`ea`, `box`, `pallet`, `kg`, `l`, `m`), fixed-point `NUMERIC(14, 4)` quantities, bin coordinates, reorder thresholds, and Moving Weighted Average (MWA) euro-cent (`EUR`) unit costs.
- **Transactional Stock Ledger:** Every stock change (`Receive`, `Dispatch`, `Cycle Count`, `Damage`) executes idempotently through a locked PostgreSQL transaction that atomically updates the product balance, records an append-only ledger entry, and writes a security audit event.
- **Operational Overview:** Monitor total inventory valuation, low-stock items below their reorder threshold, and recent stock movements from a single screen.
- **Data Exchange (`data_io`):** Import and export catalog records, ledger history, and audit trails in RFC 4180 CSV and JSON formats.
- **Barcode and Label Workflow:** Fast keyboard-wedge barcode lookup paired with printable Code-128 and QR bin labels.
- **Security and Access Control:** Argon2id password hashing, HttpOnly session cookies with CSRF protection, role-based access control (`Admin`, `Manager`, `Operator`), 256-bit SHA-256 scoped API keys, least-privilege database role separation (`penelope_owner` vs `penelope_app`), and versioned AES-256-GCM field encryption with contextual AAD for confidential product notes.

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
├── backend/                # Rust (Axum + SQLx) HTTP API server and SQL migrations
├── frontend/               # React + Vite + TypeScript web client
├── unit_test/              # Public unit test suites, fixtures, and reports
├── .sample_env.env         # Environment configuration template
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
- `MIGRATION_DATABASE_URL`: Privileged schema owner connection (`penelope_owner`) used exclusively for running database migrations.
- `DATABASE_URL`: Least-privilege runtime connection (`penelope_app`) used by the Axum server.
- `PENELOPE_ACTIVE_KEY_ID` and `PENELOPE_ENCRYPTION_KEYS`: Versioned 256-bit (64-character hex) keyring for `AES-256-GCM` field encryption.

Never commit `.env` files to version control.

## License

Licensed under the [Apache License, Version 2.0](LICENSE). Third-party font and icon notices are listed in [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md).
