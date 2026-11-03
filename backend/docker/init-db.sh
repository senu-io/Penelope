#!/bin/sh
set -eu

# ============================================================================
# PENELOPE - POSTGRESQL 16 DUAL-ROLE & SCHEMA PRIVILEGE INITIALIZATION
# Executed automatically by the official postgres:16-alpine entrypoint on
# first container initialization (/docker-entrypoint-initdb.d/01-init-db.sh).
# ============================================================================

APP_USER="${POSTGRES_APP_USER:-penelope_app}"
APP_PASSWORD="${POSTGRES_APP_PASSWORD:?POSTGRES_APP_PASSWORD is required}"

# Escape single quotes in identifiers/passwords for safe SQL literal interpolation
ESCAPED_APP_USER=$(printf "%s" "$APP_USER" | sed "s/\"/\"\"/g")
ESCAPED_APP_PASS=$(printf "%s" "$APP_PASSWORD" | sed "s/'/''/g")

psql -v ON_ERROR_STOP=1 --username "$POSTGRES_USER" --dbname "$POSTGRES_DB" <<-EOSQL
    DO \$\$
    BEGIN
        IF NOT EXISTS (
            SELECT 1 FROM pg_catalog.pg_roles WHERE rolname = '${APP_USER}'
        ) THEN
            CREATE ROLE "${ESCAPED_APP_USER}" WITH
                LOGIN
                PASSWORD '${ESCAPED_APP_PASS}'
                NOSUPERUSER
                NOCREATEDB
                NOCREATEROLE
                NOREPLICATION
                NOBYPASSRLS;
        ELSE
            ALTER ROLE "${ESCAPED_APP_USER}" WITH
                LOGIN
                PASSWORD '${ESCAPED_APP_PASS}'
                NOSUPERUSER
                NOCREATEDB
                NOCREATEROLE
                NOREPLICATION
                NOBYPASSRLS;
        END IF;
    END
    \$\$;

    -- Lock down database-level and public-schema privileges
    REVOKE ALL ON DATABASE "${POSTGRES_DB}" FROM PUBLIC;
    GRANT CONNECT ON DATABASE "${POSTGRES_DB}" TO "${ESCAPED_APP_USER}";

    REVOKE ALL ON SCHEMA public FROM PUBLIC, "${ESCAPED_APP_USER}";
    GRANT USAGE ON SCHEMA public TO "${ESCAPED_APP_USER}";

    -- Ensure future functions created by penelope_owner are never executable by PUBLIC
    ALTER DEFAULT PRIVILEGES FOR ROLE "${POSTGRES_USER}"
        REVOKE EXECUTE ON FUNCTIONS FROM PUBLIC;
EOSQL
