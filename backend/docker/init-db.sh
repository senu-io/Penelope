#!/bin/sh
set -eu

# NOTE: postgres only runs /docker-entrypoint-initdb.d scripts when the data volume is empty.
# if you change this file later, run `docker compose down -v && docker compose up -d` to recreate the volume.

OWNER_USER="${POSTGRES_OWNER_USER:-penelope_owner}"
OWNER_PASSWORD="${POSTGRES_OWNER_PASSWORD:?POSTGRES_OWNER_PASSWORD is required}"
APP_USER="${POSTGRES_APP_USER:-penelope_app}"
APP_PASSWORD="${POSTGRES_APP_PASSWORD:?POSTGRES_APP_PASSWORD is required}"

# escape quotes before interpolating into sql
ESCAPED_OWNER_ID=$(printf "%s" "$OWNER_USER" | sed 's/"/""/g')
ESCAPED_OWNER_LIT=$(printf "%s" "$OWNER_USER" | sed "s/'/''/g")
ESCAPED_OWNER_PASS=$(printf "%s" "$OWNER_PASSWORD" | sed "s/'/''/g")

ESCAPED_APP_ID=$(printf "%s" "$APP_USER" | sed 's/"/""/g')
ESCAPED_APP_LIT=$(printf "%s" "$APP_USER" | sed "s/'/''/g")
ESCAPED_APP_PASS=$(printf "%s" "$APP_PASSWORD" | sed "s/'/''/g")

psql -v ON_ERROR_STOP=1 --username "$POSTGRES_USER" --dbname "$POSTGRES_DB" <<-EOSQL
    DO \$\$
    BEGIN
        -- migration role (non-superuser, owns the schema)
        IF NOT EXISTS (
            SELECT 1 FROM pg_catalog.pg_roles WHERE rolname = '${ESCAPED_OWNER_LIT}'
        ) THEN
            CREATE ROLE "${ESCAPED_OWNER_ID}" WITH
                LOGIN
                PASSWORD '${ESCAPED_OWNER_PASS}'
                NOSUPERUSER
                NOCREATEDB
                NOCREATEROLE
                NOREPLICATION
                NOBYPASSRLS;
        ELSE
            ALTER ROLE "${ESCAPED_OWNER_ID}" WITH
                LOGIN
                PASSWORD '${ESCAPED_OWNER_PASS}'
                NOSUPERUSER
                NOCREATEDB
                NOCREATEROLE
                NOREPLICATION
                NOBYPASSRLS;
        END IF;

        -- app runtime role (least privilege)
        IF NOT EXISTS (
            SELECT 1 FROM pg_catalog.pg_roles WHERE rolname = '${ESCAPED_APP_LIT}'
        ) THEN
            CREATE ROLE "${ESCAPED_APP_ID}" WITH
                LOGIN
                PASSWORD '${ESCAPED_APP_PASS}'
                NOSUPERUSER
                NOCREATEDB
                NOCREATEROLE
                NOREPLICATION
                NOBYPASSRLS;
        ELSE
            ALTER ROLE "${ESCAPED_APP_ID}" WITH
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

    -- hand ownership of the db and public schema to penelope_owner
    ALTER DATABASE "${POSTGRES_DB}" OWNER TO "${ESCAPED_OWNER_ID}";
    ALTER SCHEMA public OWNER TO "${ESCAPED_OWNER_ID}";

    -- lock down public access and schema creation
    REVOKE ALL ON DATABASE "${POSTGRES_DB}" FROM PUBLIC;
    GRANT CONNECT ON DATABASE "${POSTGRES_DB}" TO "${ESCAPED_OWNER_ID}", "${ESCAPED_APP_ID}";

    REVOKE ALL ON SCHEMA public FROM PUBLIC, "${ESCAPED_APP_ID}";
    GRANT ALL ON SCHEMA public TO "${ESCAPED_OWNER_ID}";
    GRANT USAGE ON SCHEMA public TO "${ESCAPED_APP_ID}";

    -- don't let PUBLIC execute functions created by penelope_owner by default
    ALTER DEFAULT PRIVILEGES FOR ROLE "${ESCAPED_OWNER_ID}"
        REVOKE EXECUTE ON FUNCTIONS FROM PUBLIC;
EOSQL
