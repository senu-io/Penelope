-- 0001_initial_schema.sql
-- initial schema, role grants, append-only triggers, and security definer functions
-- executed by penelope_owner (non-superuser migration role)

-- lock down public schema and default function execute permissions
REVOKE ALL ON SCHEMA public FROM PUBLIC, penelope_app;
GRANT USAGE ON SCHEMA public TO penelope_app;

ALTER DEFAULT PRIVILEGES FOR ROLE penelope_owner
    REVOKE EXECUTE ON FUNCTIONS FROM PUBLIC;

-- 1. users
CREATE TABLE IF NOT EXISTS public.users (
    id UUID PRIMARY KEY DEFAULT pg_catalog.gen_random_uuid(),
    email TEXT NOT NULL UNIQUE CHECK (pg_catalog.length(pg_catalog.btrim(email)) > 0),
    full_name TEXT NOT NULL CHECK (pg_catalog.length(pg_catalog.btrim(full_name)) > 0),
    password_hash TEXT NOT NULL CHECK (pg_catalog.length(pg_catalog.btrim(password_hash)) > 0),
    role TEXT NOT NULL CHECK (role IN ('admin', 'manager', 'operator')),
    is_active BOOLEAN NOT NULL DEFAULT TRUE,
    last_login_at TIMESTAMPTZ NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT pg_catalog.now()
);

-- 2. sessions
CREATE TABLE IF NOT EXISTS public.sessions (
    id UUID PRIMARY KEY DEFAULT pg_catalog.gen_random_uuid(),
    user_id UUID NOT NULL REFERENCES public.users(id) ON DELETE CASCADE,
    token_hash CHAR(64) NOT NULL UNIQUE CHECK (token_hash ~ '^[0-9a-f]{64}$'),
    ip_address TEXT NOT NULL DEFAULT '',
    user_agent TEXT NOT NULL DEFAULT '',
    last_active_at TIMESTAMPTZ NOT NULL DEFAULT pg_catalog.now(),
    expires_at TIMESTAMPTZ NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT pg_catalog.now()
);

CREATE INDEX IF NOT EXISTS idx_sessions_user_id ON public.sessions(user_id);
CREATE INDEX IF NOT EXISTS idx_sessions_expires_at ON public.sessions(expires_at);

-- 3. api_keys
CREATE TABLE IF NOT EXISTS public.api_keys (
    id UUID PRIMARY KEY DEFAULT pg_catalog.gen_random_uuid(),
    name TEXT NOT NULL CHECK (pg_catalog.length(pg_catalog.btrim(name)) > 0),
    key_prefix TEXT NOT NULL CHECK (pg_catalog.length(pg_catalog.btrim(key_prefix)) > 0),
    key_hash CHAR(64) NOT NULL UNIQUE CHECK (key_hash ~ '^[0-9a-f]{64}$'),
    role_scope TEXT NOT NULL CHECK (role_scope IN ('manager', 'operator', 'readonly')),
    created_by UUID NOT NULL REFERENCES public.users(id) ON DELETE RESTRICT,
    last_used_at TIMESTAMPTZ NULL,
    expires_at TIMESTAMPTZ NULL,
    revoked_at TIMESTAMPTZ NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT pg_catalog.now()
);

CREATE INDEX IF NOT EXISTS idx_api_keys_created_by ON public.api_keys(created_by);

-- 4. categories
CREATE TABLE IF NOT EXISTS public.categories (
    id UUID PRIMARY KEY DEFAULT pg_catalog.gen_random_uuid(),
    name TEXT NOT NULL UNIQUE CHECK (pg_catalog.length(pg_catalog.btrim(name)) > 0),
    code TEXT NOT NULL UNIQUE CHECK (pg_catalog.length(pg_catalog.btrim(code)) > 0),
    description TEXT NOT NULL DEFAULT '',
    created_at TIMESTAMPTZ NOT NULL DEFAULT pg_catalog.now()
);

-- 5. products
CREATE TABLE IF NOT EXISTS public.products (
    id UUID PRIMARY KEY DEFAULT pg_catalog.gen_random_uuid(),
    sku TEXT NOT NULL UNIQUE CHECK (pg_catalog.length(pg_catalog.btrim(sku)) > 0),
    barcode TEXT NULL UNIQUE CHECK (barcode IS NULL OR pg_catalog.length(pg_catalog.btrim(barcode)) > 0),
    name TEXT NOT NULL CHECK (pg_catalog.length(pg_catalog.btrim(name)) > 0),
    description TEXT NOT NULL DEFAULT '',
    category_id UUID NOT NULL REFERENCES public.categories(id) ON DELETE RESTRICT,
    base_unit TEXT NOT NULL DEFAULT 'ea' CHECK (base_unit IN ('ea', 'box', 'pallet', 'kg', 'l', 'm')),
    allow_fractional BOOLEAN NOT NULL DEFAULT FALSE,
    bin_location TEXT NOT NULL CHECK (pg_catalog.length(pg_catalog.btrim(bin_location)) > 0),
    quantity_on_hand NUMERIC(14, 4) NOT NULL DEFAULT 0.0000
        CHECK (quantity_on_hand >= 0.0000 AND quantity_on_hand <= 1000000000.0000),
    reorder_point NUMERIC(14, 4) NOT NULL DEFAULT 10.0000
        CHECK (reorder_point >= 0.0000 AND reorder_point <= 1000000000.0000),
    currency_code CHAR(3) NOT NULL DEFAULT 'EUR' CHECK (currency_code = 'EUR'),
    total_cost_basis_eur NUMERIC(28, 6) NOT NULL DEFAULT 0.000000
        CHECK (total_cost_basis_eur >= 0.000000 AND total_cost_basis_eur <= 10000000000000000000.000000),
    unit_cost_eur NUMERIC(18, 6) NOT NULL DEFAULT 0.000000
        CHECK (unit_cost_eur >= 0.000000 AND unit_cost_eur <= 10000000000.000000),
    unit_price_eur NUMERIC(18, 2) NOT NULL DEFAULT 0.00
        CHECK (unit_price_eur >= 0.00 AND unit_price_eur <= 10000000000.00),
    encrypted_notes BYTEA NULL,
    is_archived BOOLEAN NOT NULL DEFAULT FALSE,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT pg_catalog.now(),
    created_at TIMESTAMPTZ NOT NULL DEFAULT pg_catalog.now(),
    -- discrete units (ea, box, pallet) cannot enable fractional quantities
    CONSTRAINT ck_products_unit_fractional_rule CHECK (
        (base_unit IN ('ea', 'box', 'pallet') AND allow_fractional = FALSE)
        OR (base_unit IN ('kg', 'l', 'm'))
    ),
    -- when allow_fractional is false, quantity_on_hand and reorder_point must be whole numbers
    CONSTRAINT ck_products_discrete_integrality CHECK (
        allow_fractional = TRUE
        OR (
            quantity_on_hand = pg_catalog.trunc(quantity_on_hand, 0)
            AND reorder_point = pg_catalog.trunc(reorder_point, 0)
        )
    ),
    -- zero stock must always have zero cost basis and zero unit cost
    CONSTRAINT ck_products_zero_stock_zero_cost CHECK (
        (quantity_on_hand = 0.0000 AND total_cost_basis_eur = 0.000000 AND unit_cost_eur = 0.000000)
        OR (quantity_on_hand > 0.0000)
    )
);

CREATE INDEX IF NOT EXISTS idx_products_category_id ON public.products(category_id);
CREATE INDEX IF NOT EXISTS idx_products_sku ON public.products(sku);
CREATE INDEX IF NOT EXISTS idx_products_barcode ON public.products(barcode);

-- 6. stock_ledger (append-only)
CREATE TABLE IF NOT EXISTS public.stock_ledger (
    id UUID PRIMARY KEY DEFAULT pg_catalog.gen_random_uuid(),
    idempotency_key UUID NOT NULL UNIQUE,
    request_hash CHAR(64) NOT NULL CHECK (request_hash ~ '^[0-9a-f]{64}$'),
    product_id UUID NOT NULL REFERENCES public.products(id) ON DELETE RESTRICT,
    movement_type TEXT NOT NULL CHECK (movement_type IN ('initial', 'receive', 'dispatch', 'cycle_count', 'damage')),
    previous_qty NUMERIC(14, 4) NOT NULL CHECK (previous_qty >= 0.0000 AND previous_qty <= 1000000000.0000),
    delta NUMERIC(14, 4) NOT NULL CHECK (delta <> 0.0000),
    new_qty NUMERIC(14, 4) NOT NULL CHECK (new_qty >= 0.0000 AND new_qty <= 1000000000.0000),
    currency_code CHAR(3) NOT NULL DEFAULT 'EUR' CHECK (currency_code = 'EUR'),
    total_cost_basis_eur_snapshot NUMERIC(28, 6) NOT NULL
        CHECK (total_cost_basis_eur_snapshot >= 0.000000 AND total_cost_basis_eur_snapshot <= 10000000000000000000.000000),
    unit_cost_eur_snapshot NUMERIC(18, 6) NOT NULL
        CHECK (unit_cost_eur_snapshot >= 0.000000 AND unit_cost_eur_snapshot <= 10000000000.000000),
    reference_code TEXT NULL,
    reason TEXT NOT NULL CHECK (pg_catalog.length(pg_catalog.btrim(reason)) > 0),
    actor_user_id UUID NULL REFERENCES public.users(id) ON DELETE RESTRICT,
    actor_api_key_id UUID NULL REFERENCES public.api_keys(id) ON DELETE RESTRICT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT pg_catalog.now(),
    CONSTRAINT ck_ledger_math CHECK (new_qty = previous_qty + delta AND new_qty >= 0.0000 AND delta <> 0.0000),
    CONSTRAINT ck_ledger_movement_sign CHECK (
        (movement_type IN ('initial', 'receive') AND delta > 0.0000)
        OR (movement_type IN ('dispatch', 'damage') AND delta < 0.0000)
        OR (movement_type = 'cycle_count' AND delta <> 0.0000)
    ),
    CONSTRAINT ck_ledger_single_actor CHECK (
        pg_catalog.num_nonnulls(actor_user_id, actor_api_key_id) = 1
    )
);

DO $$
BEGIN
    IF EXISTS (
        SELECT 1 FROM pg_catalog.pg_constraint
        WHERE conname = 'ck_ledger_actor_present'
          AND conrelid = 'public.stock_ledger'::pg_catalog.regclass
    ) THEN
        ALTER TABLE public.stock_ledger DROP CONSTRAINT ck_ledger_actor_present;
    END IF;

    IF NOT EXISTS (
        SELECT 1 FROM pg_catalog.pg_constraint
        WHERE conname = 'ck_ledger_single_actor'
          AND conrelid = 'public.stock_ledger'::pg_catalog.regclass
    ) THEN
        ALTER TABLE public.stock_ledger
            ADD CONSTRAINT ck_ledger_single_actor
            CHECK (pg_catalog.num_nonnulls(actor_user_id, actor_api_key_id) = 1);
    END IF;
END
$$;

CREATE INDEX IF NOT EXISTS idx_stock_ledger_product_created ON public.stock_ledger(product_id, created_at DESC);

-- 7. audit_logs (append-only)
CREATE TABLE IF NOT EXISTS public.audit_logs (
    id UUID PRIMARY KEY DEFAULT pg_catalog.gen_random_uuid(),
    actor_user_id UUID NULL REFERENCES public.users(id) ON DELETE RESTRICT,
    actor_api_key_id UUID NULL REFERENCES public.api_keys(id) ON DELETE RESTRICT,
    actor_label TEXT NOT NULL CHECK (pg_catalog.length(pg_catalog.btrim(actor_label)) > 0),
    action TEXT NOT NULL CHECK (pg_catalog.length(pg_catalog.btrim(action)) > 0),
    entity_type TEXT NOT NULL CHECK (entity_type IN ('auth', 'user', 'api_key', 'category', 'product', 'stock_ledger', 'data_io', 'system')),
    entity_id TEXT NULL,
    ip_address TEXT NOT NULL DEFAULT '',
    details JSONB NOT NULL DEFAULT '{}'::pg_catalog.jsonb CHECK (pg_catalog.jsonb_typeof(details) = 'object'),
    created_at TIMESTAMPTZ NOT NULL DEFAULT pg_catalog.now(),
    CONSTRAINT ck_audit_logs_at_most_one_actor CHECK (
        pg_catalog.num_nonnulls(actor_user_id, actor_api_key_id) <= 1
    )
);

DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_catalog.pg_constraint
        WHERE conname = 'ck_audit_logs_at_most_one_actor'
          AND conrelid = 'public.audit_logs'::pg_catalog.regclass
    ) THEN
        ALTER TABLE public.audit_logs
            ADD CONSTRAINT ck_audit_logs_at_most_one_actor
            CHECK (pg_catalog.num_nonnulls(actor_user_id, actor_api_key_id) <= 1);
    END IF;
END
$$;

CREATE INDEX IF NOT EXISTS idx_audit_logs_created_at ON public.audit_logs(created_at DESC);
CREATE INDEX IF NOT EXISTS idx_audit_logs_entity ON public.audit_logs(entity_type, entity_id);

-- enforce zero initial stock & cost on direct product insert (even by owner)
CREATE OR REPLACE FUNCTION public.enforce_initial_zero_stock_on_product_insert()
RETURNS TRIGGER
LANGUAGE plpgsql
SET search_path = pg_catalog
AS $$
BEGIN
    IF NEW.quantity_on_hand <> 0.0000 OR NEW.total_cost_basis_eur <> 0.000000 OR NEW.unit_cost_eur <> 0.000000 THEN
        RAISE EXCEPTION 'INITIAL_PRODUCT_STOCK_MUST_BE_ZERO'
            USING ERRCODE = 'P0422',
                  DETAIL = 'New products must be created with zero quantity_on_hand, total_cost_basis_eur, and unit_cost_eur.';
    END IF;
    RETURN NEW;
END;
$$;

REVOKE ALL ON FUNCTION public.enforce_initial_zero_stock_on_product_insert() FROM PUBLIC;

DROP TRIGGER IF EXISTS trg_products_enforce_initial_zero_stock ON public.products;
CREATE TRIGGER trg_products_enforce_initial_zero_stock
    BEFORE INSERT ON public.products
    FOR EACH ROW
    EXECUTE FUNCTION public.enforce_initial_zero_stock_on_product_insert();

-- append-only protection triggers on stock_ledger and audit_logs
CREATE OR REPLACE FUNCTION public.prevent_append_only_mutation()
RETURNS TRIGGER
LANGUAGE plpgsql
SET search_path = pg_catalog
AS $$
BEGIN
    RAISE EXCEPTION 'APPEND_ONLY_VIOLATION: table %.% is immutable and does not allow %',
        TG_TABLE_SCHEMA, TG_TABLE_NAME, TG_OP
        USING ERRCODE = 'P0403';
END;
$$;

REVOKE ALL ON FUNCTION public.prevent_append_only_mutation() FROM PUBLIC;

DROP TRIGGER IF EXISTS trg_stock_ledger_no_update_delete ON public.stock_ledger;
CREATE TRIGGER trg_stock_ledger_no_update_delete
    BEFORE UPDATE OR DELETE ON public.stock_ledger
    FOR EACH ROW
    EXECUTE FUNCTION public.prevent_append_only_mutation();

DROP TRIGGER IF EXISTS trg_stock_ledger_no_truncate ON public.stock_ledger;
CREATE TRIGGER trg_stock_ledger_no_truncate
    BEFORE TRUNCATE ON public.stock_ledger
    FOR EACH STATEMENT
    EXECUTE FUNCTION public.prevent_append_only_mutation();

DROP TRIGGER IF EXISTS trg_audit_logs_no_update_delete ON public.audit_logs;
CREATE TRIGGER trg_audit_logs_no_update_delete
    BEFORE UPDATE OR DELETE ON public.audit_logs
    FOR EACH ROW
    EXECUTE FUNCTION public.prevent_append_only_mutation();

DROP TRIGGER IF EXISTS trg_audit_logs_no_truncate ON public.audit_logs;
CREATE TRIGGER trg_audit_logs_no_truncate
    BEFORE TRUNCATE ON public.audit_logs
    FOR EACH STATEMENT
    EXECUTE FUNCTION public.prevent_append_only_mutation();

-- controlled security definer entry point for non-stock audit events
CREATE OR REPLACE FUNCTION public.record_audit_event(
    p_actor_user_id pg_catalog.uuid,
    p_actor_api_key_id pg_catalog.uuid,
    p_actor_label pg_catalog.text,
    p_action pg_catalog.text,
    p_entity_type pg_catalog.text,
    p_entity_id pg_catalog.text,
    p_ip_address pg_catalog.text,
    p_details pg_catalog.jsonb
)
RETURNS public.audit_logs
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog
AS $$
DECLARE
    v_label pg_catalog.text := pg_catalog.btrim(p_actor_label);
    v_action pg_catalog.text := pg_catalog.btrim(p_action);
    v_entity pg_catalog.text := pg_catalog.btrim(p_entity_type);
    v_ip pg_catalog.text := COALESCE(pg_catalog.btrim(p_ip_address), '');
    v_details pg_catalog.jsonb := COALESCE(p_details, '{}'::pg_catalog.jsonb);
    v_allowed pg_catalog.bool := FALSE;
    v_inserted public.audit_logs;
BEGIN
    IF v_label IS NULL OR pg_catalog.length(v_label) = 0 THEN
        RAISE EXCEPTION 'INVALID_AUDIT_ACTOR_LABEL'
            USING ERRCODE = 'P0422',
                  DETAIL = 'actor_label must be non-empty.';
    END IF;

    IF p_details IS NULL OR pg_catalog.jsonb_typeof(v_details) <> 'object' THEN
        RAISE EXCEPTION 'INVALID_AUDIT_DETAILS_JSON'
            USING ERRCODE = 'P0422',
                  DETAIL = 'details must be a non-null JSON object.';
    END IF;

    -- finite (entity_type, action) whitelist for non-stock application events
    -- NOTE: stock_ledger events can only be written internally by record_stock_movement()
    v_allowed := (
        (v_entity = 'auth' AND v_action IN ('auth.login.success', 'auth.login.failure', 'auth.logout'))
        OR (v_entity = 'user' AND v_action IN ('user.bootstrap.admin', 'user.create', 'user.update', 'user.deactivate', 'user.reactivate'))
        OR (v_entity = 'api_key' AND v_action IN ('api_key.create', 'api_key.revoke'))
        OR (v_entity = 'category' AND v_action IN ('category.create', 'category.update'))
        OR (v_entity = 'product' AND v_action IN ('product.create', 'product.update', 'product.archive', 'product.unarchive'))
        OR (v_entity = 'data_io' AND v_action IN ('data_io.import.products', 'data_io.export.products', 'data_io.export.ledger', 'data_io.export.audit'))
        OR (v_entity = 'system' AND v_action IN ('system.seed.executed'))
    );

    IF NOT v_allowed THEN
        RAISE EXCEPTION 'INVALID_AUDIT_EVENT'
            USING ERRCODE = 'P0422',
                  DETAIL = pg_catalog.format('Unsupported audit entity_type (%s) or action (%s).', COALESCE(v_entity, 'NULL'), COALESCE(v_action, 'NULL'));
    END IF;

    -- reject ambiguous dual-actor attribution (cannot specify both user and api key)
    IF pg_catalog.num_nonnulls(p_actor_user_id, p_actor_api_key_id) > 1 THEN
        RAISE EXCEPTION 'AMBIGUOUS_ACTOR'
            USING ERRCODE = 'P0422',
                  DETAIL = 'Cannot provide both p_actor_user_id and p_actor_api_key_id on a single audit event.';
    END IF;

    -- require an authenticated principal for all events except unauthenticated login failures or system bootstrap/seed
    IF pg_catalog.num_nonnulls(p_actor_user_id, p_actor_api_key_id) = 0
       AND NOT (
           (v_entity = 'auth' AND v_action = 'auth.login.failure')
           OR (v_entity = 'user' AND v_action = 'user.bootstrap.admin')
           OR (v_entity = 'system' AND v_action = 'system.seed.executed')
       )
    THEN
        RAISE EXCEPTION 'ACTOR_REQUIRED'
            USING ERRCODE = 'P0422',
                  DETAIL = 'Authenticated audit events require either p_actor_user_id or p_actor_api_key_id.';
    END IF;

    INSERT INTO public.audit_logs (
        actor_user_id,
        actor_api_key_id,
        actor_label,
        action,
        entity_type,
        entity_id,
        ip_address,
        details
    )
    VALUES (
        p_actor_user_id,
        p_actor_api_key_id,
        v_label,
        v_action,
        v_entity,
        p_entity_id,
        v_ip,
        v_details
    )
    RETURNING * INTO v_inserted;

    RETURN v_inserted;
END;
$$;

REVOKE ALL ON FUNCTION public.record_audit_event(
    pg_catalog.uuid, pg_catalog.uuid, pg_catalog.text,
    pg_catalog.text, pg_catalog.text, pg_catalog.text,
    pg_catalog.text, pg_catalog.jsonb
) FROM PUBLIC;

GRANT EXECUTE ON FUNCTION public.record_audit_event(
    pg_catalog.uuid, pg_catalog.uuid, pg_catalog.text,
    pg_catalog.text, pg_catalog.text, pg_catalog.text,
    pg_catalog.text, pg_catalog.jsonb
) TO penelope_app;

-- controlled security definer entry point for atomic stock movements
CREATE OR REPLACE FUNCTION public.record_stock_movement(
    p_idempotency_key pg_catalog.uuid,
    p_product_id pg_catalog.uuid,
    p_movement_type pg_catalog.text,
    p_delta pg_catalog.numeric,
    p_inbound_unit_cost_eur pg_catalog.numeric,
    p_reference_code pg_catalog.text,
    p_reason pg_catalog.text,
    p_actor_user_id pg_catalog.uuid,
    p_actor_api_key_id pg_catalog.uuid,
    p_actor_label pg_catalog.text,
    p_ip_address pg_catalog.text
)
RETURNS public.stock_ledger
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog
AS $$
DECLARE
    v_movement_type pg_catalog.text;
    v_reason_trimmed pg_catalog.text;
    v_ref_trimmed pg_catalog.text;
    v_label_trimmed pg_catalog.text;
    v_ip_trimmed pg_catalog.text;
    v_delta_norm pg_catalog.numeric(14, 4);
    v_cost_norm pg_catalog.numeric(18, 6);
    v_canonical_payload pg_catalog.text;
    v_request_hash pg_catalog.bpchar(64);
    v_existing public.stock_ledger;
    v_product public.products;
    v_new_qty pg_catalog.numeric(14, 4);
    v_prev_total_cost pg_catalog.numeric(28, 6);
    v_new_total_cost pg_catalog.numeric(28, 6);
    v_new_unit_cost pg_catalog.numeric(18, 6);
    v_relieved_cost pg_catalog.numeric(28, 6);
    v_added_cost pg_catalog.numeric(28, 6);
    v_inserted public.stock_ledger;
BEGIN
    IF p_idempotency_key IS NULL THEN
        RAISE EXCEPTION 'IDEMPOTENCY_KEY_REQUIRED'
            USING ERRCODE = 'P0422';
    END IF;

    IF p_product_id IS NULL THEN
        RAISE EXCEPTION 'PRODUCT_ID_REQUIRED'
            USING ERRCODE = 'P0422';
    END IF;

    IF p_actor_user_id IS NULL AND p_actor_api_key_id IS NULL THEN
        RAISE EXCEPTION 'ACTOR_REQUIRED'
            USING ERRCODE = 'P0422',
                  DETAIL = 'Exactly one of p_actor_user_id or p_actor_api_key_id must be provided.';
    END IF;

    IF p_actor_user_id IS NOT NULL AND p_actor_api_key_id IS NOT NULL THEN
        RAISE EXCEPTION 'AMBIGUOUS_ACTOR'
            USING ERRCODE = 'P0422',
                  DETAIL = 'Cannot provide both p_actor_user_id and p_actor_api_key_id on a stock movement.';
    END IF;

    -- verify that the single actor principal is active and authorized at the database layer
    IF p_actor_user_id IS NOT NULL THEN
        PERFORM 1
        FROM public.users
        WHERE id = p_actor_user_id
          AND is_active = TRUE;
        IF NOT FOUND THEN
            RAISE EXCEPTION 'INACTIVE_OR_UNKNOWN_ACTOR_USER'
                USING ERRCODE = 'P0403',
                      DETAIL = 'Actor user does not exist or is deactivated.';
        END IF;
    ELSE
        PERFORM 1
        FROM public.api_keys k
        JOIN public.users u ON u.id = k.created_by
        WHERE k.id = p_actor_api_key_id
          AND k.revoked_at IS NULL
          AND (k.expires_at IS NULL OR k.expires_at > pg_catalog.now())
          AND k.role_scope IN ('manager', 'operator')
          AND u.is_active = TRUE;
        IF NOT FOUND THEN
            RAISE EXCEPTION 'UNAUTHORIZED_OR_INACTIVE_API_KEY'
                USING ERRCODE = 'P0403',
                      DETAIL = 'API key is missing, revoked, expired, owned by an inactive user, or has readonly role_scope.';
        END IF;
    END IF;

    v_reason_trimmed := pg_catalog.btrim(p_reason);
    IF v_reason_trimmed IS NULL OR pg_catalog.length(v_reason_trimmed) = 0 THEN
        RAISE EXCEPTION 'REASON_REQUIRED'
            USING ERRCODE = 'P0422',
                  DETAIL = 'p_reason must be non-null and non-blank.';
    END IF;

    v_label_trimmed := pg_catalog.btrim(p_actor_label);
    IF v_label_trimmed IS NULL OR pg_catalog.length(v_label_trimmed) = 0 THEN
        RAISE EXCEPTION 'ACTOR_LABEL_REQUIRED'
            USING ERRCODE = 'P0422';
    END IF;

    v_movement_type := pg_catalog.lower(pg_catalog.btrim(COALESCE(p_movement_type, '')));
    IF v_movement_type NOT IN ('initial', 'receive', 'dispatch', 'cycle_count', 'damage') THEN
        RAISE EXCEPTION 'INVALID_MOVEMENT_TYPE'
            USING ERRCODE = 'P0422';
    END IF;

    IF p_delta IS NULL OR p_delta = 0 THEN
        RAISE EXCEPTION 'INVALID_MOVEMENT_DELTA'
            USING ERRCODE = 'P0422',
                  DETAIL = 'Movement delta must be non-zero.';
    END IF;

    -- reject excess decimal scale beyond 4 fractional digits on delta
    IF p_delta <> pg_catalog.round(p_delta, 4) THEN
        RAISE EXCEPTION 'PRECISION_EXCEEDED'
            USING ERRCODE = 'P0422',
                  DETAIL = 'Quantity delta cannot exceed 4 decimal places.';
    END IF;
    v_delta_norm := pg_catalog.round(p_delta, 4);

    IF p_inbound_unit_cost_eur IS NOT NULL THEN
        IF p_inbound_unit_cost_eur <> pg_catalog.round(p_inbound_unit_cost_eur, 6) THEN
            RAISE EXCEPTION 'COST_PRECISION_EXCEEDED'
                USING ERRCODE = 'P0422',
                      DETAIL = 'Inbound unit cost cannot exceed 6 decimal places.';
        END IF;
        v_cost_norm := pg_catalog.round(p_inbound_unit_cost_eur, 6);
    ELSE
        v_cost_norm := NULL;
    END IF;

    v_ref_trimmed := pg_catalog.btrim(p_reference_code);
    IF v_ref_trimmed = '' THEN
        v_ref_trimmed := NULL;
    END IF;
    v_ip_trimmed := COALESCE(pg_catalog.btrim(p_ip_address), '');

    -- serialize concurrent requests using the same idempotency_key under READ COMMITTED
    PERFORM pg_catalog.pg_advisory_xact_lock(
        pg_catalog.hashtextextended(p_idempotency_key::pg_catalog.text, 0)
    );

    -- build canonical length-prefixed payload and compute sha-256 request_hash
    v_canonical_payload := pg_catalog.concat_ws(
        '|',
        'v1',
        p_product_id::pg_catalog.text,
        v_movement_type,
        v_delta_norm::pg_catalog.text,
        CASE
            WHEN v_cost_norm IS NULL THEN 'N'
            ELSE 'V:' || v_cost_norm::pg_catalog.text
        END,
        CASE
            WHEN v_ref_trimmed IS NULL THEN 'N'
            ELSE 'S:' || pg_catalog.octet_length(v_ref_trimmed)::pg_catalog.text || ':' || v_ref_trimmed
        END,
        'S:' || pg_catalog.octet_length(v_reason_trimmed)::pg_catalog.text || ':' || v_reason_trimmed,
        COALESCE('U:' || p_actor_user_id::pg_catalog.text, 'N'),
        COALESCE('K:' || p_actor_api_key_id::pg_catalog.text, 'N')
    );

    v_request_hash := pg_catalog.encode(
        pg_catalog.sha256(pg_catalog.convert_to(v_canonical_payload, 'UTF8')),
        'hex'
    );

    -- check if idempotency_key was already processed
    SELECT * INTO v_existing
    FROM public.stock_ledger
    WHERE idempotency_key = p_idempotency_key;

    IF FOUND THEN
        IF v_existing.request_hash = v_request_hash THEN
            RETURN v_existing;
        ELSE
            RAISE EXCEPTION 'IDEMPOTENCY_KEY_PAYLOAD_MISMATCH'
                USING ERRCODE = 'P0409',
                      DETAIL = 'Idempotency key was already used with a different request payload.';
        END IF;
    END IF;

    -- lock target product row for atomic stock & mwa update
    SELECT * INTO v_product
    FROM public.products
    WHERE id = p_product_id
    FOR UPDATE;

    IF NOT FOUND THEN
        RAISE EXCEPTION 'PRODUCT_NOT_FOUND'
            USING ERRCODE = 'P0404';
    END IF;

    -- enforce discrete integrality when allow_fractional is false
    IF NOT v_product.allow_fractional AND v_delta_norm <> pg_catalog.trunc(v_delta_norm, 0) THEN
        RAISE EXCEPTION 'FRACTIONAL_NOT_ALLOWED'
            USING ERRCODE = 'P0422',
                  DETAIL = pg_catalog.format('Product %s (%s) does not allow fractional quantities.', v_product.sku, v_product.base_unit);
    END IF;

    -- validate movement direction and resulting quantity
    IF v_movement_type IN ('initial', 'receive') AND v_delta_norm <= 0.0000 THEN
        RAISE EXCEPTION 'INVALID_MOVEMENT_DIRECTION'
            USING ERRCODE = 'P0422',
                  DETAIL = 'Inbound movements (initial, receive) require a positive delta.';
    END IF;

    IF v_movement_type IN ('dispatch', 'damage') AND v_delta_norm >= 0.0000 THEN
        RAISE EXCEPTION 'INVALID_MOVEMENT_DIRECTION'
            USING ERRCODE = 'P0422',
                  DETAIL = 'Outbound movements (dispatch, damage) require a negative delta.';
    END IF;

    v_new_qty := v_product.quantity_on_hand + v_delta_norm;
    IF v_new_qty < 0.0000 THEN
        RAISE EXCEPTION 'INSUFFICIENT_STOCK'
            USING ERRCODE = 'P0422',
                  DETAIL = pg_catalog.format('Cannot reduce stock by %s; only %s on hand.', v_delta_norm, v_product.quantity_on_hand);
    END IF;

    IF v_new_qty > 1000000000.0000 THEN
        RAISE EXCEPTION 'QUANTITY_LIMIT_EXCEEDED'
            USING ERRCODE = 'P0422';
    END IF;

    v_prev_total_cost := v_product.total_cost_basis_eur;

    -- calculate new total_cost_basis_eur and unit_cost_eur by movement type
    IF v_movement_type IN ('initial', 'receive') THEN
        IF v_cost_norm IS NULL THEN
            RAISE EXCEPTION 'INBOUND_COST_REQUIRED'
                USING ERRCODE = 'P0422',
                      DETAIL = 'Inbound receive and initial movements require p_inbound_unit_cost_eur.';
        END IF;
        IF v_cost_norm < 0.000000 OR v_cost_norm > 10000000000.000000 THEN
            RAISE EXCEPTION 'INVALID_INBOUND_COST'
                USING ERRCODE = 'P0422';
        END IF;

        v_added_cost := pg_catalog.round(
            (v_delta_norm::pg_catalog.numeric(38, 10) * v_cost_norm::pg_catalog.numeric(38, 10)),
            6
        );
        v_new_total_cost := v_prev_total_cost + v_added_cost;
        v_new_unit_cost := pg_catalog.round(
            v_new_total_cost::pg_catalog.numeric(38, 10) / v_new_qty::pg_catalog.numeric(38, 10),
            6
        );

    ELSIF v_movement_type IN ('dispatch', 'damage') THEN
        IF v_cost_norm IS NOT NULL THEN
            RAISE EXCEPTION 'COST_NOT_ALLOWED_ON_OUTBOUND'
                USING ERRCODE = 'P0422',
                      DETAIL = 'Outbound movements (dispatch, damage) must have p_inbound_unit_cost_eur = NULL.';
        END IF;

        IF v_new_qty = 0.0000 THEN
            v_new_total_cost := 0.000000;
            v_new_unit_cost := 0.000000;
        ELSE
            v_relieved_cost := pg_catalog.round(
                (v_prev_total_cost::pg_catalog.numeric(38, 10) * pg_catalog.abs(v_delta_norm)::pg_catalog.numeric(38, 10))
                / v_product.quantity_on_hand::pg_catalog.numeric(38, 10),
                6
            );
            v_new_total_cost := v_prev_total_cost - v_relieved_cost;
            v_new_unit_cost := pg_catalog.round(
                v_new_total_cost::pg_catalog.numeric(38, 10) / v_new_qty::pg_catalog.numeric(38, 10),
                6
            );
        END IF;

    ELSIF v_movement_type = 'cycle_count' THEN
        IF v_delta_norm < 0.0000 THEN
            -- negative cycle count: relieve cost proportionally, reject inbound cost override
            IF v_cost_norm IS NOT NULL THEN
                RAISE EXCEPTION 'COST_NOT_ALLOWED_ON_NEGATIVE_CYCLE_COUNT'
                    USING ERRCODE = 'P0422';
            END IF;

            IF v_new_qty = 0.0000 THEN
                v_new_total_cost := 0.000000;
                v_new_unit_cost := 0.000000;
            ELSE
                v_relieved_cost := pg_catalog.round(
                    (v_prev_total_cost::pg_catalog.numeric(38, 10) * pg_catalog.abs(v_delta_norm)::pg_catalog.numeric(38, 10))
                    / v_product.quantity_on_hand::pg_catalog.numeric(38, 10),
                    6
                );
                v_new_total_cost := v_prev_total_cost - v_relieved_cost;
                v_new_unit_cost := pg_catalog.round(
                    v_new_total_cost::pg_catalog.numeric(38, 10) / v_new_qty::pg_catalog.numeric(38, 10),
                    6
                );
            END IF;
        ELSE
            -- positive cycle count (delta > 0)
            IF v_product.quantity_on_hand = 0.0000 THEN
                IF v_cost_norm IS NULL THEN
                    RAISE EXCEPTION 'CYCLE_COUNT_COST_REQUIRED_WHEN_ZERO_STOCK'
                        USING ERRCODE = 'P0422',
                              DETAIL = 'Positive cycle count on a zero-stock product requires p_inbound_unit_cost_eur.';
                END IF;
                IF v_cost_norm < 0.000000 OR v_cost_norm > 10000000000.000000 THEN
                    RAISE EXCEPTION 'INVALID_INBOUND_COST'
                        USING ERRCODE = 'P0422';
                END IF;
                v_added_cost := pg_catalog.round(
                    (v_delta_norm::pg_catalog.numeric(38, 10) * v_cost_norm::pg_catalog.numeric(38, 10)),
                    6
                );
            ELSE
                IF v_cost_norm IS NULL THEN
                    -- value surplus proportionally using prev_total_cost_basis_eur / prev_qty
                    v_added_cost := pg_catalog.round(
                        (v_prev_total_cost::pg_catalog.numeric(38, 10) * v_delta_norm::pg_catalog.numeric(38, 10))
                        / v_product.quantity_on_hand::pg_catalog.numeric(38, 10),
                        6
                    );
                ELSE
                    IF v_cost_norm < 0.000000 OR v_cost_norm > 10000000000.000000 THEN
                        RAISE EXCEPTION 'INVALID_INBOUND_COST'
                            USING ERRCODE = 'P0422';
                    END IF;
                    v_added_cost := pg_catalog.round(
                        (v_delta_norm::pg_catalog.numeric(38, 10) * v_cost_norm::pg_catalog.numeric(38, 10)),
                        6
                    );
                END IF;
            END IF;

            v_new_total_cost := v_prev_total_cost + v_added_cost;
            v_new_unit_cost := pg_catalog.round(
                v_new_total_cost::pg_catalog.numeric(38, 10) / v_new_qty::pg_catalog.numeric(38, 10),
                6
            );
        END IF;
    END IF;

    -- 1. update product balance and cost basis
    UPDATE public.products
    SET quantity_on_hand = v_new_qty,
        total_cost_basis_eur = v_new_total_cost,
        unit_cost_eur = v_new_unit_cost,
        updated_at = pg_catalog.now()
    WHERE id = p_product_id;

    -- 2. insert immutable ledger row
    INSERT INTO public.stock_ledger (
        idempotency_key,
        request_hash,
        product_id,
        movement_type,
        previous_qty,
        delta,
        new_qty,
        currency_code,
        total_cost_basis_eur_snapshot,
        unit_cost_eur_snapshot,
        reference_code,
        reason,
        actor_user_id,
        actor_api_key_id
    )
    VALUES (
        p_idempotency_key,
        v_request_hash,
        p_product_id,
        v_movement_type,
        v_product.quantity_on_hand,
        v_delta_norm,
        v_new_qty,
        v_product.currency_code,
        v_new_total_cost,
        v_new_unit_cost,
        v_ref_trimmed,
        v_reason_trimmed,
        p_actor_user_id,
        p_actor_api_key_id
    )
    RETURNING * INTO v_inserted;

    -- 3. insert matching security audit record in the same transaction
    INSERT INTO public.audit_logs (
        actor_user_id,
        actor_api_key_id,
        actor_label,
        action,
        entity_type,
        entity_id,
        ip_address,
        details
    )
    VALUES (
        p_actor_user_id,
        p_actor_api_key_id,
        v_label_trimmed,
        'stock.movement.' || v_movement_type,
        'stock_ledger',
        v_inserted.id::pg_catalog.text,
        v_ip_trimmed,
        pg_catalog.jsonb_build_object(
            'product_id', p_product_id,
            'sku', v_product.sku,
            'movement_type', v_movement_type,
            'previous_qty', v_product.quantity_on_hand,
            'delta', v_delta_norm,
            'new_qty', v_new_qty,
            'total_cost_basis_eur', v_new_total_cost,
            'unit_cost_eur', v_new_unit_cost,
            'idempotency_key', p_idempotency_key,
            'reference_code', v_ref_trimmed,
            'reason', v_reason_trimmed
        )
    );

    RETURN v_inserted;
END;
$$;

REVOKE ALL ON FUNCTION public.record_stock_movement(
    pg_catalog.uuid, pg_catalog.uuid, pg_catalog.text, pg_catalog.numeric,
    pg_catalog.numeric, pg_catalog.text, pg_catalog.text,
    pg_catalog.uuid, pg_catalog.uuid, pg_catalog.text, pg_catalog.text
) FROM PUBLIC;

GRANT EXECUTE ON FUNCTION public.record_stock_movement(
    pg_catalog.uuid, pg_catalog.uuid, pg_catalog.text, pg_catalog.numeric,
    pg_catalog.numeric, pg_catalog.text, pg_catalog.text,
    pg_catalog.uuid, pg_catalog.uuid, pg_catalog.text, pg_catalog.text
) TO penelope_app;

-- table & column-level grants for penelope_app
REVOKE ALL ON TABLE public.users, public.sessions, public.api_keys, public.categories FROM PUBLIC, penelope_app;
GRANT SELECT, INSERT, UPDATE ON TABLE public.users, public.api_keys, public.categories TO penelope_app;
GRANT SELECT, INSERT, UPDATE, DELETE ON TABLE public.sessions TO penelope_app;

REVOKE ALL ON TABLE public.products FROM PUBLIC, penelope_app;
GRANT SELECT ON TABLE public.products TO penelope_app;
GRANT INSERT (
    id, sku, barcode, name, description, category_id,
    base_unit, allow_fractional, bin_location, reorder_point,
    currency_code, unit_price_eur, encrypted_notes, is_archived
) ON TABLE public.products TO penelope_app;
GRANT UPDATE (
    sku, barcode, name, description, category_id,
    bin_location, reorder_point, unit_price_eur,
    encrypted_notes, is_archived, updated_at
) ON TABLE public.products TO penelope_app;

REVOKE ALL ON TABLE public.stock_ledger, public.audit_logs FROM PUBLIC, penelope_app;
GRANT SELECT ON TABLE public.stock_ledger, public.audit_logs TO penelope_app;
