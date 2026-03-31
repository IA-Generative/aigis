-- ============================================================
-- Migration
-- ============================================================

-- ── Type token_status ────────────────────────────────────────
-- Créé avec toutes les valeurs finales ; si le type existe déjà
-- on ajoute uniquement les valeurs manquantes.
DO $$ BEGIN
    CREATE TYPE token_status AS ENUM ('active', 'suspended', 'revoked', 'pending_approval');
EXCEPTION WHEN duplicate_object THEN NULL;
END $$;

-- ── Table principale ──────────────────────────────────────────
CREATE TABLE IF NOT EXISTS tokens (
    id             UUID          PRIMARY KEY DEFAULT gen_random_uuid(),
    algorithm      VARCHAR       NOT NULL DEFAULT 'sha256',
    user_id        VARCHAR       NOT NULL,
    hash           VARCHAR       NOT NULL UNIQUE,
    name           VARCHAR,
    status         token_status NOT NULL DEFAULT 'active',
    last_seen      TIMESTAMP,
    created_at     TIMESTAMP     NOT NULL DEFAULT NOW(),
    revoked_at     TIMESTAMP,
    revoked_by     VARCHAR
);

-- ── Index ─────────────────────────────────────────────────────
CREATE INDEX IF NOT EXISTS idx_tokens_user_id        ON tokens (user_id);
CREATE INDEX IF NOT EXISTS idx_tokens_status         ON tokens (status);
CREATE INDEX IF NOT EXISTS idx_tokens_pending_user
    ON tokens (user_id, status) WHERE status = 'pending_approval';

