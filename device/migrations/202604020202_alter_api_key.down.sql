-- ============================================================
-- Migration UP
-- ============================================================

-- ── Add columns ───────────────────────────────────
ALTER TABLE tokens
    -- Cette colonne permettra de stocker la clé d'API en clair pour les opérations de création et de gestion des tokens
    ADD COLUMN IF NOT EXISTS secret VARCHAR NOT NULL UNIQUE,
    -- Cette colonne permettra de stocker une liste de plage d'adresses IP autorisées pour chaque token
    ADD COLUMN IF NOT EXISTS ip_whitelist INET[]; -- Array de INET pour les plages d'adresses IP autorisées

-- ── Index ─────────────────────────────────────────────────────
CREATE INDEX IF NOT EXISTS idx_tokens_secret ON tokens (secret);

-- ============================================================
-- Migration Down
-- ============================================================
DROP INDEX IF EXISTS idx_tokens_secret;

ALTER TABLE tokens
    DROP COLUMN IF EXISTS secret,
    DROP COLUMN IF EXISTS ip_whitelist;
