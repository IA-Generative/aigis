-- ============================================================
-- Migration
-- ============================================================

-- ── Add columns ───────────────────────────────────
ALTER TABLE tokens
    -- Cette colonne permettra de stocker la clé d'API en clair pour les opérations de création et de gestion des tokens
    ADD COLUMN IF NOT EXISTS secret VARCHAR UNIQUE,
    -- Cette colonne permettra de stocker une liste de plage d'adresses IP autorisées pour chaque token
    ADD COLUMN IF NOT EXISTS ip_whitelist INET[] NOT NULL DEFAULT '{}'; -- Array de INET pour les plages d'adresses IP autorisées

-- ── Index ─────────────────────────────────────────────────────
CREATE INDEX IF NOT EXISTS idx_tokens_secret         ON tokens (secret);

