-- ============================================================
-- Down Migration of 202603311516_add_api_key.up.sql
-- ============================================================

CREATE EXTENSION IF NOT EXISTS "pgcrypto";

-- ── Type token_status ────────────────────────────────────────
-- Créé avec toutes les valeurs finales ; si le type existe déjà
-- on ajoute uniquement les valeurs manquantes.
DO $$ BEGIN
    DROP TYPE IF EXISTS token_status;
EXCEPTION WHEN duplicate_object THEN NULL;
END $$;

-- ── Table principale ──────────────────────────────────────────
DROP TABLE IF EXISTS tokens;