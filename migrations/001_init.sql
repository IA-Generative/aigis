-- ============================================================
-- Migration unique — idempotente (fusionne 001 + 002 + 003)
-- ============================================================

CREATE EXTENSION IF NOT EXISTS "pgcrypto";

-- ── Type device_status ────────────────────────────────────────
-- Créé avec toutes les valeurs finales ; si le type existe déjà
-- on ajoute uniquement les valeurs manquantes.
DO $$ BEGIN
    CREATE TYPE device_status AS ENUM ('active', 'suspended', 'revoked', 'pending_approval');
EXCEPTION WHEN duplicate_object THEN NULL;
END $$;

ALTER TYPE device_status ADD VALUE IF NOT EXISTS 'suspended';
ALTER TYPE device_status ADD VALUE IF NOT EXISTS 'pending_approval';

-- ── Table principale ──────────────────────────────────────────
CREATE TABLE IF NOT EXISTS devices (
    id             UUID          PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id        VARCHAR       NOT NULL,
    device_id      VARCHAR       NOT NULL UNIQUE,
    name           VARCHAR,
    user_agent     VARCHAR,
    platform       VARCHAR,
    public_key     TEXT,
    key_algorithm  VARCHAR,
    hardware_level VARCHAR,
    provider_name  VARCHAR,
    attested_at    TIMESTAMP,
    last_challenge VARCHAR,
    challenge_exp  TIMESTAMP,
    status         device_status NOT NULL DEFAULT 'active',
    last_seen      TIMESTAMP,
    created_at     TIMESTAMP     NOT NULL DEFAULT NOW(),
    revoked_at     TIMESTAMP,
    revoked_by     VARCHAR,
    -- 002 : attestation avancée & score de confiance
    trust_score    INT           DEFAULT 0,
    reattest_at    TIMESTAMP,
    reattest_count INT           DEFAULT 0,
    -- 003 : approbation cross-device
    approved_by    VARCHAR,
    approved_at    TIMESTAMP
);

-- Colonnes ajoutées en 002/003 (no-op si la table vient d'être créée)
ALTER TABLE devices ADD COLUMN IF NOT EXISTS trust_score    INT       DEFAULT 0;
ALTER TABLE devices ADD COLUMN IF NOT EXISTS reattest_at    TIMESTAMP;
ALTER TABLE devices ADD COLUMN IF NOT EXISTS reattest_count INT       DEFAULT 0;
ALTER TABLE devices ADD COLUMN IF NOT EXISTS approved_by    VARCHAR;
ALTER TABLE devices ADD COLUMN IF NOT EXISTS approved_at    TIMESTAMP;

-- ── Index ─────────────────────────────────────────────────────
CREATE INDEX IF NOT EXISTS idx_devices_user_id        ON devices (user_id);
CREATE INDEX IF NOT EXISTS idx_devices_device_id      ON devices (device_id);
CREATE INDEX IF NOT EXISTS idx_devices_status         ON devices (status);
CREATE INDEX IF NOT EXISTS idx_devices_hardware_level ON devices (hardware_level);
CREATE INDEX IF NOT EXISTS idx_devices_trust_score    ON devices (trust_score);
CREATE INDEX IF NOT EXISTS idx_devices_pending_user
    ON devices (user_id, status) WHERE status = 'pending_approval';

-- ── Vue d'audit ───────────────────────────────────────────────
DROP VIEW IF EXISTS device_security_summary;
CREATE VIEW device_security_summary AS
SELECT
    hardware_level,
    COUNT(*)                                                        AS total,
    COUNT(*) FILTER (WHERE status = 'active')                       AS active,
    COUNT(*) FILTER (WHERE status = 'revoked')                      AS revoked,
    COUNT(*) FILTER (WHERE status = 'suspended')                    AS suspended,
    COUNT(*) FILTER (WHERE status = 'pending_approval')             AS pending_approval,
    ROUND(AVG(trust_score), 1)                                      AS avg_trust_score,
    COUNT(*) FILTER (WHERE reattest_at > NOW() - INTERVAL '24 hours') AS recently_attested
FROM devices
GROUP BY hardware_level;
