package repository

import (
	"context"
	"database/sql"
	"errors"
	"time"

	"github.com/jmoiron/sqlx"

	"github.com/ia-generative/device-service/internal/model"
)

var ErrNotFound = errors.New("device not found")

type DeviceRepository struct {
	db *sqlx.DB
}

func NewDeviceRepository(db *sqlx.DB) *DeviceRepository {
	return &DeviceRepository{db: db}
}

func (r *DeviceRepository) Create(ctx context.Context, d *model.Device) error {
	query := `
		INSERT INTO devices (device_id, name, user_agent, platform, status)
		VALUES (:device_id, :name, :user_agent, :platform, :status)
		RETURNING id, created_at`

	rows, err := r.db.NamedQueryContext(ctx, query, d)
	if err != nil {
		return err
	}
	defer rows.Close()

	if rows.Next() {
		return rows.Scan(&d.ID, &d.CreatedAt)
	}
	return nil
}

func (r *DeviceRepository) GetByDeviceID(ctx context.Context, deviceID string) (*model.Device, error) {
	var d model.Device
	err := r.db.GetContext(ctx, &d,
		`SELECT * FROM devices WHERE device_id = $1`, deviceID)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	return &d, err
}

func (r *DeviceRepository) ListByUserID(ctx context.Context, userID string) ([]*model.Device, error) {
	var devices []*model.Device
	err := r.db.SelectContext(ctx, &devices,
		`SELECT * FROM devices WHERE user_id = $1 AND status != 'revoked' ORDER BY created_at DESC`, userID)
	return devices, err
}

func (r *DeviceRepository) Revoke(ctx context.Context, deviceID, revokedBy string) error {
	now := time.Now()
	result, err := r.db.ExecContext(ctx, `
		UPDATE devices
		SET status = 'revoked', revoked_at = $1, revoked_by = $2,
		    trust_score = 0, reattest_count = 0
		WHERE device_id = $3 AND status != 'revoked'`,
		now, revokedBy, deviceID)
	if err != nil {
		return err
	}

	rows, _ := result.RowsAffected()
	if rows == 0 {
		return ErrNotFound
	}
	return nil
}

func (r *DeviceRepository) RevokeByUser(ctx context.Context, deviceID, userID string) error {
	now := time.Now()
	result, err := r.db.ExecContext(ctx, `
		UPDATE devices
		SET status = 'revoked', revoked_at = $1, revoked_by = $2,
		    trust_score = 0, reattest_count = 0
		WHERE device_id = $3 AND user_id = $4 AND status != 'revoked'`,
		now, userID, deviceID, userID)
	if err != nil {
		return err
	}

	rows, _ := result.RowsAffected()
	if rows == 0 {
		return ErrNotFound
	}
	return nil
}

func (r *DeviceRepository) UpdateLastSeen(ctx context.Context, deviceID string) error {
	_, err := r.db.ExecContext(ctx,
		`UPDATE devices SET last_seen = NOW() WHERE device_id = $1`, deviceID)
	return err
}

func (r *DeviceRepository) Delete(ctx context.Context, deviceID, userID string) error {
	result, err := r.db.ExecContext(ctx,
		`DELETE FROM devices WHERE device_id = $1 AND user_id = $2`,
		deviceID, userID)
	if err != nil {
		return err
	}

	rows, _ := result.RowsAffected()
	if rows == 0 {
		return ErrNotFound
	}
	return nil
}

// SetChallenge stocke un challenge avec sa date d'expiration sur un device
func (r *DeviceRepository) SetChallenge(
	ctx context.Context,
	deviceID, challenge string,
	expiresAt time.Time,
) error {
	result, err := r.db.ExecContext(ctx, `
        UPDATE devices
        SET last_challenge = $1,
            challenge_exp  = $2
        WHERE device_id = $3
          AND status != 'revoked'`,
		challenge, expiresAt, deviceID,
	)
	if err != nil {
		return err
	}

	rows, _ := result.RowsAffected()
	if rows == 0 {
		return ErrNotFound
	}
	return nil
}

func (r *DeviceRepository) Ping(ctx context.Context) error {
	return r.db.PingContext(ctx)
}

// Suspend passe un device actif en statut suspended
func (r *DeviceRepository) Suspend(ctx context.Context, deviceID, reason string) error {
	result, err := r.db.ExecContext(ctx, `
		UPDATE devices
		SET status = 'suspended',
		    trust_score = 0
		WHERE device_id = $1
		  AND status = 'active'`,
		deviceID)
	if err != nil {
		return err
	}
	rows, _ := result.RowsAffected()
	if rows == 0 {
		return ErrNotFound
	}
	return nil
}

// UpgradeKey met à jour la clé publique et le hardware_level d'un device
func (r *DeviceRepository) UpgradeKey(ctx context.Context, deviceID, publicKey, keyAlgorithm, hardwareLevel, providerName string) error {
	result, err := r.db.ExecContext(ctx, `
		UPDATE devices
		SET public_key     = $1,
		    key_algorithm  = $2,
		    hardware_level = $3,
		    provider_name  = $4,
		    attested_at    = NOW(),
		    last_seen      = NOW()
		WHERE device_id = $5
		  AND status = 'active'`,
		publicKey, keyAlgorithm, hardwareLevel, providerName, deviceID)
	if err != nil {
		return err
	}
	rows, _ := result.RowsAffected()
	if rows == 0 {
		return ErrNotFound
	}
	return nil
}

// UpdateTrustScore met à jour le score de confiance d'un device
func (r *DeviceRepository) UpdateTrustScore(ctx context.Context, deviceID string, score int) error {
	_, err := r.db.ExecContext(ctx,
		`UPDATE devices SET trust_score = $1 WHERE device_id = $2`, score, deviceID)
	return err
}

// RecordReattestation enregistre une re-attestation réussie
func (r *DeviceRepository) RecordReattestation(ctx context.Context, deviceID string) error {
	result, err := r.db.ExecContext(ctx, `
		UPDATE devices
		SET reattest_at    = NOW(),
		    reattest_count = COALESCE(reattest_count, 0) + 1,
		    attested_at    = NOW(),
		    last_seen      = NOW()
		WHERE device_id = $1
		  AND status != 'revoked'`,
		deviceID,
	)
	if err != nil {
		return err
	}

	rows, _ := result.RowsAffected()
	if rows == 0 {
		return ErrNotFound
	}
	return nil
}

// GetChallenge récupère le challenge actif d'un device (pour vérification)
func (r *DeviceRepository) GetChallenge(ctx context.Context, deviceID string) (string, *time.Time, error) {
	var challenge *string
	var exp *time.Time
	err := r.db.QueryRowContext(ctx,
		`SELECT last_challenge, challenge_exp FROM devices WHERE device_id = $1`,
		deviceID,
	).Scan(&challenge, &exp)
	if err != nil {
		return "", nil, err
	}
	if challenge == nil {
		return "", nil, ErrNotFound
	}
	return *challenge, exp, nil
}

// CreateWithKey insère un device avec ses informations d'attestation cryptographique
func (r *DeviceRepository) CreateWithKey(ctx context.Context, d *model.Device) error {
	query := `
        INSERT INTO devices (
            device_id,
            name,
            user_agent,
            platform,
            status,
            public_key,
            key_algorithm,
            hardware_level,
            provider_name,
            attested_at,
						user_id
        ) VALUES (
            :device_id,
            :name,
            :user_agent,
            :platform,
            :status,
            :public_key,
            :key_algorithm,
            :hardware_level,
            :provider_name,
            :attested_at,
						:user_id
        )
        RETURNING id, created_at`

	rows, err := r.db.NamedQueryContext(ctx, query, d)
	if err != nil {
		return err
	}
	defer rows.Close()

	if rows.Next() {
		return rows.Scan(&d.ID, &d.CreatedAt)
	}
	return nil
}

// ─── Architecture A+B : Bootstrap Trust ─────────────────────────────────────

// CountActiveByUser retourne le nombre de devices actifs pour un utilisateur
func (r *DeviceRepository) CountActiveByUser(ctx context.Context, userID string) (int, error) {
	var count int
	err := r.db.GetContext(ctx, &count,
		`SELECT COUNT(*) FROM devices WHERE user_id = $1 AND status = 'active'`, userID)
	return count, err
}

// ListPendingByUser retourne les devices en attente d'approbation pour un utilisateur
func (r *DeviceRepository) ListPendingByUser(ctx context.Context, userID string) ([]*model.Device, error) {
	var devices []*model.Device
	err := r.db.SelectContext(ctx, &devices,
		`SELECT * FROM devices WHERE user_id = $1 AND status = 'pending_approval' ORDER BY created_at DESC`, userID)
	return devices, err
}

// Approve active un device pending_approval et enregistre le device approbateur
func (r *DeviceRepository) Approve(ctx context.Context, deviceID, approverDeviceID string) error {
	now := time.Now()
	result, err := r.db.ExecContext(ctx, `
		UPDATE devices
		SET status = 'active',
		    approved_by = $1,
		    approved_at = $2,
		    last_seen   = $2
		WHERE device_id = $3
		  AND status = 'pending_approval'`,
		approverDeviceID, now, deviceID)
	if err != nil {
		return err
	}

	rows, _ := result.RowsAffected()
	if rows == 0 {
		return ErrNotFound
	}
	return nil
}

// Reject rejette un device pending_approval en le passant en revoked
func (r *DeviceRepository) Reject(ctx context.Context, deviceID, rejectedBy string) error {
	now := time.Now()
	result, err := r.db.ExecContext(ctx, `
		UPDATE devices
		SET status     = 'revoked',
		    revoked_at = $1,
		    revoked_by = $2,
		    trust_score = 0
		WHERE device_id = $3
		  AND status = 'pending_approval'`,
		now, rejectedBy, deviceID)
	if err != nil {
		return err
	}

	rows, _ := result.RowsAffected()
	if rows == 0 {
		return ErrNotFound
	}
	return nil
}

// ExpirePendingDevices expire les devices pending_approval plus anciens que le timeout
func (r *DeviceRepository) ExpirePendingDevices(ctx context.Context, timeoutMinutes int) (int64, error) {
	result, err := r.db.ExecContext(ctx, `
		UPDATE devices
		SET status     = 'revoked',
		    revoked_at = NOW(),
		    revoked_by = 'system:timeout',
		    trust_score = 0
		WHERE status = 'pending_approval'
		  AND created_at < NOW() - ($1 || ' minutes')::INTERVAL`,
		timeoutMinutes)
	if err != nil {
		return 0, err
	}

	rows, _ := result.RowsAffected()
	return rows, nil
}
