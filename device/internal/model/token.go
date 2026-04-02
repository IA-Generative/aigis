package model

import (
	"time"
)

type TokenStatus string

const (
	TokenActive          TokenStatus = "active"
	TokenSuspended       TokenStatus = "suspended"
	TokenRevoked         TokenStatus = "revoked"
	TokenPendingApproval TokenStatus = "pending_approval"
)

type Token struct {
	ID          string      `db:"id"              json:"id"`
	UserID      string      `db:"user_id"         json:"user_id"`
	Algorithm   *string     `db:"algorithm"       json:"algorithm,omitempty"`
	Name        *string     `db:"name"            json:"name,omitempty"`
	Hash        *string     `db:"hash"            json:"hash"`
	Secret      *string     `db:"secret"`
	IPWhitelist *string     `db:"ip_whitelist"    json:"ip_whitelist,omitempty"`
	Status      TokenStatus `db:"status"`
	// Attestation
	ApprovedBy *string    `db:"approved_by"     json:"approved_by,omitempty"`
	ApprovedAt *time.Time `db:"approved_at"     json:"approved_at,omitempty"`
	// Timestamps
	LastSeen  *time.Time `db:"last_seen"       json:"last_seen,omitempty"`
	CreatedAt time.Time  `db:"created_at"      json:"created_at"`
	RevokedAt *time.Time `db:"revoked_at"      json:"revoked_at,omitempty"`
	RevokedBy *string    `db:"revoked_by"      json:"revoked_by,omitempty"`
}
