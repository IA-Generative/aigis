package model

import (
	"time"

	cfg "github.com/ia-generative/device-service/internal/config"
)

type DeviceStatus string

const (
	DeviceActive          DeviceStatus = "active"
	DeviceSuspended       DeviceStatus = "suspended"
	DeviceRevoked         DeviceStatus = "revoked"
	DevicePendingApproval DeviceStatus = "pending_approval"
)

type Device struct {
	ID        string       `db:"id"              json:"id"`
	UserID    string       `db:"user_id"         json:"user_id"`
	DeviceID  string       `db:"device_id"       json:"device_id"`
	Name      *string      `db:"name"            json:"name,omitempty"`
	UserAgent *string      `db:"user_agent"      json:"user_agent,omitempty"`
	Platform  *string      `db:"platform"        json:"platform,omitempty"`
	Status    DeviceStatus `db:"status"          json:"status"`
	// Attestation
	PublicKey    *string    `db:"public_key"      json:"public_key,omitempty"`
	KeyAlgorithm *string    `db:"key_algorithm"   json:"key_algorithm,omitempty"`
	ProviderName *string    `db:"provider_name"   json:"provider_name,omitempty"`
	AttestedAt   *time.Time `db:"attested_at"     json:"attested_at,omitempty"`
	// Challenge
	LastChallenge *string    `db:"last_challenge"  json:"-"`
	ChallengeExp  *time.Time `db:"challenge_exp"   json:"-"`
	// Trust & Re-attestation
	TrustScore    *int       `db:"trust_score"     json:"trust_score"`
	ReattestAt    *time.Time `db:"reattest_at"     json:"reattest_at,omitempty"`
	ReattestCount *int       `db:"reattest_count"  json:"reattest_count,omitempty"`
	// Approval (Architecture B — cross-device)
	ApprovedBy *string    `db:"approved_by"     json:"approved_by,omitempty"`
	ApprovedAt *time.Time `db:"approved_at"     json:"approved_at,omitempty"`
	// Timestamps
	LastSeen  *time.Time `db:"last_seen"       json:"last_seen,omitempty"`
	CreatedAt time.Time  `db:"created_at"      json:"created_at"`
	RevokedAt *time.Time `db:"revoked_at"      json:"revoked_at,omitempty"`
	RevokedBy *string    `db:"revoked_by"      json:"revoked_by,omitempty"`
}

type AttestationInfo struct {
	PublicKeyPEM string
	KeyAlgorithm string
	ProviderName string
}

type RegisterRequest struct {
	UserID       string `json:"user_id"`
	DeviceID     string `json:"device_id"`
	Name         string `json:"name"`
	UserAgent    string `json:"user_agent"`
	Platform     string `json:"platform"`
	PublicKey    string `json:"public_key"`
	KeyAlgorithm string `json:"key_algorithm"`
	ProviderName string `json:"provider_name"`
	// Challenge-then-register (FIDO2-style atomic ceremony)
	Challenge          string `json:"challenge,omitempty"`
	ChallengeSignature string `json:"challenge_signature,omitempty"`
	// Email (extracted from JWT, not from request body)
	Email string `json:"-"`
	// ACR level from JWT (e.g. "urn:keycloak:acr:silver")
	Acr string `json:"-"`
}

type RenewCodeRequest struct {
	UserID   string `json:"user_id"`
	DeviceID string `json:"device_id"`
	// Email (extracted from JWT, not from request body)
	Email string `json:"-"`
}

type StatusResponse struct {
	DeviceID        string               `json:"device_id"`
	UserID          string               `json:"user_id"`
	TrustScore      *int                 `json:"trust_score"`
	Status          DeviceStatus         `json:"status"`
	Signed          bool                 `json:"device_signed"`
	ApprovalMethods []cfg.ApprovalMethod `json:"approval_methods,omitempty"`
}

type VerifyResponse struct {
	DeviceID   string       `json:"device_id"`
	UserID     string       `json:"user_id"`
	TrustScore *int         `json:"trust_score"`
	Message    string       `json:"message"`
	Verified   bool         `json:"verified"`
	Status     DeviceStatus `json:"status"`
}

// type VerifyResponse struct {
// 	Code    int
// 	Payload VerifySignatureResponse
// }

type VerifySignatureResponse struct {
	DeviceID     string `json:"device_id"`
	UserID       string `json:"user_id"`
	TrustScore   *int   `json:"trust_score"`
	Status       string `json:"status"`
	DeviceSigned bool   `json:"device_signed"` // si le divice a une clé enregistrée
	Message      string `json:"message"`
	Verified     bool   `json:"verified"`
}

type RevokeRequest struct {
	Reason string `json:"reason"`
}

// ─── Challenge / Re-attestation ───────────────────────────────────────────────

type ChallengeRequest struct {
	DeviceID string `json:"device_id"`
}

type ChallengeResponse struct {
	Challenge string `json:"challenge"`
	ExpiresIn int    `json:"expires_in"` // secondes
}

type VerifyChallengeRequest struct {
	DeviceID  string `json:"device_id"`
	Signature string `json:"signature"` // base64 ECDSA signature of challenge
	Timestamp string `json:"timestamp"` // RFC3339
	Nonce     string `json:"nonce"`
}

type ReattestRequest struct {
	DeviceID     string `json:"device_id"`
	Signature    string `json:"signature"` // base64 sign(nonce|timestamp)
	Timestamp    string `json:"timestamp"` // RFC3339
	Nonce        string `json:"nonce"`
	PublicKey    string `json:"public_key"` // PEM — peut être la même ou une nouvelle
	KeyAlgorithm string `json:"key_algorithm"`
	// HardwareLevel string `json:"hardware_level"`
	ProviderName  string `json:"provider_name"`
	HardwareProof string `json:"hardware_proof,omitempty"` // base64 TPM quote / enclave proof
}

// ─── Risk / Trust Score ──────────────────────────────────────────────────────

type TrustScoreResponse struct {
	DeviceID   string         `json:"device_id"`
	TrustScore int            `json:"trust_score"`
	Breakdown  TrustBreakdown `json:"breakdown"`
}

type TrustBreakdown struct {
	ApprovalMethod  int `json:"approval_method_points"`
	SignaturePoints int `json:"signature_points"`
	AttestationAge  int `json:"attestation_age_points"`
	ReattestCount   int `json:"reattest_count_points"`
	ActivityPoints  int `json:"activity_points"`
	StatusPoints    int `json:"status_points"`
}

// ─── Device-Bound Session ────────────────────────────────────────────────────

type DeviceSignatureHeaders struct {
	DeviceID  string // X-Device-ID
	Nonce     string // X-Device-Nonce
	Timestamp string // X-Device-Timestamp
	Signature string // X-Device-Signature (base64)
}

// ─── Architecture A+B : Bootstrap Trust ─────────────────────────────────────

// RegisterResponse est la réponse enrichie du register
type RegisterResponse struct {
	DeviceID        string               `json:"device_id"`
	Status          DeviceStatus         `json:"device_status"`
	Message         string               `json:"message"`
	TrustScore      int                  `json:"trust_score"`
	ApprovalMethods []cfg.ApprovalMethod `json:"approval_methods,omitempty"`
}

type RenewCodeResponse struct {
	Message string `json:"message"`
}

// EmailChallengeRequest pour valider le code email
type EmailChallengeRequest struct {
	Code string `json:"code"`
}

// UpgradeKeyRequest pour upgrader la clé d'un device (software → hardware)
type UpgradeKeyRequest struct {
	DeviceID      string `json:"device_id"`
	PublicKey     string `json:"public_key"`
	KeyAlgorithm  string `json:"key_algorithm"`
	HardwareLevel string `json:"hardware_level"`
	ProviderName  string `json:"provider_name"`
	HardwareProof string `json:"hardware_proof,omitempty"`
	// Preuve de continuité : signature avec l'ancienne clé
	OldSignature string `json:"old_signature"`
	Nonce        string `json:"nonce"`
	Timestamp    string `json:"timestamp"`
}

// ApproveRejectRequest pour approuver ou rejeter un device pending_approval
type ApproveRejectRequest struct {
	DeviceID string `json:"device_id"` // device à approuver/rejeter
}

// ApprovalEvent envoyé via SSE quand un device pending reçoit une décision
type ApprovalEvent struct {
	Type     string `json:"type"`      // "approved" | "rejected"
	DeviceID string `json:"device_id"` // device concerné
	Message  string `json:"message"`
}
