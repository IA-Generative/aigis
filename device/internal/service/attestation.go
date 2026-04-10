package service

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"time"

	"go.uber.org/zap"

	"github.com/ia-generative/aigis/internal/attestation"
	"github.com/ia-generative/aigis/internal/model"
)

const (
	challengeTTL    = 2 * time.Minute
	signatureWindow = 30 * time.Second
	nonceTTL        = 60 * time.Second
)

type AttestationService struct {
	deviceSvc *DeviceService
	logger    *zap.Logger
}

func NewAttestationService(
	deviceSvc *DeviceService,
	logger *zap.Logger,
) *AttestationService {
	return &AttestationService{
		deviceSvc: deviceSvc,
		logger:    logger,
	}
}

// GetDevice expose l'accès au device pour le handler (vérification de politique)
func (s *AttestationService) GetDevice(ctx context.Context, deviceID string) (*model.Device, error) {
	return s.deviceSvc.repo.GetByDeviceID(ctx, deviceID)
}

// GenerateChallenge génère un challenge à signer par le device
func (s *AttestationService) GenerateChallenge(ctx context.Context, deviceID string) (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	challenge := hex.EncodeToString(b)

	if err := s.deviceSvc.repo.SetChallenge(ctx, deviceID, challenge, time.Now().Add(challengeTTL)); err != nil {
		return "", err
	}

	return challenge, nil
}

// GenerateRegisterChallenge génère un challenge pré-enregistrement.
// Stocké dans Redis (pas en DB car le device n'existe pas encore).
// Le challenge est lié au userID extrait du JWT.
func (s *AttestationService) GenerateRegisterChallenge(ctx context.Context, userID string) (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	challenge := hex.EncodeToString(b)

	if err := s.deviceSvc.cache.SetRegisterChallenge(ctx, userID, challenge, challengeTTL); err != nil {
		return "", err
	}

	s.logger.Debug("register challenge generated",
		zap.String("user_id", userID),
		zap.Duration("ttl", challengeTTL))

	return challenge, nil
}

// VerifyRegisterSignature vérifie la signature du challenge pré-enregistrement.
// Le client signe le challenge brut avec sa clé ECDSA et envoie tout
// au moment du POST /devices/register.
func (s *AttestationService) VerifyRegisterSignature(
	ctx context.Context,
	userID, publicKeyPEM, challenge, signatureB64 string,
) error {
	// 1. Le challenge correspond-il à celui stocké dans Redis ?
	stored, err := s.deviceSvc.cache.GetRegisterChallenge(ctx, userID)
	if err != nil {
		return fmt.Errorf("failed to get register challenge: %w", err)
	}
	if stored == "" || stored != challenge {
		return errors.New("invalid or expired register challenge")
	}

	// 2. Vérifier la signature ECDSA sur le challenge
	provider := &attestation.SoftwareProvider{}
	if err := provider.VerifySignature(ctx, publicKeyPEM, challenge, signatureB64); err != nil {
		s.logger.Warn("register challenge signature verification failed",
			zap.String("user_id", userID),
			zap.Error(err))
		return fmt.Errorf("challenge signature invalid: %w", err)
	}

	return nil
}

// VerifyRequestSignature vérifie la signature sur chaque appel API
func (s *AttestationService) VerifyRequestSignature(
	ctx context.Context,
	deviceID, nonce, timestamp, signatureB64, userID string,
) (*model.VerifySignatureResponse, error) {
	// 0. Récupérer le device et sa clé publique
	device, err := s.deviceSvc.repo.GetByDeviceID(ctx, deviceID)
	if err != nil {
		return nil, err
	}

	deviceSigned := device.PublicKey != nil && *device.PublicKey != ""
	resp := &model.VerifySignatureResponse{
		DeviceID:     device.DeviceID,
		UserID:       device.UserID,
		Verified:     false,
		Message:      "",
		Status:       string(device.Status),
		DeviceSigned: deviceSigned,
	}

	if resp.Status != string(model.DeviceActive) {
		resp.Message = "device is not active"
		return resp, nil
	}

	if device.UserID != userID {
		resp.Message = "device does not belong to this user"
		return resp, nil
	}

	// 1. Anti-replay : nonce déjà vu ?
	seen, _ := s.deviceSvc.cache.GetNonce(ctx, nonce)
	if seen {
		resp.Message = "nonce already used"
		resp.Verified = false
		return resp, nil
	}

	// 2. Fenêtre de timestamp
	ts, err := time.Parse(time.RFC3339, timestamp)
	if err != nil || time.Since(ts) > signatureWindow {
		resp.Message = "timestamp out of window"
		return resp, nil
	}

	if device.PublicKey == nil {
		resp.Message = "device has no registered key, skipping signature verification"
		return resp, nil
	}

	// 3. Vérifier la signature (toujours software, car hardware_level supprimé)
	payload := nonce + "|" + timestamp
	provider := &attestation.SoftwareProvider{}
	if err := provider.VerifySignature(ctx, *device.PublicKey, payload, signatureB64); err != nil {
		s.logger.Warn("request signature verification failed",
			zap.String("device_id", deviceID),
			zap.Error(err))
		resp.Message = "request signature verification failed"
		return resp, nil
	}

	// 4. Consommer le nonce
	_ = s.deviceSvc.cache.SetNonce(ctx, nonce, nonceTTL)

	// 5. Mettre à jour last_seen
	_ = s.deviceSvc.repo.UpdateLastSeen(ctx, deviceID)

	if resp.Status != string(model.DeviceActive) {
		resp.Message = "device is not active"
	}

	resp.Verified = true
	return resp, nil
}

// RecordReattestation enregistre une re-attestation réussie
func (s *AttestationService) RecordReattestation(ctx context.Context, deviceID string) error {
	if err := s.deviceSvc.repo.RecordReattestation(ctx, deviceID); err != nil {
		s.logger.Error("failed to record reattestation",
			zap.String("device_id", deviceID),
			zap.Error(err))
		return err
	}

	// Invalider le cache
	_ = s.deviceSvc.cache.InvalidateDevice(ctx, deviceID)

	s.logger.Info("reattestation recorded",
		zap.String("device_id", deviceID))
	return nil
}
