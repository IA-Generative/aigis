package service

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"time"

	"go.uber.org/zap"

	"github.com/ia-generative/device-service/internal/attestation"
	"github.com/ia-generative/device-service/internal/config"
	"github.com/ia-generative/device-service/internal/model"
)

const (
	challengeTTL    = 2 * time.Minute
	signatureWindow = 30 * time.Second
	nonceTTL        = 60 * time.Second
)

type AttestationService struct {
	deviceSvc *DeviceService
	mode      config.AttestationMode
	logger    *zap.Logger
}

func NewAttestationService(
	deviceSvc *DeviceService,
	mode config.AttestationMode,
	logger *zap.Logger,
) *AttestationService {
	return &AttestationService{
		deviceSvc: deviceSvc,
		mode:      mode,
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
	deviceID, nonce, timestamp, signatureB64 string,
) error {

	// 1. Anti-replay : nonce déjà vu ?
	seen, _ := s.deviceSvc.cache.GetNonce(ctx, nonce)
	if seen {
		return attestation.ErrReplayAttack
	}

	// 2. Fenêtre de timestamp
	ts, err := time.Parse(time.RFC3339, timestamp)
	if err != nil || time.Since(ts) > signatureWindow {
		return attestation.ErrTimestampOutOfWindow
	}

	// 3. Récupérer le device et sa clé publique
	device, err := s.deviceSvc.repo.GetByDeviceID(ctx, deviceID)
	if err != nil {
		return err
	}

	if device.PublicKey == nil || device.HardwareLevel == nil {
		return errors.New("device has no registered key — attestation required")
	}

	// 4. Instancier le provider correspondant au niveau enregistré
	provider, err := attestation.NewProvider(
		attestation.HardwareLevel(*device.HardwareLevel),
		nil, // pas de preuve à ce stade
		string(s.mode),
	)
	if err != nil {
		return err
	}

	// 5. Vérifier la signature
	payload := nonce + "|" + timestamp
	if err := provider.VerifySignature(ctx, *device.PublicKey, payload, signatureB64); err != nil {
		s.logger.Warn("request signature verification failed",
			zap.String("device_id", deviceID),
			zap.String("provider", provider.Name()),
			zap.Error(err))
		return err
	}

	// 6. Consommer le nonce
	_ = s.deviceSvc.cache.SetNonce(ctx, nonce, nonceTTL)

	// 7. Mettre à jour last_seen
	_ = s.deviceSvc.repo.UpdateLastSeen(ctx, deviceID)

	return nil
}

// ─── Hardware Level Policy ──────────────────────────────────────────────────

// hardwareLevelRank retourne le rang d'un hardware level pour comparer les niveaux.
// Plus le rang est élevé, plus le niveau est fort.
func hardwareLevelRank(level string) int {
	switch level {
	case "tee", "secure_enclave":
		return 2
	case "software":
		return 1
	default:
		return 0
	}
}

// CheckHardwareLevelTransition vérifie la politique de transition hardware.
// Retourne nil si la transition est autorisée, une erreur sinon.
// En cas de downgrade, le device est automatiquement suspendu.
func (s *AttestationService) CheckHardwareLevelTransition(
	ctx context.Context,
	deviceID, currentLevel, requestedLevel string,
) error {
	currentRank := hardwareLevelRank(currentLevel)
	requestedRank := hardwareLevelRank(requestedLevel)

	if requestedRank < currentRank {
		// Downgrade interdit → suspension automatique
		s.logger.Warn("hardware level downgrade detected — suspending device",
			zap.String("device_id", deviceID),
			zap.String("current_level", currentLevel),
			zap.String("requested_level", requestedLevel))

		if err := s.deviceSvc.repo.Suspend(ctx, deviceID, "hardware_downgrade"); err != nil {
			s.logger.Error("failed to suspend device after hw downgrade",
				zap.String("device_id", deviceID),
				zap.Error(err))
		}
		_ = s.deviceSvc.cache.InvalidateDevice(ctx, deviceID)

		return fmt.Errorf("hardware level downgrade (%s → %s) is not allowed — device suspended", currentLevel, requestedLevel)
	}

	return nil
}

// UpgradeKey permet à un device d'upgrader sa clé (software → hardware).
// Exige la preuve de possession de l'ancienne clé + la nouvelle clé publique.
func (s *AttestationService) UpgradeKey(
	ctx context.Context,
	deviceID, userID string,
	newPublicKey, newKeyAlgorithm, newHardwareLevel, newProviderName string,
	oldNonce, oldTimestamp, oldSignature string,
) error {
	// 1. Récupérer le device
	device, err := s.deviceSvc.repo.GetByDeviceID(ctx, deviceID)
	if err != nil {
		return err
	}
	if device.UserID != userID {
		return errors.New("device does not belong to this user")
	}
	if device.Status != "active" {
		return errors.New("device is not active")
	}

	// 2. Vérifier que c'est bien un upgrade
	currentLevel := "software"
	if device.HardwareLevel != nil {
		currentLevel = *device.HardwareLevel
	}
	if err := s.CheckHardwareLevelTransition(ctx, deviceID, currentLevel, newHardwareLevel); err != nil {
		return err
	}
	if hardwareLevelRank(newHardwareLevel) <= hardwareLevelRank(currentLevel) {
		return errors.New("upgrade-key requires a higher hardware level than current")
	}

	// 3. Vérifier la preuve de possession de l'ancienne clé
	if device.PublicKey != nil && *device.PublicKey != "" {
		if err := s.VerifyRequestSignature(ctx, deviceID, oldNonce, oldTimestamp, oldSignature); err != nil {
			return fmt.Errorf("old key proof of possession failed: %w", err)
		}
	}

	// 4. Mettre à jour la clé
	if err := s.deviceSvc.repo.UpgradeKey(ctx, deviceID, newPublicKey, newKeyAlgorithm, newHardwareLevel, newProviderName); err != nil {
		return err
	}

	_ = s.deviceSvc.cache.InvalidateDevice(ctx, deviceID)

	s.logger.Info("device key upgraded",
		zap.String("device_id", deviceID),
		zap.String("from_level", currentLevel),
		zap.String("to_level", newHardwareLevel))

	return nil
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
