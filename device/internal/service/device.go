package service

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"

	"time"

	"go.uber.org/zap"

	"github.com/ia-generative/device-service/internal/cache"
	"github.com/ia-generative/device-service/internal/config"
	"github.com/ia-generative/device-service/internal/model"
	"github.com/ia-generative/device-service/internal/repository"

	"math/big"

	"github.com/google/uuid"
	"github.com/redis/go-redis/v9"
)

type DeviceService struct {
	repo                   *repository.DeviceRepository
	cache                  *cache.Redis
	emailSvc               *EmailService
	logger                 *zap.Logger
	attestationMode        config.AttestationMode
	approvalTimeoutMinutes int
}

var ErrHardwareAttestationRequired = errors.New("hardware attestation required")

func NewDeviceService(repo *repository.DeviceRepository, cache *cache.Redis, logger *zap.Logger, attestationMode config.AttestationMode) *DeviceService {
	return &DeviceService{repo: repo, cache: cache, logger: logger, attestationMode: attestationMode}
}

// NewDeviceServiceWithConfig crée un DeviceService avec la configuration A+B
func NewDeviceServiceWithConfig(repo *repository.DeviceRepository, cache *cache.Redis, emailSvc *EmailService, logger *zap.Logger, cfg *config.Config) *DeviceService {
	return &DeviceService{
		repo:                   repo,
		cache:                  cache,
		emailSvc:               emailSvc,
		logger:                 logger,
		attestationMode:        cfg.AttestationMode,
		approvalTimeoutMinutes: cfg.ApprovalTimeoutMinutes,
	}
}

func (s *DeviceService) Register(ctx context.Context, req model.RegisterRequest) (*model.Device, error) {
	now := time.Now()
	hardwareLevel := req.HardwareLevel
	providerName := req.ProviderName
	publicKey := req.PublicKey
	keyAlgorithm := req.KeyAlgorithm

	if hardwareLevel == "" {
		hardwareLevel = "software"
	}
	if providerName == "" {
		providerName = "software"
	}

	// ─── Politique d'attestation ──────────────────────────────────────────────
	hasKeys := publicKey != ""

	switch s.attestationMode {
	case config.AttestationSoftwareOnly:
		// Software only : on accepte sans clé ou avec clé, mais pas hardware
		hardwareLevel = "software"
		providerName = "software"
		// On garde les clés si le client les envoie (challenge-then-register vérifié en amont)

	case config.AttestationRequireHardware:
		if !hasKeys {
			return nil, ErrHardwareAttestationRequired
		}
		if hardwareLevel != "tee" && hardwareLevel != "secure_enclave" {
			return nil, ErrHardwareAttestationRequired
		}

	case config.AttestationPreferHardware:
		// On accepte tout, clés ou pas.
		// Si pas de clés, on enregistre en "software" sans attestation.
		if !hasKeys {
			hardwareLevel = "software"
			providerName = "software"
		}
	}

	deviceID := req.DeviceID
	if deviceID == "" {
		deviceID = uuid.New().String()
	}

	// si aucun user_id fourni, rejet pour éviter les devices orphelins
	if req.UserID == "" {
		return nil, errors.New("user_id is required in token for device registration")
	}

	// ─── Architecture A+B : déterminer le statut initial ──────────────────────
	initialStatus := model.StatusActive
	activeCount, err := s.repo.CountActiveByUser(ctx, req.UserID)
	if err != nil {
		s.logger.Error("failed to count active devices", zap.Error(err))
		activeCount = 0
	}

	if activeCount == 0 {
		// Premier device : enregistrement direct
		s.logger.Info("first device registration — active directly",
			zap.String("user_id", req.UserID))
		initialStatus = model.StatusActive
	} else {
		// Architecture B : N-ième device → pending_approval + email challenge
		s.logger.Info("additional device registration (Architecture B — email challenge)",
			zap.String("user_id", req.UserID),
			zap.Int("existing_active_devices", activeCount))
		initialStatus = model.StatusPendingApproval
	}

	device := &model.Device{
		DeviceID:      deviceID,
		UserID:        req.UserID,
		Status:        initialStatus,
		HardwareLevel: &hardwareLevel,
		ProviderName:  &providerName,
	}

	if req.Name != "" {
		device.Name = &req.Name
	}
	if req.UserAgent != "" {
		device.UserAgent = &req.UserAgent
	}
	if req.Platform != "" {
		device.Platform = &req.Platform
	}
	if publicKey != "" {
		device.PublicKey = &publicKey
		device.AttestedAt = &now
	}
	if keyAlgorithm != "" {
		device.KeyAlgorithm = &keyAlgorithm
		if device.AttestedAt == nil {
			device.AttestedAt = &now
		}
	}

	if err := s.repo.CreateWithKey(ctx, device); err != nil {
		s.logger.Error("failed to create device", zap.Error(err))
		return nil, err
	}

	// Si pending_approval : générer un code email et l'envoyer à l'utilisateur
	if initialStatus == model.StatusPendingApproval {
		// Pub/Sub pour les devices déjà connectés
		event := `{"type":"pending_device","device_id":"` + device.DeviceID + `","name":"` + stringOrDefault(device.Name, "Nouveau device") + `","message":"Un nouveau device demande à être approuvé"}`
		if pubErr := s.cache.PublishApprovalEvent(ctx, req.UserID, event); pubErr != nil {
			s.logger.Warn("failed to publish approval event",
				zap.String("user_id", req.UserID),
				zap.Error(pubErr))
		}

		// Générer et stocker le code email
		if req.Email != "" {
			code, err := generateOTPCode()
			if err != nil {
				s.logger.Warn("failed to generate email challenge", zap.Error(err))
			} else {
				ttl := time.Duration(s.approvalTimeoutMinutes) * time.Minute
				if ttl <= 0 {
					ttl = 30 * time.Minute
				}
				if err := s.cache.SetEmailChallenge(ctx, device.DeviceID, code, ttl); err != nil {
					s.logger.Warn("failed to store email challenge", zap.Error(err))
				} else if s.emailSvc != nil {
					if err := s.emailSvc.SendDeviceApprovalCode(req.Email, stringOrDefault(device.Name, "Nouveau device"), code); err != nil {
						s.logger.Warn("failed to send approval email",
							zap.String("to", req.Email),
							zap.Error(err))
					} else {
						s.logger.Info("approval email sent",
							zap.String("to", req.Email),
							zap.String("device_id", device.DeviceID))
					}
				}
			}
		} else {
			s.logger.Warn("no email in token — email challenge skipped", zap.String("device_id", device.DeviceID))
		}
	}

	s.logger.Info("device registered",
		zap.String("device_id", device.DeviceID),
		zap.String("status", string(initialStatus)),
		zap.String("hardware_level", hardwareLevel),
		zap.String("provider_name", providerName),
	)
	// s.Bind(ctx, device.DeviceID, req.UserID)
	return device, nil
}

func (s *DeviceService) Get(ctx context.Context, deviceID string) (*model.Device, error) {
	return s.repo.GetByDeviceID(ctx, deviceID)
}

func (s *DeviceService) Status(ctx context.Context, deviceID string) (*model.StatusResponse, error) {
	// 1. Chercher dans le cache Redis
	if data, err := s.cache.GetDeviceStatus(ctx, deviceID); err == nil {
		var sr model.StatusResponse
		if err := json.Unmarshal(data, &sr); err == nil {
			s.logger.Debug("device status from cache", zap.String("device_id", deviceID))
			return &sr, nil
		}
	}

	// 2. Fallback sur Postgres
	device, err := s.repo.GetByDeviceID(ctx, deviceID)
	if err != nil {
		return nil, err
	}

	sr := &model.StatusResponse{
		DeviceID:      device.DeviceID,
		UserID:        device.UserID,
		Status:        device.Status,
		HardwareLevel: device.HardwareLevel,
		TrustScore:    device.TrustScore,
		AttestedAt:    device.AttestedAt,
		ReattestAt:    device.ReattestAt,
	}

	// 3. Mettre en cache
	if err := s.cache.SetDeviceStatus(ctx, deviceID, sr); err != nil {
		s.logger.Warn("failed to cache device status",
			zap.String("device_id", deviceID),
			zap.Error(err))
	}

	return sr, nil
}

func (s *DeviceService) ListByUser(ctx context.Context, userID string) ([]*model.Device, error) {
	return s.repo.ListByUserID(ctx, userID)
}

func (s *DeviceService) ListMine(ctx context.Context, userID string) ([]*model.Device, error) {
	return s.repo.ListByUserID(ctx, userID)
}

func (s *DeviceService) Revoke(ctx context.Context, deviceID, revokedBy string) error {
	if err := s.repo.Revoke(ctx, deviceID, revokedBy); err != nil {
		s.logger.Error("failed to revoke device",
			zap.String("device_id", deviceID),
			zap.Error(err))
		return err
	}

	// Invalider immédiatement le cache → révocation effective < TTL
	if err := s.cache.InvalidateDevice(ctx, deviceID); err != nil {
		s.logger.Warn("failed to invalidate cache after revoke",
			zap.String("device_id", deviceID),
			zap.Error(err))
	}

	s.logger.Info("device revoked",
		zap.String("device_id", deviceID),
		zap.String("revoked_by", revokedBy))
	return nil
}

func (s *DeviceService) RevokeMine(ctx context.Context, deviceID, userID string) error {
	if err := s.repo.RevokeByUser(ctx, deviceID, userID); err != nil {
		s.logger.Error("failed to revoke own device",
			zap.String("device_id", deviceID),
			zap.String("user_id", userID),
			zap.Error(err))
		return err
	}

	if err := s.cache.InvalidateDevice(ctx, deviceID); err != nil {
		s.logger.Warn("failed to invalidate cache after own revoke",
			zap.String("device_id", deviceID),
			zap.Error(err))
	}

	s.logger.Info("own device revoked",
		zap.String("device_id", deviceID),
		zap.String("user_id", userID))
	return nil
}

func (s *DeviceService) Delete(ctx context.Context, deviceID, userID string) error {
	if err := s.repo.Delete(ctx, deviceID, userID); err != nil {
		return err
	}

	_ = s.cache.InvalidateDevice(ctx, deviceID)

	s.logger.Info("device deleted",
		zap.String("device_id", deviceID),
		zap.String("user_id", userID))
	return nil
}

func (s *DeviceService) TouchLastSeen(ctx context.Context, deviceID string) error {
	if err := s.repo.UpdateLastSeen(ctx, deviceID); err != nil {
		return err
	}
	_ = s.cache.InvalidateDevice(ctx, deviceID)
	return nil
}

// RegisterWithKey enregistre un device et associe immédiatement
// les informations d'attestation cryptographique (clé publique + niveau hardware)
func (s *DeviceService) RegisterWithKey(
	ctx context.Context,
	baseReq *model.RegisterRequest,
	attestInfo *model.AttestationInfo,
) (*model.Device, error) {

	now := time.Now()

	device := &model.Device{
		DeviceID: uuid.New().String(),
		Status:   model.StatusActive,
		// Attestation
		PublicKey:     &attestInfo.PublicKeyPEM,
		KeyAlgorithm:  &attestInfo.KeyAlgorithm,
		HardwareLevel: &attestInfo.HardwareLevel,
		ProviderName:  &attestInfo.ProviderName,
		AttestedAt:    &now,
	}

	if baseReq.Name != "" {
		device.Name = &baseReq.Name
	}
	if baseReq.UserAgent != "" {
		device.UserAgent = &baseReq.UserAgent
	}
	if baseReq.Platform != "" {
		device.Platform = &baseReq.Platform
	}

	if err := s.repo.CreateWithKey(ctx, device); err != nil {
		s.logger.Error("failed to create device with key",
			zap.String("hardware_level", attestInfo.HardwareLevel),
			zap.Error(err),
		)
		return nil, err
	}

	s.logger.Info("device registered with attestation",
		zap.String("device_id", device.DeviceID),
		zap.String("hardware_level", attestInfo.HardwareLevel),
		zap.String("provider", attestInfo.ProviderName),
	)

	return device, nil
}

// ─── Architecture A+B : Approve / Reject / Pending ─────────────────────────

// ApproveDevice approuve un device pending_approval.
// approverDeviceID est le device_id du device de confiance qui approuve.
func (s *DeviceService) ApproveDevice(ctx context.Context, deviceID, approverDeviceID, userID string) error {
	// Vérifier que le device pending appartient bien au même utilisateur
	pendingDevice, err := s.repo.GetByDeviceID(ctx, deviceID)
	if err != nil {
		return err
	}
	if pendingDevice.UserID != userID {
		return errors.New("device does not belong to this user")
	}
	if pendingDevice.Status != model.StatusPendingApproval {
		return errors.New("device is not pending approval")
	}

	// Vérifier que le device approbateur est actif et appartient au même user
	approver, err := s.repo.GetByDeviceID(ctx, approverDeviceID)
	if err != nil {
		return errors.New("approver device not found")
	}
	if approver.UserID != userID {
		return errors.New("approver device does not belong to this user")
	}
	if approver.Status != model.StatusActive {
		return errors.New("approver device is not active")
	}

	if err := s.repo.Approve(ctx, deviceID, approverDeviceID); err != nil {
		s.logger.Error("failed to approve device", zap.Error(err))
		return err
	}

	_ = s.cache.InvalidateDevice(ctx, deviceID)

	// Notifier via Pub/Sub que le device a été approuvé
	event := `{"type":"approved","device_id":"` + deviceID + `","message":"Device approuvé par ` + approverDeviceID + `"}`
	if pubErr := s.cache.PublishApprovalEvent(ctx, userID, event); pubErr != nil {
		s.logger.Warn("failed to publish approval event", zap.Error(pubErr))
	}

	s.logger.Info("device approved",
		zap.String("device_id", deviceID),
		zap.String("approved_by", approverDeviceID))
	return nil
}

// ValidateEmailChallenge vérifie le code OTP envoyé par email et approuve le device.
func (s *DeviceService) ValidateEmailChallenge(ctx context.Context, deviceID, userID, code string) error {
	device, err := s.repo.GetByDeviceID(ctx, deviceID)
	if err != nil {
		return err
	}
	if device.UserID != userID {
		return errors.New("device does not belong to this user")
	}
	if device.Status != model.StatusPendingApproval {
		return errors.New("device is not pending approval")
	}

	stored, err := s.cache.GetAndDeleteEmailChallenge(ctx, deviceID)
	if err != nil {
		return fmt.Errorf("failed to retrieve email challenge: %w", err)
	}
	if stored == "" {
		return errors.New("email challenge expired or not found — request a new registration")
	}
	if subtle.ConstantTimeCompare([]byte(code), []byte(stored)) != 1 {
		return errors.New("invalid code")
	}

	if err := s.repo.Approve(ctx, deviceID, "self:email:"+userID); err != nil {
		s.logger.Error("failed to approve device via email challenge", zap.Error(err))
		return err
	}

	_ = s.cache.InvalidateDevice(ctx, deviceID)

	event := `{"type":"approved","device_id":"` + deviceID + `","message":"Device approuvé par code email"}`
	if pubErr := s.cache.PublishApprovalEvent(ctx, userID, event); pubErr != nil {
		s.logger.Warn("failed to publish approval event", zap.Error(pubErr))
	}

	s.logger.Info("device approved via email challenge",
		zap.String("device_id", deviceID),
		zap.String("user_id", userID))
	return nil
}

// RejectDevice rejette un device pending_approval
func (s *DeviceService) RejectDevice(ctx context.Context, deviceID, userID string) error {
	pendingDevice, err := s.repo.GetByDeviceID(ctx, deviceID)
	if err != nil {
		return err
	}
	if pendingDevice.UserID != userID {
		return errors.New("device does not belong to this user")
	}
	if pendingDevice.Status != model.StatusPendingApproval {
		return errors.New("device is not pending approval")
	}

	if err := s.repo.Reject(ctx, deviceID, userID); err != nil {
		s.logger.Error("failed to reject device", zap.Error(err))
		return err
	}

	_ = s.cache.InvalidateDevice(ctx, deviceID)

	// Notifier via Pub/Sub que le device a été rejeté
	event := `{"type":"rejected","device_id":"` + deviceID + `","message":"Device rejeté"}`
	if pubErr := s.cache.PublishApprovalEvent(ctx, userID, event); pubErr != nil {
		s.logger.Warn("failed to publish rejection event", zap.Error(pubErr))
	}

	s.logger.Info("device rejected",
		zap.String("device_id", deviceID),
		zap.String("rejected_by", userID))
	return nil
}

// ListPending retourne les devices en attente d'approbation pour un utilisateur
func (s *DeviceService) ListPending(ctx context.Context, userID string) ([]*model.Device, error) {
	return s.repo.ListPendingByUser(ctx, userID)
}

// CountActiveDevices retourne le nombre de devices actifs pour un utilisateur
func (s *DeviceService) CountActiveDevices(ctx context.Context, userID string) (int, error) {
	return s.repo.CountActiveByUser(ctx, userID)
}

// SubscribeApproval souscrit au canal de notifications d'approbation d'un utilisateur
func (s *DeviceService) SubscribeApproval(ctx context.Context, userID string) *redis.PubSub {
	return s.cache.SubscribeApproval(ctx, userID)
}

// helper
func stringOrDefault(s *string, def string) string {
	if s != nil && *s != "" {
		return *s
	}
	return def
}

// generateOTPCode generates a cryptographically secure 6-digit code.
func generateOTPCode() (string, error) {
	n, err := rand.Int(rand.Reader, big.NewInt(1_000_000))
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("%06d", n.Int64()), nil
}
