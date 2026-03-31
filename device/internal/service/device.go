package service

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
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
	repo     *repository.DeviceRepository
	cache    *cache.Redis
	emailSvc *EmailService
	logger   *zap.Logger
	cfg      *config.Config
}

var ErrHardwareAttestationRequired = errors.New("hardware attestation required")

func NewDeviceService(repo *repository.DeviceRepository, cache *cache.Redis, logger *zap.Logger, cfg *config.Config) *DeviceService {
	return &DeviceService{repo: repo, cache: cache, logger: logger, cfg: cfg}
}

// NewDeviceServiceWithConfig crée un DeviceService avec la configuration complète (email, etc.)
func NewDeviceServiceWithConfig(repo *repository.DeviceRepository, cache *cache.Redis, emailSvc *EmailService, logger *zap.Logger, cfg *config.Config) *DeviceService {
	return &DeviceService{
		repo:     repo,
		cache:    cache,
		emailSvc: emailSvc,
		logger:   logger,
		cfg:      cfg,
	}
}

// ─── Enrollment Policy Engine ────────────────────────────────────────────────

// RegistrationDecision contient la décision prise par la politique d'enrollment.
type RegistrationDecision struct {
	InitialStatus         model.DeviceStatus
	ApprovedBy            string // ex: "auto:first_device", "acr:<value>", ""
	SendEmailChallenge    bool
	NotifyExistingDevices bool
}

// resolveRegistration détermine le statut initial et les actions post-enregistrement
// selon : AutoApproveFirstDevice, ApprovalMethods (acr/email/cross_device), AcrValues.
func (s *DeviceService) resolveRegistration(ctx context.Context, req model.RegisterRequest) (*RegistrationDecision, error) {
	cfg := s.cfg
	hasEmail := req.Email != ""

	// ── 1. Premier device auto-approuvé ? ──────────────────────────────
	if cfg.AutoApproveFirstDevice {
		activeCount, err := s.repo.CountActiveByUser(ctx, req.UserID)
		if err != nil {
			return nil, fmt.Errorf("failed to count active devices: %w", err)
		}
		if activeCount == 0 {
			s.logger.Info("first device — auto-approved",
				zap.String("user_id", req.UserID))
			return &RegistrationDecision{
				InitialStatus:         model.DeviceActive,
				ApprovedBy:            "auto:first_device",
				SendEmailChallenge:    false,
				NotifyExistingDevices: false,
			}, nil
		}
	}

	// ── 2. ACR approval : si activé et que le token satisfait acr_values → actif ─
	if cfg.HasApprovalMethod(config.ApprovalAcr) && cfg.AcrValues != "" && req.Acr != "" {
		if req.Acr == cfg.AcrValues {
			s.logger.Info("device approved via ACR",
				zap.String("user_id", req.UserID),
				zap.String("acr", req.Acr))
			return &RegistrationDecision{
				InitialStatus:         model.DeviceActive,
				ApprovedBy:            "acr:" + req.Acr,
				SendEmailChallenge:    false,
				NotifyExistingDevices: false,
			}, nil
		}
		s.logger.Info("ACR mismatch — falling through to async approval",
			zap.String("required", cfg.AcrValues),
			zap.String("got", req.Acr))
	}

	// ── 3. Aucune approbation synchrone → pending avec méthodes async ──
	s.logger.Info("device pending approval",
		zap.String("user_id", req.UserID),
		zap.Any("approval_methods", cfg.ApprovalMethods))

	return &RegistrationDecision{
		InitialStatus:         model.DevicePendingApproval,
		SendEmailChallenge:    hasEmail && cfg.HasApprovalMethod(config.ApprovalEmail),
		NotifyExistingDevices: cfg.HasApprovalMethod(config.ApprovalCrossDevice),
	}, nil
}

func (s *DeviceService) Register(ctx context.Context, req model.RegisterRequest) (*model.Device, error) {
	now := time.Now()
	providerName := req.ProviderName
	publicKey := req.PublicKey
	keyAlgorithm := req.KeyAlgorithm

	deviceID := req.DeviceID
	if deviceID == "" {
		deviceID = uuid.New().String()
	}

	if req.UserID == "" {
		return nil, errors.New("user_id is required in token for device registration")
	}

	// ─── Résolution de la politique d'enrollment ───────────────────────────────
	decision, err := s.resolveRegistration(ctx, req)
	if err != nil {
		return nil, fmt.Errorf("registration policy resolution failed: %w", err)
	}
	initialStatus := decision.InitialStatus

	device := &model.Device{
		DeviceID:     deviceID,
		UserID:       req.UserID,
		Status:       initialStatus,
		ProviderName: &providerName,
	}
	if decision.ApprovedBy != "" {
		device.ApprovedBy = &decision.ApprovedBy
		now := time.Now()
		device.ApprovedAt = &now
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

	s.ApplyRegistrationDecision(ctx, decision, *device, req)

	s.logger.Info("device registered",
		zap.String("device_id", device.DeviceID),
		zap.String("status", string(initialStatus)),
		zap.String("provider_name", providerName),
	)
	return device, nil
}

func (s *DeviceService) RenewOTPCode(ctx context.Context, req model.RenewCodeRequest) error {
	deviceID := req.DeviceID
	if deviceID == "" {
		return errors.New("no device id provided")
	}

	device, err := s.repo.GetByDeviceID(ctx, deviceID)
	if err != nil {
		s.logger.Error("failed to get device", zap.Error(err))
		return err
	}

	if req.UserID != device.UserID {
		return repository.ErrNotFound
	}

	if device.Status != model.DevicePendingApproval {
		return errors.New("device is not in pending approval")
	}

	if req.Email == "" {
		return errors.New("can't retrieve email from authorization")
	}

	if !s.cfg.HasApprovalMethod(config.ApprovalEmail) {
		return errors.New("validation by email is disabled")
	}

	s.SendEmailChallenge(ctx, *device, req.Email)

	return nil
}

func (s *DeviceService) Get(ctx context.Context, deviceID string) (*model.Device, error) {
	return s.repo.GetByDeviceID(ctx, deviceID)
}

func (s *DeviceService) Status(ctx context.Context, deviceID string) (*model.StatusResponse, error) {
	device, err := s.repo.GetByDeviceID(ctx, deviceID)
	if err != nil {
		return nil, err
	}

	// Trust score calculé en temps réel (jamais lu depuis DB)
	params := TrustParamsFromConfig(s.cfg)
	score, _ := model.ComputeTrustScore(device, params)

	signed := device.PublicKey != nil && *device.PublicKey != ""
	sr := &model.StatusResponse{
		DeviceID:   device.DeviceID,
		Status:     device.Status,
		TrustScore: &score,
		UserID:     device.UserID,
		Signed:     signed,
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
		Status:   model.DeviceActive,
		// Attestation
		PublicKey:    &attestInfo.PublicKeyPEM,
		KeyAlgorithm: &attestInfo.KeyAlgorithm,
		ProviderName: &attestInfo.ProviderName,
		AttestedAt:   &now,
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
			zap.Error(err),
		)
		return nil, err
	}

	s.logger.Info("device registered with attestation",
		zap.String("device_id", device.DeviceID),
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
	if pendingDevice.Status != model.DevicePendingApproval {
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
	if approver.Status != model.DeviceActive {
		return errors.New("approver device is not active")
	}

	// Vérifier que l'approbateur a un trust score suffisant (temps réel)
	params := TrustParamsFromConfig(s.cfg)
	approverScore, _ := model.ComputeTrustScore(approver, params)
	if approverScore < s.cfg.CrossDeviceMinTrust {
		return fmt.Errorf("approver trust score too low (%d < %d)", approverScore, s.cfg.CrossDeviceMinTrust)
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
	if device.Status != model.DevicePendingApproval {
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
	if pendingDevice.Status != model.DevicePendingApproval {
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

func (s *DeviceService) GetDevicePendingApprovalMethods() []config.ApprovalMethod {
	return s.cfg.ApprovalMethods
}

func (s *DeviceService) ApplyRegistrationDecision(ctx context.Context, decision *RegistrationDecision, device model.Device, req model.RegisterRequest) {
	// ─── Actions post-enregistrement selon la décision de politique ─────────
	if decision.NotifyExistingDevices {
		event := `{"type":"pending_device","device_id":"` + device.DeviceID + `","name":"` + stringOrDefault(device.Name, "Nouveau device") + `","message":"Un nouveau device demande à être approuvé"}`
		if pubErr := s.cache.PublishApprovalEvent(ctx, device.UserID, event); pubErr != nil {
			s.logger.Warn("failed to publish approval event",
				zap.String("user_id", device.UserID),
				zap.Error(pubErr))
		}
	}

	if decision.SendEmailChallenge {
		s.SendEmailChallenge(ctx, device, req.Email)
	}
}

func (s *DeviceService) SendEmailChallenge(ctx context.Context, device model.Device, email string) error {
	code, err := generateOTPCode()
	if err != nil {
		s.logger.Warn("failed to generate email challenge", zap.Error(err))
	} else {
		ttl := time.Duration(s.cfg.EmailChallengeTTL) * time.Minute
		if ttl <= 0 {
			ttl = 30 * time.Minute
		}
		if err := s.cache.SetEmailChallenge(ctx, device.DeviceID, code, ttl); err != nil {
			s.logger.Warn("failed to store email challenge", zap.Error(err))
		} else if s.emailSvc != nil {
			if err := s.emailSvc.SendDeviceApprovalCode(email, stringOrDefault(device.Name, "Nouveau device"), code); err != nil {
				s.logger.Warn("failed to send approval email",
					zap.String("to", email),
					zap.Error(err))
			} else {
				s.logger.Info("approval email sent",
					zap.String("to", email),
					zap.String("device_id", device.DeviceID))
			}
		}
	}
	return nil
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
