package service

import (
	"context"

	"go.uber.org/zap"

	"github.com/ia-generative/aigis/internal/config"
	"github.com/ia-generative/aigis/internal/model"
)

// RiskService calcule un score de confiance gradué (0–100) pour un device.
// Le score est TOUJOURS calculé en temps réel via model.ComputeTrustScore.
// La valeur persistée en DB n'est qu'un cache informatif (dashboard, logs).
type RiskService struct {
	deviceSvc *DeviceService
	cfg       *config.Config
	logger    *zap.Logger
}

func NewRiskService(deviceSvc *DeviceService, cfg *config.Config, logger *zap.Logger) *RiskService {
	return &RiskService{
		deviceSvc: deviceSvc,
		cfg:       cfg,
		logger:    logger,
	}
}

// TrustParams construit les paramètres de calcul à partir de la config.
func TrustParamsFromConfig(cfg *config.Config) model.TrustParams {
	return model.TrustParams{
		PointsFirstDevice:     cfg.TrustPointsFirstDevice,
		PointsEmail:           cfg.TrustPointsEmail,
		PointsAcr:             cfg.TrustPointsAcr,
		PointsCrossDevice:     cfg.TrustPointsCrossDevice,
		ReattestIntervalHours: cfg.ReattestIntervalHours,
	}
}

// ComputeTrustScore calcule le trust score en temps réel et persiste le résultat
// en DB comme cache (pour dashboard/analytics uniquement).
func (s *RiskService) ComputeTrustScore(ctx context.Context, deviceID string) (*model.TrustScoreResponse, error) {
	device, err := s.deviceSvc.Get(ctx, deviceID)
	if err != nil {
		return nil, err
	}

	params := TrustParamsFromConfig(s.cfg)
	total, breakdown := model.ComputeTrustScore(device, params)

	// Persist as cache (informational only — never used for access decisions)
	if err := s.deviceSvc.repo.UpdateTrustScore(ctx, deviceID, total); err != nil {
		s.logger.Warn("failed to persist trust score cache",
			zap.String("device_id", deviceID),
			zap.Error(err))
	}

	if err := s.deviceSvc.cache.InvalidateDevice(ctx, deviceID); err != nil {
		s.logger.Warn("failed to invalidate cache after trust update",
			zap.String("device_id", deviceID),
			zap.Error(err))
	}

	return &model.TrustScoreResponse{
		DeviceID:   deviceID,
		TrustScore: total,
		Breakdown:  breakdown,
	}, nil
}
