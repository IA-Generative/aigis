package service

import (
	"context"
	"time"

	"go.uber.org/zap"

	"github.com/ia-generative/device-service/internal/model"
)

// RiskService calcule un score de confiance gradué (0–100) pour un device
// Architecture D — Graduated Trust : le score monte progressivement selon
// la méthode d'approbation, le hardware, la fraîcheur d'attestation, la fidélité
// de re-attestation et l'activité récente.
type RiskService struct {
	deviceSvc             *DeviceService
	reattestIntervalHours int
	logger                *zap.Logger
}

func NewRiskService(deviceSvc *DeviceService, reattestIntervalHours int, logger *zap.Logger) *RiskService {
	return &RiskService{
		deviceSvc:             deviceSvc,
		reattestIntervalHours: reattestIntervalHours,
		logger:                logger,
	}
}

// ComputeTrustScore calcule et persiste le trust score d'un device
func (s *RiskService) ComputeTrustScore(ctx context.Context, deviceID string) (*model.TrustScoreResponse, error) {
	device, err := s.deviceSvc.Get(ctx, deviceID)
	if err != nil {
		return nil, err
	}

	breakdown := s.computeBreakdown(device)
	total := breakdown.ApprovalMethod +
		breakdown.HardwarePoints +
		breakdown.AttestationAge +
		breakdown.ReattestCount +
		breakdown.ActivityPoints +
		breakdown.StatusPoints

	// Clamp to 0-100
	if total < 0 {
		total = 0
	}
	if total > 100 {
		total = 100
	}

	// Persist
	if err := s.deviceSvc.repo.UpdateTrustScore(ctx, deviceID, total); err != nil {
		s.logger.Warn("failed to persist trust score",
			zap.String("device_id", deviceID),
			zap.Error(err))
	}

	// Cache
	if err := s.deviceSvc.cache.InvalidateDevice(ctx, deviceID); err != nil {
		s.logger.Warn("failed to invalidate cache after trust update",
			zap.String("device_id", deviceID),
			zap.Error(err))
	}

	hwLevel := "unknown"
	if device.HardwareLevel != nil {
		hwLevel = *device.HardwareLevel
	}

	return &model.TrustScoreResponse{
		DeviceID:      deviceID,
		TrustScore:    total,
		HardwareLevel: hwLevel,
		Breakdown:     breakdown,
	}, nil
}

func (s *RiskService) computeBreakdown(device *model.Device) model.TrustBreakdown {
	var bd model.TrustBreakdown

	// ── 1. Approval method (0-30 points) ───────────────────────
	// Premier facteur du Graduated Trust : comment le device a été admis.
	// approved_by = nil          → premier device (aucune validation tierce)
	// approved_by = "self:email:*" → auto-approbation par code email
	// approved_by = "<device_id>"  → cross-device approval
	if device.ApprovedBy == nil {
		// Premier device de l'utilisateur — pas de validation externe
		bd.ApprovalMethod = 10
	} else {
		approver := *device.ApprovedBy
		if len(approver) > 11 && approver[:11] == "self:email:" {
			// Email self-approve — preuve de contrôle de l'identité
			bd.ApprovalMethod = 20
		} else {
			// Cross-device approval — validé par un device de confiance
			bd.ApprovalMethod = 30
		}
	}

	// ── 2. Hardware level (0-25 points) ─────────────────────────
	if device.HardwareLevel != nil {
		switch *device.HardwareLevel {
		case "tee", "secure_enclave":
			bd.HardwarePoints = 25
		case "software":
			if device.PublicKey != nil && *device.PublicKey != "" {
				bd.HardwarePoints = 15
			} else {
				bd.HardwarePoints = 5
			}
		default:
			bd.HardwarePoints = 5
		}
	}

	// ── 3. Attestation freshness (−10 to +15 points) ────────────
	if device.AttestedAt != nil {
		age := time.Since(*device.AttestedAt)
		switch {
		case age < 1*time.Hour:
			bd.AttestationAge = 15
		case age < time.Duration(s.reattestIntervalHours)*time.Hour:
			bd.AttestationAge = 10
		case age < 7*24*time.Hour:
			bd.AttestationAge = 0
		default:
			bd.AttestationAge = -10
		}
	}

	// ── 4. Re-attestation loyalty (0-15 points) ─────────────────
	if device.ReattestCount != nil {
		count := *device.ReattestCount
		switch {
		case count >= 10:
			bd.ReattestCount = 15
		case count >= 5:
			bd.ReattestCount = 10
		case count >= 1:
			bd.ReattestCount = 5
		default:
			bd.ReattestCount = 0
		}
	}

	// ── 5. Recent activity (0-10 points) ──────────────────────────
	if device.LastSeen != nil {
		since := time.Since(*device.LastSeen)
		switch {
		case since < 1*time.Hour:
			bd.ActivityPoints = 10
		case since < 24*time.Hour:
			bd.ActivityPoints = 5
		default:
			bd.ActivityPoints = 0
		}
	}

	// ── 6. Status (−20 to +5 points) ──────────────────────────────
	switch device.Status {
	case model.StatusActive:
		bd.StatusPoints = 5
	case model.StatusSuspended:
		bd.StatusPoints = -10
	case model.StatusRevoked:
		bd.StatusPoints = -20
	}

	return bd
}
