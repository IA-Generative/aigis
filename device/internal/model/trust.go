package model

import (
	"fmt"
	"time"

	"go.uber.org/zap"
)

// TrustParams contient les paramètres configurables du calcul de trust score.
// Passé en valeur pour garder le calcul pur (pas de dépendance config/service).
type TrustParams struct {
	PointsFirstDevice     int
	PointsEmail           int
	PointsAcr             int
	PointsCrossDevice     int
	ReattestIntervalHours int
}

// ComputeTrustScore calcule le trust score d'un device de façon déterministe
// à partir de l'état actuel du device et de l'horloge courante.
// Le score est toujours recalculé en temps réel — la valeur en DB n'est qu'un cache.
func ComputeTrustScore(device *Device, params TrustParams) (int, TrustBreakdown) {
	bd := computeBreakdown(device, params)
	fmt.Sprintf("breakdown", zap.Any("breakdown", bd))
	total := bd.ApprovalMethod +
		bd.AttestationAge +
		bd.ReattestCount +
		bd.ActivityPoints +
		bd.StatusPoints +
		bd.SignaturePoints

	if total < 0 {
		total = 0
	}
	if total > 100 {
		total = 100
	}
	return total, bd
}

func computeBreakdown(device *Device, params TrustParams) TrustBreakdown {
	var bd TrustBreakdown

	// ── 1. Approval method (0-30 points) ───────────────────────
	if device.ApprovedBy != nil {
		approver := *device.ApprovedBy
		switch {
		case len(approver) >= 17 && approver[:17] == "auto:first_device":
			bd.ApprovalMethod = params.PointsFirstDevice
		case len(approver) > 11 && approver[:11] == "self:email:":
			bd.ApprovalMethod = params.PointsEmail
		case len(approver) > 4 && approver[:4] == "acr:":
			bd.ApprovalMethod = params.PointsAcr
		default:
			bd.ApprovalMethod = params.PointsCrossDevice
		}
	}

	// ── 2. Signature level (0-25 points) ─────────────────────────
	if device.PublicKey != nil && *device.PublicKey != "" {
		bd.SignaturePoints = 25 // Points pour la présence d'une clé publique (preuve de possession)
	} else {
		bd.SignaturePoints = 0
	}

	// ── 3. Attestation freshness (−10 to +15 points) ────────────
	if device.AttestedAt != nil {
		age := time.Since(*device.AttestedAt)
		interval := time.Duration(params.ReattestIntervalHours) * time.Hour
		switch {
		case age < 1*time.Hour:
			bd.AttestationAge = 15
		case age < interval:
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
	case DeviceActive:
		bd.StatusPoints = 5
	default:
		bd.StatusPoints = -100
	}

	return bd
}
