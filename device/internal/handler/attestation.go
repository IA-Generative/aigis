package handler

import (
	"encoding/json"
	"errors"
	"net/http"

	"github.com/go-chi/chi/v5"
	"go.uber.org/zap"

	"github.com/ia-generative/device-service/internal/ctxkeys"
	"github.com/ia-generative/device-service/internal/model"
	"github.com/ia-generative/device-service/internal/repository"
	"github.com/ia-generative/device-service/internal/service"
)

type AttestationHandler struct {
	attestSvc *service.AttestationService
	riskSvc   *service.RiskService
	logger    *zap.Logger
}

func NewAttestationHandler(
	attestSvc *service.AttestationService,
	riskSvc *service.RiskService,
	logger *zap.Logger,
) *AttestationHandler {
	return &AttestationHandler{
		attestSvc: attestSvc,
		riskSvc:   riskSvc,
		logger:    logger,
	}
}

// POST /devices/register/challenge
// Génère un challenge pré-enregistrement (le device n'existe pas encore)
// Le challenge est lié au userID du JWT, stocké dans Redis.
func (h *AttestationHandler) RegisterChallenge(w http.ResponseWriter, r *http.Request) {
	userID, ok := r.Context().Value(ctxkeys.UserID).(string)
	if !ok || userID == "" {
		jsonError(w, "unauthorized", http.StatusUnauthorized)
		return
	}

	challenge, err := h.attestSvc.GenerateRegisterChallenge(r.Context(), userID)
	if err != nil {
		h.logger.Error("failed to generate register challenge",
			zap.String("user_id", userID),
			zap.Error(err))
		jsonError(w, "internal error", http.StatusInternalServerError)
		return
	}

	resp := model.ChallengeResponse{
		Challenge: challenge,
		ExpiresIn: 120, // 2 minutes
	}
	jsonResponse(w, resp, http.StatusOK)
}

// POST /devices/{device_id}/challenge
// Génère un challenge pour le device (WebAuthn / signature ECDSA)
func (h *AttestationHandler) Challenge(w http.ResponseWriter, r *http.Request) {
	deviceID := chi.URLParam(r, "device_id")
	if deviceID == "" {
		jsonError(w, "device_id required", http.StatusBadRequest)
		return
	}

	challenge, err := h.attestSvc.GenerateChallenge(r.Context(), deviceID)
	if err != nil {
		if errors.Is(err, repository.ErrNotFound) {
			jsonError(w, "device not found", http.StatusNotFound)
			return
		}
		h.logger.Error("failed to generate challenge",
			zap.String("device_id", deviceID),
			zap.Error(err))
		jsonError(w, "internal error", http.StatusInternalServerError)
		return
	}

	resp := model.ChallengeResponse{
		Challenge: challenge,
		ExpiresIn: 120, // 2 minutes
	}
	jsonResponse(w, resp, http.StatusOK)
}

// POST /devices/{device_id}/verify
// Vérifie une signature sur un challenge (device-bound session proof)
func (h *AttestationHandler) Verify(w http.ResponseWriter, r *http.Request) {
	deviceID := chi.URLParam(r, "device_id")

	var req model.VerifyChallengeRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		jsonError(w, "invalid request body", http.StatusBadRequest)
		return
	}
	req.DeviceID = deviceID

	if err := h.attestSvc.VerifyRequestSignature(
		r.Context(),
		req.DeviceID,
		req.Nonce,
		req.Timestamp,
		req.Signature,
	); err != nil {
		h.logger.Warn("signature verification failed",
			zap.String("device_id", deviceID),
			zap.Error(err))
		jsonError(w, err.Error(), http.StatusUnauthorized)
		return
	}

	// Recalculate trust score after successful verification
	trustResp, err := h.riskSvc.ComputeTrustScore(r.Context(), deviceID)
	if err != nil {
		h.logger.Warn("trust score computation failed after verify",
			zap.String("device_id", deviceID),
			zap.Error(err))
	}

	resp := map[string]interface{}{
		"verified":  true,
		"device_id": deviceID,
	}
	if trustResp != nil {
		resp["trust_score"] = trustResp.TrustScore
	}
	jsonResponse(w, resp, http.StatusOK)
}

// POST /devices/{device_id}/reattest
// Re-attestation : le device prouve qu'il possède toujours la clé
// et optionnellement fournit une nouvelle preuve matérielle (TPM quote)
func (h *AttestationHandler) Reattest(w http.ResponseWriter, r *http.Request) {
	deviceID := chi.URLParam(r, "device_id")

	userID, ok := r.Context().Value(ctxkeys.UserID).(string)
	if !ok || userID == "" {
		jsonError(w, "unauthorized", http.StatusUnauthorized)
		return
	}

	var req model.ReattestRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		jsonError(w, "invalid request body", http.StatusBadRequest)
		return
	}
	req.DeviceID = deviceID

	// 0. Hardware level policy: check for downgrade attempt
	if req.HardwareLevel != "" {
		device, err := h.attestSvc.GetDevice(r.Context(), deviceID)
		if err != nil {
			h.logger.Error("failed to get device for hw check",
				zap.String("device_id", deviceID),
				zap.Error(err))
			jsonError(w, "device not found", http.StatusNotFound)
			return
		}

		currentLevel := "software"
		if device.HardwareLevel != nil {
			currentLevel = *device.HardwareLevel
		}

		if err := h.attestSvc.CheckHardwareLevelTransition(r.Context(), deviceID, currentLevel, req.HardwareLevel); err != nil {
			h.logger.Warn("reattest hardware downgrade blocked",
				zap.String("device_id", deviceID),
				zap.String("current", currentLevel),
				zap.String("requested", req.HardwareLevel))
			jsonError(w, err.Error(), http.StatusForbidden)
			return
		}
	}

	// 1. Verify the signature (proves possession of the private key)
	if err := h.attestSvc.VerifyRequestSignature(
		r.Context(),
		req.DeviceID,
		req.Nonce,
		req.Timestamp,
		req.Signature,
	); err != nil {
		h.logger.Warn("reattest signature failed",
			zap.String("device_id", deviceID),
			zap.Error(err))
		jsonError(w, "signature verification failed: "+err.Error(), http.StatusUnauthorized)
		return
	}

	// 2. Record successful re-attestation
	if err := h.attestSvc.RecordReattestation(r.Context(), deviceID); err != nil {
		h.logger.Error("failed to record reattestation",
			zap.String("device_id", deviceID),
			zap.Error(err))
		jsonError(w, "internal error", http.StatusInternalServerError)
		return
	}

	// 3. Recompute trust score
	trustResp, err := h.riskSvc.ComputeTrustScore(r.Context(), deviceID)
	if err != nil {
		h.logger.Warn("trust score computation failed after reattest",
			zap.String("device_id", deviceID),
			zap.Error(err))
	}

	resp := map[string]interface{}{
		"reattested": true,
		"device_id":  deviceID,
	}
	if trustResp != nil {
		resp["trust_score"] = trustResp.TrustScore
		resp["breakdown"] = trustResp.Breakdown
	}

	h.logger.Info("device re-attested",
		zap.String("device_id", deviceID),
		zap.String("user_id", userID))

	jsonResponse(w, resp, http.StatusOK)
}

// POST /devices/{device_id}/upgrade-key
// Upgrade de clé : le device prouve qu'il possède l'ancienne clé
// et fournit une nouvelle clé avec un hardware_level supérieur.
func (h *AttestationHandler) UpgradeKey(w http.ResponseWriter, r *http.Request) {
	deviceID := chi.URLParam(r, "device_id")

	userID, ok := r.Context().Value(ctxkeys.UserID).(string)
	if !ok || userID == "" {
		jsonError(w, "unauthorized", http.StatusUnauthorized)
		return
	}

	var req model.UpgradeKeyRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		jsonError(w, "invalid request body", http.StatusBadRequest)
		return
	}
	req.DeviceID = deviceID

	if req.PublicKey == "" || req.HardwareLevel == "" {
		jsonError(w, "public_key and hardware_level are required", http.StatusBadRequest)
		return
	}

	if err := h.attestSvc.UpgradeKey(
		r.Context(),
		deviceID, userID,
		req.PublicKey, req.KeyAlgorithm, req.HardwareLevel, req.ProviderName,
		req.Nonce, req.Timestamp, req.OldSignature,
	); err != nil {
		h.logger.Warn("key upgrade failed",
			zap.String("device_id", deviceID),
			zap.Error(err))
		status := http.StatusBadRequest
		if err.Error() == "device does not belong to this user" {
			status = http.StatusForbidden
		}
		jsonError(w, err.Error(), status)
		return
	}

	// Recompute trust score after upgrade
	trustResp, err := h.riskSvc.ComputeTrustScore(r.Context(), deviceID)
	if err != nil {
		h.logger.Warn("trust score computation failed after key upgrade",
			zap.String("device_id", deviceID),
			zap.Error(err))
	}

	resp := map[string]interface{}{
		"upgraded":       true,
		"device_id":      deviceID,
		"hardware_level": req.HardwareLevel,
	}
	if trustResp != nil {
		resp["trust_score"] = trustResp.TrustScore
		resp["breakdown"] = trustResp.Breakdown
	}

	h.logger.Info("device key upgraded",
		zap.String("device_id", deviceID),
		zap.String("user_id", userID),
		zap.String("new_level", req.HardwareLevel))

	jsonResponse(w, resp, http.StatusOK)
}

// GET /devices/{device_id}/trust
// Retourne le trust score actuel du device
func (h *AttestationHandler) TrustScore(w http.ResponseWriter, r *http.Request) {
	deviceID := chi.URLParam(r, "device_id")

	trustResp, err := h.riskSvc.ComputeTrustScore(r.Context(), deviceID)
	if err != nil {
		if errors.Is(err, repository.ErrNotFound) {
			jsonError(w, "device not found", http.StatusNotFound)
			return
		}
		h.logger.Error("trust score computation failed",
			zap.String("device_id", deviceID),
			zap.Error(err))
		jsonError(w, "internal error", http.StatusInternalServerError)
		return
	}

	jsonResponse(w, trustResp, http.StatusOK)
}
