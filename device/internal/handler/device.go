package handler

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"

	"github.com/go-chi/chi/v5"
	"go.uber.org/zap"

	"github.com/ia-generative/device-service/internal/config"
	"github.com/ia-generative/device-service/internal/ctxkeys"
	"github.com/ia-generative/device-service/internal/model"
	"github.com/ia-generative/device-service/internal/repository"
	"github.com/ia-generative/device-service/internal/service"
)

type DeviceHandler struct {
	svc       *service.DeviceService
	attestSvc *service.AttestationService
	riskSvc   *service.RiskService
	cfg       *config.Config
	logger    *zap.Logger
}

func NewDeviceHandler(svc *service.DeviceService, attestSvc *service.AttestationService, riskSvc *service.RiskService, cfg *config.Config, logger *zap.Logger) *DeviceHandler {
	return &DeviceHandler{svc: svc, attestSvc: attestSvc, riskSvc: riskSvc, cfg: cfg, logger: logger}
}

// POST /devices/register
func (h *DeviceHandler) Register(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		jsonError(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// userID extrait du JWT par le middleware
	userID, ok := r.Context().Value(ctxkeys.UserID).(string)
	if !ok || userID == "" {
		jsonError(w, "unauthorized", http.StatusUnauthorized)
		return
	}

	h.logger.Info("register device request", zap.String("user_id", userID))

	var req authRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil && !errors.Is(err, io.EOF) {
		resp := map[string]interface{}{
			"message": "invalid request body",
		}
		jsonResponse(w, resp, http.StatusBadRequest)
		return
	}

	registerReq := model.RegisterRequest{
		UserID:             userID,
		DeviceID:           req.DeviceID,
		Name:               req.Name,
		UserAgent:          req.UserAgent,
		Platform:           req.Platform,
		PublicKey:          req.PublicKey,
		KeyAlgorithm:       req.KeyAlgorithm,
		HardwareLevel:      req.HardwareLevel,
		ProviderName:       req.ProviderName,
		Challenge:          req.Challenge,
		ChallengeSignature: req.ChallengeSignature,
	}

	// Extract email from JWT context (Architecture B — email challenge)
	if email, ok := r.Context().Value(ctxkeys.Email).(string); ok {
		registerReq.Email = email
	}

	// ─── Challenge-then-register : vérifier la preuve de possession ──────────
	if registerReq.PublicKey != "" && registerReq.Challenge != "" && registerReq.ChallengeSignature != "" {
		if err := h.attestSvc.VerifyRegisterSignature(
			r.Context(),
			userID,
			registerReq.PublicKey,
			registerReq.Challenge,
			registerReq.ChallengeSignature,
		); err != nil {
			h.logger.Warn("register challenge verification failed",
				zap.String("user_id", userID),
				zap.Error(err))
			resp := map[string]interface{}{
				"message": "challenge signature verification failed: " + err.Error(),
			}
			jsonResponse(w, resp, http.StatusBadRequest)
			return
		}
		h.logger.Info("register challenge verified",
			zap.String("user_id", userID),
			zap.String("hardware_level", registerReq.HardwareLevel))
	} else if registerReq.PublicKey != "" && (registerReq.Challenge == "" || registerReq.ChallengeSignature == "") {
		h.logger.Warn("register with key but no challenge proof — key binding not verified",
			zap.String("user_id", userID))
	}

	if req.DeviceID == "" {
		device, err := h.svc.Register(r.Context(), registerReq)
		if err != nil {
			if errors.Is(err, service.ErrHardwareAttestationRequired) {
				resp := map[string]interface{}{
					"message": "hardware attestation required",
				}
				jsonResponse(w, resp, http.StatusBadRequest)
				return
			}
			resp := map[string]interface{}{
				"message": "internal error",
			}
			jsonResponse(w, resp, http.StatusInternalServerError)
			return
		}

		// Calculer le trust score initial (seulement pour les devices actifs)
		var trustScore int
		if device.Status == model.StatusActive {
			trustResp, err := h.riskSvc.ComputeTrustScore(r.Context(), device.DeviceID)
			if err != nil {
				h.logger.Warn("failed to compute initial trust score",
					zap.String("device_id", device.DeviceID),
					zap.Error(err))
			} else {
				trustScore = trustResp.TrustScore
			}
		}

		resp := map[string]interface{}{
			"device_status": device.Status,
			"message":       "device created",
			"device_id":     device.DeviceID,
			"trust_score":   trustScore,
		}
		if device.Status == model.StatusPendingApproval {
			resp["message"] = "device pending approval from an existing trusted device"
		}
		jsonResponse(w, resp, http.StatusCreated)
		return
	}

	device, err := h.svc.Get(r.Context(), req.DeviceID)
	if err != nil {
		if errors.Is(err, repository.ErrNotFound) {
			resp := map[string]interface{}{
				"message":   "device not found",
				"device_id": req.DeviceID,
			}
			jsonResponse(w, resp, http.StatusNotFound)
			return
		}
		resp := map[string]interface{}{
			"message":   "internal error",
			"device_id": req.DeviceID,
		}
		jsonResponse(w, resp, http.StatusInternalServerError)
		return
	}

	if device.Status == model.StatusActive {
		_ = h.svc.TouchLastSeen(r.Context(), req.DeviceID)
		resp := map[string]interface{}{
			"device_status": device.Status,
			"message":       "device active, timestamp updated",
			"device_id":     req.DeviceID,
		}
		jsonResponse(w, resp, http.StatusOK)
		return
	}

	resp := map[string]interface{}{
		"device_status": device.Status,
		"device_id":     req.DeviceID,
	}
	switch device.Status {
	case model.StatusRevoked:
		resp["message"] = "device revoked"
		jsonResponse(w, resp, http.StatusConflict)
	case model.StatusSuspended:
		resp["message"] = "device suspended"
		jsonResponse(w, resp, http.StatusConflict)
	case model.StatusPendingApproval:
		resp["message"] = "device pending approval"
		jsonResponse(w, resp, http.StatusAccepted)
	default:
		resp["message"] = "device status not supported"
		jsonResponse(w, resp, http.StatusConflict)
	}
}

// GET /devices/{device_id}
func (h *DeviceHandler) Get(w http.ResponseWriter, r *http.Request) {
	deviceID := chi.URLParam(r, "device_id")

	device, err := h.svc.Get(r.Context(), deviceID)
	if err != nil {
		if errors.Is(err, repository.ErrNotFound) {
			jsonError(w, "device not found", http.StatusNotFound)
			return
		}
		jsonError(w, "internal error", http.StatusInternalServerError)
		return
	}

	jsonResponse(w, device, http.StatusOK)
}

// GET /devices/{device_id}/status
func (h *DeviceHandler) Status(w http.ResponseWriter, r *http.Request) {
	deviceID := chi.URLParam(r, "device_id")

	sr, err := h.svc.Status(r.Context(), deviceID)
	if err != nil {
		if errors.Is(err, repository.ErrNotFound) {
			jsonError(w, "device not found", http.StatusNotFound)
			return
		}
		jsonError(w, "internal error", http.StatusInternalServerError)
		return
	}

	jsonResponse(w, sr, http.StatusOK)
}

// GET /users/{user_id}/devices
func (h *DeviceHandler) ListByUser(w http.ResponseWriter, r *http.Request) {
	userID := chi.URLParam(r, "user_id")

	devices, err := h.svc.ListByUser(r.Context(), userID)
	if err != nil {
		jsonError(w, "internal error", http.StatusInternalServerError)
		return
	}

	jsonResponse(w, devices, http.StatusOK)
}

// GET /me/devices
func (h *DeviceHandler) ListMine(w http.ResponseWriter, r *http.Request) {
	userID, ok := r.Context().Value(ctxkeys.UserID).(string)
	if !ok || userID == "" {
		jsonError(w, "unauthorized", http.StatusUnauthorized)
		return
	}

	devices, err := h.svc.ListMine(r.Context(), userID)
	if err != nil {
		jsonError(w, "internal error", http.StatusInternalServerError)
		return
	}

	jsonResponse(w, devices, http.StatusOK)
}

// POST /devices/{device_id}/revoke
func (h *DeviceHandler) Revoke(w http.ResponseWriter, r *http.Request) {
	deviceID := chi.URLParam(r, "device_id")
	revokedBy, _ := r.Context().Value(ctxkeys.UserID).(string)

	if err := h.svc.Revoke(r.Context(), deviceID, revokedBy); err != nil {
		if errors.Is(err, repository.ErrNotFound) {
			jsonError(w, "device not found", http.StatusNotFound)
			return
		}
		jsonError(w, "internal error", http.StatusInternalServerError)
		return
	}

	jsonResponse(w, map[string]string{"status": "revoked"}, http.StatusOK)
}

// DELETE /devices/{device_id}
func (h *DeviceHandler) Delete(w http.ResponseWriter, r *http.Request) {
	deviceID := chi.URLParam(r, "device_id")
	userID, ok := r.Context().Value(ctxkeys.UserID).(string)
	if !ok || userID == "" {
		jsonError(w, "unauthorized", http.StatusUnauthorized)
		return
	}

	if err := h.svc.Delete(r.Context(), deviceID, userID); err != nil {
		if errors.Is(err, repository.ErrNotFound) {
			jsonError(w, "device not found", http.StatusNotFound)
			return
		}
		jsonError(w, "internal error", http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

// ─── Architecture A+B : Approve / Reject / Pending / SSE ──────────────────

// POST /devices/{device_id}/approve
func (h *DeviceHandler) Approve(w http.ResponseWriter, r *http.Request) {
	deviceID := chi.URLParam(r, "device_id")
	userID, ok := r.Context().Value(ctxkeys.UserID).(string)
	if !ok || userID == "" {
		jsonError(w, "unauthorized", http.StatusUnauthorized)
		return
	}

	// Le device approbateur est celui du JWT ou passé dans le body
	approverDeviceID, _ := r.Context().Value(ctxkeys.DeviceID).(string)
	if approverDeviceID == "" {
		// Fallback : lire depuis le body
		var body struct {
			ApproverDeviceID string `json:"approver_device_id"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err == nil && body.ApproverDeviceID != "" {
			approverDeviceID = body.ApproverDeviceID
		}
	}
	if approverDeviceID == "" {
		jsonError(w, "approver_device_id required (in JWT or body)", http.StatusBadRequest)
		return
	}

	if err := h.svc.ApproveDevice(r.Context(), deviceID, approverDeviceID, userID); err != nil {
		if errors.Is(err, repository.ErrNotFound) {
			jsonError(w, "device not found or not pending", http.StatusNotFound)
			return
		}
		jsonError(w, err.Error(), http.StatusBadRequest)
		return
	}

	// Calculer le trust score initial du device nouvellement approuvé
	trustScore := 0
	if trustResp, err := h.riskSvc.ComputeTrustScore(r.Context(), deviceID); err == nil {
		trustScore = trustResp.TrustScore
	}

	jsonResponse(w, map[string]interface{}{
		"status":      "approved",
		"device_id":   deviceID,
		"approved_by": approverDeviceID,
		"trust_score": trustScore,
	}, http.StatusOK)
}

// POST /devices/{device_id}/reject
func (h *DeviceHandler) Reject(w http.ResponseWriter, r *http.Request) {
	deviceID := chi.URLParam(r, "device_id")
	userID, ok := r.Context().Value(ctxkeys.UserID).(string)
	if !ok || userID == "" {
		jsonError(w, "unauthorized", http.StatusUnauthorized)
		return
	}

	if err := h.svc.RejectDevice(r.Context(), deviceID, userID); err != nil {
		if errors.Is(err, repository.ErrNotFound) {
			jsonError(w, "device not found or not pending", http.StatusNotFound)
			return
		}
		jsonError(w, err.Error(), http.StatusBadRequest)
		return
	}

	jsonResponse(w, map[string]interface{}{
		"status":    "rejected",
		"device_id": deviceID,
	}, http.StatusOK)
}

// POST /me/devices/{device_id}/verify-email
// Validates the one-time email code to approve a pending device.
func (h *DeviceHandler) VerifyEmail(w http.ResponseWriter, r *http.Request) {
	deviceID := chi.URLParam(r, "device_id")
	userID, ok := r.Context().Value(ctxkeys.UserID).(string)
	if !ok || userID == "" {
		jsonError(w, "unauthorized", http.StatusUnauthorized)
		return
	}

	var body model.EmailChallengeRequest
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil || body.Code == "" {
		jsonError(w, "code is required", http.StatusBadRequest)
		return
	}

	if err := h.svc.ValidateEmailChallenge(r.Context(), deviceID, userID, body.Code); err != nil {
		if errors.Is(err, repository.ErrNotFound) {
			jsonError(w, "device not found or not pending", http.StatusNotFound)
			return
		}
		h.logger.Warn("email challenge validation failed",
			zap.String("device_id", deviceID),
			zap.Error(err))
		jsonError(w, err.Error(), http.StatusBadRequest)
		return
	}

	trustScore := 0
	if trustResp, err := h.riskSvc.ComputeTrustScore(r.Context(), deviceID); err == nil {
		trustScore = trustResp.TrustScore
	}

	jsonResponse(w, map[string]interface{}{
		"status":      "approved",
		"device_id":   deviceID,
		"approved_by": "self:email",
		"trust_score": trustScore,
	}, http.StatusOK)
}

// GET /me/devices/pending
func (h *DeviceHandler) ListPending(w http.ResponseWriter, r *http.Request) {
	userID, ok := r.Context().Value(ctxkeys.UserID).(string)
	if !ok || userID == "" {
		jsonError(w, "unauthorized", http.StatusUnauthorized)
		return
	}

	devices, err := h.svc.ListPending(r.Context(), userID)
	if err != nil {
		jsonError(w, "internal error", http.StatusInternalServerError)
		return
	}

	jsonResponse(w, devices, http.StatusOK)
}

// GET /me/events — SSE (Server-Sent Events) pour les notifications temps réel
// Les devices de confiance reçoivent ici les demandes d'approbation
func (h *DeviceHandler) Events(w http.ResponseWriter, r *http.Request) {
	userID, ok := r.Context().Value(ctxkeys.UserID).(string)
	if !ok || userID == "" {
		jsonError(w, "unauthorized", http.StatusUnauthorized)
		return
	}

	flusher, ok := w.(http.Flusher)
	if !ok {
		jsonError(w, "streaming not supported", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	w.Header().Set("Access-Control-Allow-Origin", "*")

	// Souscrire au canal Redis Pub/Sub pour cet utilisateur
	pubsub := h.svc.SubscribeApproval(r.Context(), userID)
	defer pubsub.Close()

	ch := pubsub.Channel()

	// Envoyer un heartbeat initial
	fmt.Fprintf(w, "event: connected\ndata: {\"message\":\"SSE connected\"}\n\n")
	flusher.Flush()

	h.logger.Info("SSE client connected",
		zap.String("user_id", userID))

	for {
		select {
		case <-r.Context().Done():
			h.logger.Info("SSE client disconnected",
				zap.String("user_id", userID))
			return
		case msg, ok := <-ch:
			if !ok {
				return
			}
			fmt.Fprintf(w, "event: approval\ndata: %s\n\n", msg.Payload)
			flusher.Flush()
		}
	}
}

// helpers
func jsonResponse(w http.ResponseWriter, payload interface{}, status int) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(payload)
}

func jsonError(w http.ResponseWriter, msg string, status int) {
	jsonResponse(w, map[string]string{"error": msg}, status)
}
