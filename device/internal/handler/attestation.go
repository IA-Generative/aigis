package handler

import (
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"strconv"
	"strings"

	"github.com/go-chi/chi/v5"
	"go.uber.org/zap"

	"github.com/ia-generative/device-service/internal/ctxkeys"
	"github.com/ia-generative/device-service/internal/model"
	"github.com/ia-generative/device-service/internal/repository"
	"github.com/ia-generative/device-service/internal/service"
)

type AttestationHandler struct {
	attestSvc *service.AttestationService
	deviceSvc *service.DeviceService
	tokenSvc  *service.TokenService
	riskSvc   *service.RiskService
	logger    *zap.Logger
}

func NewAttestationHandler(
	attestSvc *service.AttestationService,
	deviceSvc *service.DeviceService,
	tokenSvc *service.TokenService,
	riskSvc *service.RiskService,
	logger *zap.Logger,
) *AttestationHandler {
	return &AttestationHandler{
		attestSvc: attestSvc,
		deviceSvc: deviceSvc,
		tokenSvc:  tokenSvc,
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

// POST /verify
// Vérifie une signature sur un challenge (device-bound session proof)
func (h *AttestationHandler) Verify(w http.ResponseWriter, r *http.Request) {
	var code int
	var resp model.VerifyResponse
	var errorMessage error

	if token := r.Header.Get(string(ctxkeys.HeaderXApiKey)); token != "" {
		code, errorMessage = h.VerifyToken(w, r, &resp)
	} else {
		code, errorMessage = h.VerifyDevice(w, r, &resp)
	}

	w.Header().Set("Content-Type", "application/json")
	h.logger.Info("verification attempt", zap.Any("resp", resp))
	if resp.UserID != nil {
		w.Header().Set(string(ctxkeys.HeaderXUserID), *resp.UserID)
	}
	if resp.DeviceID != nil {
		w.Header().Set(string(ctxkeys.HeaderXDeviceID), *resp.DeviceID)
	}
	if resp.ServiceID != nil {
		w.Header().Set(string(ctxkeys.HeaderXServiceID), *resp.ServiceID)
	}
	w.Header().Set(string(ctxkeys.HeaderXVerified), strconv.FormatBool(resp.Verified))
	w.Header().Set(string(ctxkeys.HeaderXDeviceStatus), resp.Status)
	if resp.DeviceSigned != nil {
		w.Header().Set(string(ctxkeys.HeaderXDeviceSigned), strconv.FormatBool(*resp.DeviceSigned))
	}
	if resp.TrustScore != nil {
		w.Header().Set(string(ctxkeys.HeaderXTrustScore), strconv.Itoa(*resp.TrustScore))
	}

	if errorMessage != nil {
		jsonError(w, errorMessage.Error(), code)
	} else {
		jsonResponse(w, resp, code)
	}
}

func (h *AttestationHandler) VerifyToken(w http.ResponseWriter, r *http.Request, response *model.VerifyResponse) (code int, errMessage error) {
	tokenHeader := r.Header.Get(string(ctxkeys.HeaderXApiKey))
	if tokenHeader == "" {
		return http.StatusUnauthorized, errors.New("missing token")
	}

	token, err := h.tokenSvc.GetByKey(tokenHeader)

	if err != nil {
		if errors.Is(err, repository.ErrTokenNotFound) {
			return http.StatusUnauthorized, errors.New("token not found")
		}
		h.logger.Error("failed to get token by key",
			zap.String("token", tokenHeader),
			zap.Error(err))
		return http.StatusInternalServerError, errors.New("internal error")
	}

	if token.Status != model.TokenActive {
		return http.StatusUnauthorized, errors.New("token is not active")
	}

	// valeur en BDD : {127.0.0.1,192.168.1.1/24}"
	// exemple de valeur retournée par la BDD en string : "{127.0.0.1,192.168.1.1/24}"
	// conversion de string en []string -> net.IPNet pour vérification
	IPWhitelist := strings.TrimLeft(*token.IPWhitelist, "{")
	IPWhitelist = strings.TrimRight(IPWhitelist, "}")
	ipList := strings.Split(IPWhitelist, ",")

	if ok, err := ipCheck(r, ipList); !ok {
		if err != nil {
			h.logger.Error("failed to check IP", zap.Error(err))
			return http.StatusInternalServerError, errors.New("internal error")
		}
		return http.StatusUnauthorized, errors.New("IP not allowed")
	}

	serviceID := token.ID
	if token.Name != nil && *token.Name != "" {
		serviceID = *token.Name
	}
	response.ServiceID = &serviceID
	response.Verified = true
	response.Message = "token valid"
	response.Status = string(model.TokenActive)

	return http.StatusOK, nil
}

func (h *AttestationHandler) VerifyDevice(w http.ResponseWriter, r *http.Request, response *model.VerifyResponse) (code int, err error) {
	userID, ok := r.Context().Value(ctxkeys.UserID).(string)
	if !ok || userID == "" {
		return http.StatusUnauthorized, errors.New("unauthorized")
	}

	var req model.VerifyChallengeRequest
	// parse JSON body if present, otherwise fallback to headers (for GET requests or clients that can't send JSON)
	if r.Method == http.MethodPost && r.Body != nil {
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			return http.StatusBadRequest, errors.New("invalid request body")
		}
	}

	if req.Nonce == "" {
		req.Nonce = r.Header.Get(string(ctxkeys.HeaderXDeviceNonce))
	}
	if req.Timestamp == "" {
		req.Timestamp = r.Header.Get(string(ctxkeys.HeaderXDeviceTimestamp))
	}
	if req.Signature == "" {
		req.Signature = r.Header.Get(string(ctxkeys.HeaderXDeviceSignature))
	}
	if req.DeviceID == "" {
		req.DeviceID = r.Header.Get(string(ctxkeys.HeaderXDeviceID))
	}

	if req.DeviceID == "" {
		return http.StatusBadRequest, errors.New("device_id is required")
	}

	vrsr, err := h.attestSvc.VerifyRequestSignature(
		r.Context(),
		req.DeviceID,
		req.Nonce,
		req.Timestamp,
		req.Signature,
		userID,
	)

	if err != nil {
		if errors.Is(err, repository.ErrNotFound) {
			return http.StatusNotFound, errors.New("device not found")
		}
	}

	code = http.StatusOK

	if vrsr.DeviceSigned && !vrsr.Verified {
		code = http.StatusUnauthorized
	} else if vrsr.Status != string(model.DeviceActive) {
		code = http.StatusForbidden
	} else {
		code = http.StatusOK
	}

	// Recalculate trust score after successful verification
	trustResp, err := h.riskSvc.ComputeTrustScore(r.Context(), req.DeviceID)
	if err != nil {
		vrsr.Message += "; failed to compute trust score: " + err.Error()
		code = http.StatusInternalServerError
		h.logger.Warn("trust score computation failed after verify",
			zap.String("device_id", req.DeviceID),
			zap.Error(err))
	}

	if vrsr.TrustScore != nil {
		w.Header().Set(string(ctxkeys.HeaderXTrustScore), strconv.Itoa(*vrsr.TrustScore))
	}

	response.DeviceID = &req.DeviceID
	response.UserID = &vrsr.UserID
	response.Message = vrsr.Message
	response.Verified = vrsr.Verified
	response.Status = vrsr.Status
	response.DeviceSigned = &vrsr.DeviceSigned
	if trustResp != nil {
		response.TrustScore = &trustResp.TrustScore
	}
	return code, nil
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

	// 1. Verify the signature (proves possession of the private key)
	if _, err := h.attestSvc.VerifyRequestSignature(
		r.Context(),
		req.DeviceID,
		req.Nonce,
		req.Timestamp,
		req.Signature,
		userID,
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
	}

	h.logger.Info("device re-attested",
		zap.String("device_id", deviceID),
		zap.String("user_id", userID))

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

func ipCheck(r *http.Request, inets []string) (bool, error) {
	ipList := filterEmpty(inets)
	if len(ipList) == 0 {
		return true, nil
	}
	ipStr := r.Header.Get(string(ctxkeys.HeaderXForwardedFor))
	if ipStr == "" {
		ipStr = r.RemoteAddr
	}

	for _, inet := range ipList {
		if strings.Contains(inet, "/") {
			_, ipNet, err := net.ParseCIDR(inet)
			if err != nil {
				return false, err
			}
			if ipNet.Contains(net.ParseIP(ipStr)) {
				return true, nil
			}
		} else {
			if inet == ipStr {
				return true, nil
			}
		}
	}
	return false, nil
}

func filterEmpty(input []string) []string {

	var output []string
	for _, str := range input {
		if str == "NULL" {
			continue
		}
		if strings.TrimSpace(str) != "" {
			output = append(output, str)
		}
	}
	return output
}
