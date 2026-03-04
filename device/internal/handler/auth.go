package handler

import (
	"net/http"
	"strings"

	"github.com/ia-generative/device-service/internal/config"
	"github.com/ia-generative/device-service/internal/service"
)

type AuthHandler struct {
	cfg *config.Config
	svc *service.DeviceService
}

func NewAuthHandler(cfg *config.Config, svc *service.DeviceService) *AuthHandler {
	return &AuthHandler{cfg: cfg, svc: svc}
}

type authRequest struct {
	UserID             string `json:"sub"`
	ClientID           string `json:"client_id"`
	RedirectURI        string `json:"redirect_uri"`
	DeviceID           string `json:"device_id"`
	Name               string `json:"name"`
	UserAgent          string `json:"user_agent"`
	Platform           string `json:"platform"`
	PublicKey          string `json:"public_key"`
	KeyAlgorithm       string `json:"key_algorithm"`
	HardwareLevel      string `json:"hardware_level"`
	ProviderName       string `json:"provider_name"`
	Challenge          string `json:"challenge,omitempty"`
	ChallengeSignature string `json:"challenge_signature,omitempty"`
}

func (h *AuthHandler) baseResponse(clientID, redirectURI, deviceID string) map[string]interface{} {
	authBaseURL := strings.TrimRight(h.cfg.KeycloakPublicURI, "/")
	tokenPath := "/realms/" + h.cfg.KeycloakRealm + "/protocol/openid-connect/token"

	return map[string]interface{}{
		"realm":         h.cfg.KeycloakRealm,
		"client_id":     clientID,
		"redirect_uri":  redirectURI,
		"auth_base_url": authBaseURL,
		"token_path":    tokenPath,
	}
}

// GET /discover
func (h *AuthHandler) Discover(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		jsonError(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	resp := h.baseResponse(h.cfg.KeycloakClientID, h.cfg.KeycloakRedirectURI, "")
	jsonResponse(w, resp, http.StatusOK)
}
