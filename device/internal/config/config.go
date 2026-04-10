package config

import (
	"os"
	"strconv"
	"strings"

	"github.com/ia-generative/aigis/internal/ctxkeys"
)

// ApprovalMethod définit un mécanisme d'approbation pour l'enrollment.
type ApprovalMethod string

const (
	ApprovalAcr         ApprovalMethod = "acr"          // MFA via Keycloak (acr_values)
	ApprovalEmail       ApprovalMethod = "email"        // Code OTP par email
	ApprovalCrossDevice ApprovalMethod = "cross_device" // Approbation par un device de confiance
)

type Config struct {
	UiEnabled           bool
	Env                 string
	Port                string
	DatabaseURL         string
	RedisURL            string
	KeycloakURL         string
	KeycloakRealm       string
	KeycloakClientID    string
	KeycloakRedirectURI string
	KeycloakPublicURI   string
	JWKSEndpoint        string
	// Re-attestation
	ReattestIntervalHours  int  // Interval between re-attestations (hours)
	RequireDeviceSignature bool // Require X-Device-Signature on protected endpoints
	// Risk thresholds
	RiskThresholdFull    int // Score >= this: full access
	RiskThresholdLimited int // Score >= this: limited access (MFA suggested)
	// CORS
	CORSAllowedOrigins   []string
	CORSAllowedMethods   []string
	CORSAllowedHeaders   []string
	CORSExposedHeaders   []string
	CORSAllowCredentials bool
	CORSMaxAgeSeconds    int
	// Architecture B : Email challenge
	SMTPHost       string
	SMTPPort       string
	SMTPFrom       string
	SMTPAuthType   string // none | plain | login | crammd5
	SMTPUsername   string
	SMTPPassword   string
	SMTPEncryption string // none | starttls | tls
	// ─── Enrollment Policy ───────────────────────────────────────────────────
	AutoApproveFirstDevice bool             // true → 1er device auto-actif (Architecture A)
	ApprovalMethods        []ApprovalMethod // acr, email, cross_device — n'importe quelle combinaison
	CrossDeviceMinTrust    int              // Trust score min pour qu'un device puisse en approuver un autre
	EmailChallengeTTL      int              // Durée de validité du code email (minutes)
	AcrValues              string           // acr_values Keycloak exigé pour l'approbation ACR (ex: "urn:keycloak:acr:silver")
	// ─── Trust scoring par méthode d'approbation (0-30) ──────────────────
	TrustPointsFirstDevice int // Points pour le premier device auto-appouvé
	TrustPointsEmail       int // Points pour approbation par code email
	TrustPointsAcr         int // Points pour approbation via MFA Keycloak
	TrustPointsCrossDevice int // Points pour approbation cross-device
}

func Load() *Config {
	keycloakRealm := getEnv("KEYCLOAK_REALM", "myapp")

	defaultAllowHeaders := []string{
		"Accept",
		string(ctxkeys.HeaderAuthorization),
		"Content-Type",
		"Origin",
		string(ctxkeys.HeaderXDeviceID),
		string(ctxkeys.HeaderXDeviceNonce),
		string(ctxkeys.HeaderXDeviceTimestamp),
		string(ctxkeys.HeaderXDeviceSignature),
		string(ctxkeys.HeaderXUserID),
		string(ctxkeys.HeaderXApiKey),
		string(ctxkeys.HeaderXForwardedFor), // Source IP du client (dernière IP dans la chaîne)
		"X-Forwarded-Proto",                 // HTTP ou HTTPS
		"X-Forwarded-Method",                // Méthode HTTP originale (utile si un proxy modifie la méthode)
		"X-Forwarded-Host",                  // Host original de la requête
		"X-Forwarded-Uri",                   // URI original de la requête
	}
	return &Config{
		UiEnabled:           parseBool(getEnv("UI_ENABLED", "false"), false),
		Env:                 getEnv("ENV", "development"),
		Port:                getEnv("PORT", "8080"),
		DatabaseURL:         getEnv("DATABASE_URL", "postgres://device:device@localhost:5432/devicedb?sslmode=disable"),
		RedisURL:            getEnv("REDIS_URL", "redis://localhost:6379"),
		KeycloakRealm:       keycloakRealm,
		KeycloakClientID:    getEnv("KEYCLOAK_CLIENT_ID", "device-cli"),
		KeycloakRedirectURI: getEnv("KEYCLOAK_REDIRECT_URI", "http://localhost:8082/"),
		KeycloakPublicURI:   getEnv("KEYCLOAK_PUBLIC_URI", "http://localhost:8081/"),
		JWKSEndpoint:        getEnv("JWKS_ENDPOINT", "http://keycloak/realms/myapp/protocol/openid-connect/certs"),
		// Re-attestation
		ReattestIntervalHours:  parseInt(getEnv("REATTEST_INTERVAL_HOURS", "24"), 24),
		RequireDeviceSignature: parseBool(getEnv("REQUIRE_DEVICE_SIGNATURE", "false"), false),
		// Risk thresholds
		RiskThresholdFull:    parseInt(getEnv("RISK_THRESHOLD_FULL", "70"), 70),
		RiskThresholdLimited: parseInt(getEnv("RISK_THRESHOLD_LIMITED", "40"), 40),
		// CORS
		CORSAllowedOrigins:   parseCSV(getEnv("CORS_ALLOWED_ORIGINS", "*")),
		CORSAllowedMethods:   parseCSV(getEnv("CORS_ALLOWED_METHODS", "GET,POST,PUT,PATCH,DELETE,OPTIONS")),
		CORSAllowedHeaders:   parseCSV(getEnv("CORS_ALLOWED_HEADERS", strings.Join(defaultAllowHeaders, ","))),
		CORSExposedHeaders:   parseCSV(getEnv("CORS_EXPOSED_HEADERS", "")),
		CORSAllowCredentials: parseBool(getEnv("CORS_ALLOW_CREDENTIALS", "true"), true),
		CORSMaxAgeSeconds:    parseInt(getEnv("CORS_MAX_AGE_SECONDS", "300"), 300),
		// Architecture B : Email challenge
		SMTPHost:       getEnv("SMTP_HOST", "localhost"),
		SMTPPort:       getEnv("SMTP_PORT", "1025"),
		SMTPFrom:       getEnv("SMTP_FROM", "device-service@localhost"),
		SMTPAuthType:   getEnv("SMTP_AUTH_TYPE", "none"),
		SMTPUsername:   getEnv("SMTP_USERNAME", ""),
		SMTPPassword:   getEnv("SMTP_PASSWORD", ""),
		SMTPEncryption: getEnv("SMTP_ENCRYPTION", "none"),
		// Enrollment Policy
		AutoApproveFirstDevice: parseBool(getEnv("AUTO_APPROVE_FIRST_DEVICE", "true"), true),
		ApprovalMethods:        parseApprovalMethods(getEnv("APPROVAL_METHODS", "email,cross_device")),
		CrossDeviceMinTrust:    parseInt(getEnv("CROSS_DEVICE_MIN_TRUST", "50"), 50),
		EmailChallengeTTL:      parseInt(getEnv("EMAIL_CHALLENGE_TTL", "30"), 30),
		AcrValues:              getEnv("ACR_VALUES", ""),
		// Trust scoring
		TrustPointsFirstDevice: parseInt(getEnv("TRUST_POINTS_FIRST_DEVICE", "30"), 30),
		TrustPointsEmail:       parseInt(getEnv("TRUST_POINTS_EMAIL", "20"), 20),
		TrustPointsAcr:         parseInt(getEnv("TRUST_POINTS_ACR", "25"), 25),
		TrustPointsCrossDevice: parseInt(getEnv("TRUST_POINTS_CROSS_DEVICE", "30"), 30),
	}
}

func getEnv(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

func parseCSV(value string) []string {
	if strings.TrimSpace(value) == "" {
		return []string{}
	}

	raw := strings.Split(value, ",")
	result := make([]string, 0, len(raw))
	for _, item := range raw {
		item = strings.TrimSpace(item)
		if item == "" {
			continue
		}
		result = append(result, item)
	}
	return result
}

func parseBool(value string, fallback bool) bool {
	b, err := strconv.ParseBool(strings.TrimSpace(value))
	if err != nil {
		return fallback
	}
	return b
}

func parseInt(value string, fallback int) int {
	i, err := strconv.Atoi(strings.TrimSpace(value))
	if err != nil {
		return fallback
	}
	return i
}

func parseApprovalMethods(value string) []ApprovalMethod {
	raw := parseCSV(value)
	methods := make([]ApprovalMethod, 0, len(raw))
	for _, m := range raw {
		switch ApprovalMethod(m) {
		case ApprovalAcr, ApprovalEmail, ApprovalCrossDevice:
			methods = append(methods, ApprovalMethod(m))
		}
	}
	return methods
}

// HasApprovalMethod vérifie si une méthode d'approbation est activée.
func (c *Config) HasApprovalMethod(method ApprovalMethod) bool {
	for _, m := range c.ApprovalMethods {
		if m == method {
			return true
		}
	}
	return false
}
