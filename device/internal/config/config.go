package config

import (
	"os"
	"strconv"
	"strings"
)

type AttestationMode string

const (
	// AttestationSoftwareOnly : ECDSA logiciel uniquement, Secure Enclave/TPM refusé
	// Cas d'usage : environnements de test, clients légers sans TPM
	AttestationSoftwareOnly AttestationMode = "software_only"

	// AttestationPreferHardware : software accepté, hardware préféré (optionnel)
	// Cas d'usage : prod standard — on accepte tout mais on logue le niveau
	AttestationPreferHardware AttestationMode = "prefer_hardware"

	// AttestationRequireHardware : Secure Enclave/TPM obligatoire
	// Cas d'usage : haute sécurité — devices sans TPM refusés
	AttestationRequireHardware AttestationMode = "require_hardware"
)

type Config struct {
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
	AttestationMode     AttestationMode
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
	SMTPHost               string
	SMTPPort               string
	SMTPFrom               string
	ApprovalTimeoutMinutes int // Délai d'expiration des devices pending_approval
}

func Load() *Config {
	keycloakURL := getEnv("KEYCLOAK_URL", "http://localhost:8081")
	keycloakRealm := getEnv("KEYCLOAK_REALM", "myapp")
	defaultJWKS := strings.TrimRight(keycloakURL, "/") + "/realms/" + keycloakRealm + "/protocol/openid-connect/certs"

	return &Config{
		Env:                 getEnv("ENV", "development"),
		Port:                getEnv("PORT", "8080"),
		DatabaseURL:         getEnv("DATABASE_URL", "postgres://device:device@localhost:5432/devicedb?sslmode=disable"),
		RedisURL:            getEnv("REDIS_URL", "redis://localhost:6379"),
		KeycloakURL:         keycloakURL,
		KeycloakRealm:       keycloakRealm,
		KeycloakClientID:    getEnv("KEYCLOAK_CLIENT_ID", "device-cli"),
		KeycloakRedirectURI: getEnv("KEYCLOAK_REDIRECT_URI", "http://localhost:8082/"),
		KeycloakPublicURI:   getEnv("KEYCLOAK_PUBLIC_URI", "http://localhost:8081/"),
		JWKSEndpoint:        getEnv("JWKS_ENDPOINT", defaultJWKS),
		AttestationMode:     AttestationMode(getEnv("ATTESTATION_MODE", string(AttestationPreferHardware))),
		// Re-attestation
		ReattestIntervalHours:  parseInt(getEnv("REATTEST_INTERVAL_HOURS", "24"), 24),
		RequireDeviceSignature: parseBool(getEnv("REQUIRE_DEVICE_SIGNATURE", "false"), false),
		// Risk thresholds
		RiskThresholdFull:    parseInt(getEnv("RISK_THRESHOLD_FULL", "70"), 70),
		RiskThresholdLimited: parseInt(getEnv("RISK_THRESHOLD_LIMITED", "40"), 40),
		// CORS
		CORSAllowedOrigins:   parseCSV(getEnv("CORS_ALLOWED_ORIGINS", "*")),
		CORSAllowedMethods:   parseCSV(getEnv("CORS_ALLOWED_METHODS", "GET,POST,PUT,PATCH,DELETE,OPTIONS")),
		CORSAllowedHeaders:   parseCSV(getEnv("CORS_ALLOWED_HEADERS", "Accept,Authorization,Content-Type,Origin,X-Device-ID,X-Device-Nonce,X-Device-Timestamp,X-Device-Signature")),
		CORSExposedHeaders:   parseCSV(getEnv("CORS_EXPOSED_HEADERS", "")),
		CORSAllowCredentials: parseBool(getEnv("CORS_ALLOW_CREDENTIALS", "true"), true),
		CORSMaxAgeSeconds:    parseInt(getEnv("CORS_MAX_AGE_SECONDS", "300"), 300),
		// Architecture B : Email challenge
		SMTPHost:               getEnv("SMTP_HOST", "localhost"),
		SMTPPort:               getEnv("SMTP_PORT", "1025"),
		SMTPFrom:               getEnv("SMTP_FROM", "device-service@localhost"),
		ApprovalTimeoutMinutes: parseInt(getEnv("APPROVAL_TIMEOUT_MINUTES", "30"), 30),
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
