package middleware

import (
	"net/http"

	"go.uber.org/zap"

	"github.com/ia-generative/device-service/internal/service"
)

// DeviceSignature est un middleware qui vérifie les headers de signature device-bound
// sur les requêtes protégées. Si la vérification échoue, la requête est rejetée.
//
// Headers attendus :
//
//	X-Device-ID:        identifiant du device
//	X-Device-Nonce:     nonce unique pour anti-replay
//	X-Device-Timestamp: RFC3339 timestamp
//	X-Device-Signature: base64(sign(nonce|timestamp))
//
// Si require=false, les headers sont vérifiés s'ils sont présents mais pas obligatoires.
func DeviceSignature(attestSvc *service.AttestationService, require bool, logger *zap.Logger) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			deviceID := r.Header.Get("X-Device-ID")
			nonce := r.Header.Get("X-Device-Nonce")
			timestamp := r.Header.Get("X-Device-Timestamp")
			signature := r.Header.Get("X-Device-Signature")

			// Si aucun header de signature n'est présent
			hasHeaders := deviceID != "" || nonce != "" || timestamp != "" || signature != ""

			if !hasHeaders {
				if require {
					logger.Warn("device signature headers missing (required mode)")
					http.Error(w, `{"error":"device signature required"}`, http.StatusUnauthorized)
					return
				}
				// Mode optionnel : on laisse passer sans vérification
				next.ServeHTTP(w, r)
				return
			}

			// Si certains headers sont présents mais pas tous : erreur
			if deviceID == "" || nonce == "" || timestamp == "" || signature == "" {
				logger.Warn("incomplete device signature headers",
					zap.String("device_id", deviceID),
					zap.Bool("has_nonce", nonce != ""),
					zap.Bool("has_ts", timestamp != ""),
					zap.Bool("has_sig", signature != ""))
				http.Error(w, `{"error":"incomplete device signature headers"}`, http.StatusBadRequest)
				return
			}

			// Vérifier la signature
			if err := attestSvc.VerifyRequestSignature(
				r.Context(),
				deviceID,
				nonce,
				timestamp,
				signature,
			); err != nil {
				logger.Warn("device signature verification failed",
					zap.String("device_id", deviceID),
					zap.Error(err))
				http.Error(w, `{"error":"invalid device signature: `+err.Error()+`"}`, http.StatusUnauthorized)
				return
			}

			logger.Debug("device signature verified",
				zap.String("device_id", deviceID))

			next.ServeHTTP(w, r)
		})
	}
}
