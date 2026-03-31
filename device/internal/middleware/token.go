package middleware

import (
	"context"
	"net/http"
	"strings"

	"github.com/ia-generative/device-service/internal/ctxkeys"
	"go.uber.org/zap"
)

func TokenAuthExtract(logger *zap.Logger) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Extraire les headers d'authentification du device
			// first copy headers, then lowers them for case-insensitive matching
			headers := make(map[string]string)
			for k, v := range r.Header {
				headers[strings.ToLower(k)] = v[0]
			}

			token := headers["x-api-key"]

			ctx := r.Context()

			if token != "" {
				// Inject in context
				ctx = context.WithValue(ctx, ctxkeys.Token, token)
			}

			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}
