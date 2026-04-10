package middleware

import (
	"context"
	"net/http"

	"github.com/ia-generative/aigis/internal/ctxkeys"
	"go.uber.org/zap"
)

func TokenAuthExtract(logger *zap.Logger) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			token := r.Header.Get(string(ctxkeys.HeaderXApiKey))

			ctx := r.Context()

			if token != "" {
				// Inject in context
				ctx = context.WithValue(ctx, ctxkeys.Token, token)
			}

			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}
