package middleware

import (
	"context"
	"net/http"

	"github.com/ia-generative/device-service/internal/ctxkeys"
	"go.uber.org/zap"
)

func HeaderExtract(logger *zap.Logger) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Inject in context
			ctx := r.Context()
			ctx = context.WithValue(ctx, ctxkeys.ForwardedFor, r.Header.Values(string(ctxkeys.HeaderXForwardedFor)))

			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}
