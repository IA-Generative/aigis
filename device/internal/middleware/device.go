package middleware

import (
	"context"
	"net/http"

	"github.com/ia-generative/device-service/internal/ctxkeys"
	"go.uber.org/zap"
)

func DeviceAuthExtract(logger *zap.Logger) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {

			// Inject in context
			ctx := r.Context()
			ctx = context.WithValue(ctx, ctxkeys.DeviceID, r.Header.Get(string(ctxkeys.HeaderXDeviceID)))
			ctx = context.WithValue(ctx, ctxkeys.DeviceNonce, r.Header.Get(string(ctxkeys.HeaderXDeviceNonce)))
			ctx = context.WithValue(ctx, ctxkeys.DeviceTimestamp, r.Header.Get(string(ctxkeys.HeaderXDeviceTimestamp)))
			ctx = context.WithValue(ctx, ctxkeys.DeviceSignature, r.Header.Get(string(ctxkeys.HeaderXDeviceSignature)))

			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}
