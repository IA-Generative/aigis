package middleware

import (
	"context"
	"net/http"
	"strings"

	"github.com/MicahParks/keyfunc/v2"
	"github.com/golang-jwt/jwt/v5"
	"github.com/ia-generative/device-service/internal/ctxkeys"
	"go.uber.org/zap"
)

func JWTAuth(jwksURL string, logger *zap.Logger, mandatory bool) func(http.Handler) http.Handler {
	// Chargement des clés JWKS (avec refresh automatique sur kid inconnu)
	jwks, err := keyfunc.Get(jwksURL, keyfunc.Options{
		RefreshErrorHandler: func(err error) {
			logger.Error("jwks refresh error", zap.Error(err))
		},
		RefreshUnknownKID: true, // ← key rollover automatique
	})
	if err != nil {
		logger.Fatal("failed to fetch JWKS", zap.Error(err))
	}

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			authHeader := r.Header.Get("Authorization")
			if !strings.HasPrefix(authHeader, "Bearer ") {
				if mandatory {
					http.Error(w, `{"error":"missing token"}`, http.StatusUnauthorized)
					return
				}
				next.ServeHTTP(w, r)
				return
			}

			tokenStr := strings.TrimPrefix(authHeader, "Bearer ")

			token, err := jwt.Parse(tokenStr, jwks.Keyfunc)
			if err != nil || !token.Valid {
				logger.Info("invalid token", zap.String("error", err.Error()))
				http.Error(w, `{"error":"invalid token"}`, http.StatusUnauthorized)
				return
			}

			claims, ok := token.Claims.(jwt.MapClaims)
			if !ok {
				http.Error(w, `{"error":"invalid claims"}`, http.StatusUnauthorized)
				return
			}

			// Injecter sub, email et device_id dans le contexte
			ctx := r.Context()
			logger.Debug("authenticated request", zap.Any("claims", claims))
			if sub, ok := claims["sub"].(string); ok {
				ctx = context.WithValue(ctx, ctxkeys.UserID, sub)
			}
			if did, ok := claims["device_id"].(string); ok {
				ctx = context.WithValue(ctx, ctxkeys.DeviceID, did)
			}
			if email, ok := claims["email"].(string); ok {
				ctx = context.WithValue(ctx, ctxkeys.Email, email)
			}
			if acr, ok := claims["acr"].(string); ok {
				ctx = context.WithValue(ctx, ctxkeys.Acr, acr)
			}

			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}
