package main

import (
	"context"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"go.uber.org/zap"

	"github.com/ia-generative/device-service/internal/cache"
	"github.com/ia-generative/device-service/internal/config"
	"github.com/ia-generative/device-service/internal/db"
	"github.com/ia-generative/device-service/internal/handler"
	authmw "github.com/ia-generative/device-service/internal/middleware"
	"github.com/ia-generative/device-service/internal/repository"
	"github.com/ia-generative/device-service/internal/service"
)

func main() {
	cfg := config.Load()

	// Logger
	logger, err := buildLogger(cfg.Env)
	if err != nil {
		panic(err)
	}
	defer logger.Sync()

	// Postgres
	pg, err := db.NewPostgres(cfg.DatabaseURL)
	if err != nil {
		logger.Fatal("failed to connect to postgres", zap.Error(err))
	}
	defer pg.Close()

	// Redis
	rdb, err := cache.NewRedis(cfg.RedisURL)
	if err != nil {
		logger.Fatal("failed to connect to redis", zap.Error(err))
	}
	defer rdb.Close()

	// Layers
	repo := repository.NewDeviceRepository(pg)
	emailSvc := service.NewEmailService(cfg.SMTPHost, cfg.SMTPPort, cfg.SMTPFrom)
	svc := service.NewDeviceServiceWithConfig(repo, rdb, emailSvc, logger, cfg)
	attestSvc := service.NewAttestationService(svc, cfg.AttestationMode, logger)
	riskSvc := service.NewRiskService(svc, cfg.ReattestIntervalHours, logger)

	probeHandler := handler.NewProbeHandler(pg, rdb, logger)
	authHandler := handler.NewAuthHandler(cfg, svc)
	deviceHandler := handler.NewDeviceHandler(svc, attestSvc, riskSvc, cfg, logger)
	attestHandler := handler.NewAttestationHandler(attestSvc, riskSvc, logger)

	// Router
	r := chi.NewRouter()
	r.Use(authmw.CORS(authmw.CORSOptions{
		AllowedOrigins:   cfg.CORSAllowedOrigins,
		AllowedMethods:   cfg.CORSAllowedMethods,
		AllowedHeaders:   cfg.CORSAllowedHeaders,
		ExposedHeaders:   cfg.CORSExposedHeaders,
		AllowCredentials: cfg.CORSAllowCredentials,
		MaxAgeSeconds:    cfg.CORSMaxAgeSeconds,
	}))
	r.Use(middleware.RequestID)
	r.Use(middleware.RealIP)
	r.Use(middleware.Recoverer)

	// Kubernetes probes (pas d'auth)
	r.Get("/healthz", probeHandler.Liveness)
	r.Get("/readyz", probeHandler.Readiness)
	r.Get("/discover", authHandler.Discover)
	r.Get("/devices/{device_id}/status", deviceHandler.Status)

	// Device endpoints (JWT requis)
	r.Group(func(r chi.Router) {
		r.Use(authmw.JWTAuth(cfg.JWKSEndpoint, logger))

		r.Post("/devices/register", deviceHandler.Register)
		r.Post("/devices/register/challenge", attestHandler.RegisterChallenge)
		r.Get("/devices/{device_id}", deviceHandler.Get)
		r.Get("/me/devices", deviceHandler.ListMine)
		r.Get("/me/devices/pending", deviceHandler.ListPending)
		r.Get("/me/events", deviceHandler.Events)
		r.Get("/users/{user_id}/devices", deviceHandler.ListByUser)
		r.Post("/devices/{device_id}/revoke", deviceHandler.Revoke)
		r.Post("/devices/{device_id}/approve", deviceHandler.Approve)
		r.Post("/devices/{device_id}/reject", deviceHandler.Reject)
		r.Post("/me/devices/{device_id}/verify-email", deviceHandler.VerifyEmail)

		// Attestation endpoints
		r.Post("/devices/{device_id}/challenge", attestHandler.Challenge)
		r.Post("/devices/{device_id}/verify", attestHandler.Verify)
		r.Post("/devices/{device_id}/reattest", attestHandler.Reattest)
		r.Post("/devices/{device_id}/upgrade-key", attestHandler.UpgradeKey)
		r.Get("/devices/{device_id}/trust", attestHandler.TrustScore)
	})

	// Protected endpoints requiring device signature (device-bound sessions)
	r.Group(func(r chi.Router) {
		r.Use(authmw.JWTAuth(cfg.JWKSEndpoint, logger))
		r.Use(authmw.DeviceSignature(attestSvc, cfg.RequireDeviceSignature, logger))
		// Ajouter ici les endpoints sensibles nécessitant signature device
		// Par exemple : r.Post("/sensitive/action", sensitiveHandler.Action)
	})

	srv := &http.Server{
		Addr:         ":" + cfg.Port,
		Handler:      r,
		ReadTimeout:  10 * time.Second,
		WriteTimeout: 10 * time.Second,
		IdleTimeout:  30 * time.Second,
	}

	// Graceful shutdown
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)

	go func() {
		logger.Info("device service starting", zap.String("port", cfg.Port))
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			logger.Fatal("server error", zap.Error(err))
		}
	}()

	<-quit
	logger.Info("shutting down...")

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	if err := srv.Shutdown(ctx); err != nil {
		logger.Fatal("forced shutdown", zap.Error(err))
	}

	logger.Info("server stopped")
}

func buildLogger(env string) (*zap.Logger, error) {
	if env == "production" {
		return zap.NewProduction()
	}
	return zap.NewDevelopment()
}
