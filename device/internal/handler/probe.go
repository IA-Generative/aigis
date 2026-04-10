package handler

import (
	"context"
	"encoding/json"
	"net/http"
	"time"

	"github.com/jmoiron/sqlx"
	"go.uber.org/zap"

	"github.com/ia-generative/aigis/internal/cache"
)

type ProbeHandler struct {
	db     *sqlx.DB
	cache  *cache.Redis
	logger *zap.Logger
}

func NewProbeHandler(db *sqlx.DB, cache *cache.Redis, logger *zap.Logger) *ProbeHandler {
	return &ProbeHandler{db: db, cache: cache, logger: logger}
}

// GET /healthz — Liveness : le process tourne
func (h *ProbeHandler) Liveness(w http.ResponseWriter, r *http.Request) {
	jsonResponse(w, map[string]string{"status": "ok"}, http.StatusOK)
}

// GET /readyz — Readiness : les dépendances sont disponibles
func (h *ProbeHandler) Readiness(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 2*time.Second)
	defer cancel()

	type check struct {
		Status string `json:"status"`
		Error  string `json:"error,omitempty"`
	}

	result := map[string]check{}
	ready := true

	// Postgres
	if err := h.db.PingContext(ctx); err != nil {
		result["postgres"] = check{Status: "unhealthy", Error: err.Error()}
		h.logger.Warn("readiness: postgres unhealthy", zap.Error(err))
		ready = false
	} else {
		result["postgres"] = check{Status: "healthy"}
	}

	// Redis
	if err := h.cache.Ping(ctx); err != nil {
		result["redis"] = check{Status: "unhealthy", Error: err.Error()}
		h.logger.Warn("readiness: redis unhealthy", zap.Error(err))
		ready = false
	} else {
		result["redis"] = check{Status: "healthy"}
	}

	status := http.StatusOK
	if !ready {
		status = http.StatusServiceUnavailable
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(result)
}
