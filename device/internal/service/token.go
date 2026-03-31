package service

import (
	"context"
	"crypto/sha256"
	"fmt"

	"go.uber.org/zap"

	"github.com/ia-generative/device-service/internal/cache"
	"github.com/ia-generative/device-service/internal/config"
	"github.com/ia-generative/device-service/internal/model"
	"github.com/ia-generative/device-service/internal/repository"
)

type TokenService struct {
	repo     *repository.TokenRepository
	cache    *cache.Redis
	emailSvc *EmailService
	logger   *zap.Logger
	cfg      *config.Config
}

func NewTokenService(repo *repository.TokenRepository, cache *cache.Redis, logger *zap.Logger, cfg *config.Config) *TokenService {
	return &TokenService{repo: repo, cache: cache, logger: logger, cfg: cfg}
}

// NewTokenServiceWithConfig crée un TokenService avec la configuration complète (email, etc.)
func NewTokenServiceWithConfig(repo *repository.TokenRepository, cache *cache.Redis, emailSvc *EmailService, logger *zap.Logger, cfg *config.Config) *TokenService {
	return &TokenService{
		repo:     repo,
		cache:    cache,
		emailSvc: emailSvc,
		logger:   logger,
		cfg:      cfg,
	}
}

func (s *TokenService) GetByKey(ctx context.Context, key string) (*model.Token, error) {
	sum := sha256.Sum256([]byte(key))
	sumStr := fmt.Sprintf("%x", sum)
	s.logger.Info("hash generated", zap.String("key", key), zap.String("hash", sumStr))
	t, err := s.repo.GetBySha256Sum(ctx, sumStr)
	if err != nil {
		if err == repository.ErrTokenNotFound {
			return nil, repository.ErrTokenNotFound
		}
		return nil, err
	}
	s.logger.Info("token retrieved", zap.String("user_id", t.UserID), zap.String("token_id", t.ID))
	return t, nil
}
