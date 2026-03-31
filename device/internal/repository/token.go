package repository

import (
	"context"
	"database/sql"
	"errors"

	"github.com/jmoiron/sqlx"

	"github.com/ia-generative/device-service/internal/model"
)

var ErrTokenNotFound = errors.New("token not found")

type TokenRepository struct {
	db *sqlx.DB
}

func NewTokenRepository(db *sqlx.DB) *TokenRepository {
	return &TokenRepository{db: db}
}

func (r *TokenRepository) GetBySha256Sum(ctx context.Context, hash string) (*model.Token, error) {
	var t model.Token
	err := r.db.GetContext(ctx, &t,
		`SELECT * FROM tokens WHERE hash = $1`, hash)
	
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrTokenNotFound
	}
	return &t, err
}
