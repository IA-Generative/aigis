package repository

import (
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

func (r *TokenRepository) GetBySha256SumOrSecret(hash, secret string) (*model.Token, error) {
	var t model.Token
	err := r.db.Get(&t,
		`SELECT * FROM tokens WHERE hash = $1 OR secret = $2`, hash, secret)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrTokenNotFound
	}
	return &t, err
}
