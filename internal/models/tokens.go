package models

import (
	"context"

	"github.com/gofrs/uuid"
)

type RefreshTokenData struct {
	Id           string
	RefreshToken string
	UserId       uuid.UUID
}

//go:generate mockery --name RefreshTokensRepository
type RefreshTokensRepository interface {
	Create(ctx context.Context, id, refreshToken string, userId uuid.UUID) error
	Get(ctx context.Context, id string) (*RefreshTokenData, error)
	Delete(ctx context.Context, id string) error
	DeleteByUserID(ctx context.Context, userID uuid.UUID) error
}

type RefreshTokensRepositoryImpl struct {
	tokenStore map[string]RefreshTokenData
}

func NewRefreshTokensRepositoryImpl() *RefreshTokensRepositoryImpl {
	p := new(RefreshTokensRepositoryImpl)
	p.tokenStore = make(map[string]RefreshTokenData)
	return p
}

func (s *RefreshTokensRepositoryImpl) Create(ctx context.Context, id, refreshToken string, userId uuid.UUID) error {
	s.tokenStore[id] = RefreshTokenData{
		Id:           id,
		RefreshToken: refreshToken,
		UserId:       userId,
	}
	return nil
}

func (s *RefreshTokensRepositoryImpl) Get(ctx context.Context, id string) (*RefreshTokenData, error) {
	token, ok := s.tokenStore[id]
	if !ok {
		return nil, ErrNotFound
	}

	return &token, nil
}

func (s *RefreshTokensRepositoryImpl) Delete(ctx context.Context, id string) error {
	delete(s.tokenStore, id)
	return nil
}

func (s *RefreshTokensRepositoryImpl) DeleteByUserID(ctx context.Context, userId uuid.UUID) error {
	for _, token := range s.tokenStore {
		if token.UserId == userId {
			delete(s.tokenStore, token.Id)
			break
		}
	}
	return nil
}
