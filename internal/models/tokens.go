package models

import (
	"context"

	"github.com/gofrs/uuid"
)

type TokenData struct {
	Id     string
	Token  string
	UserId uuid.UUID
}

type TokensRepository interface {
	Create(ctx context.Context, id, refreshToken string, userId uuid.UUID) error
	Get(ctx context.Context, id string) (*TokenData, error)
	Delete(ctx context.Context, id string) error
	DeleteByUserID(ctx context.Context, userID uuid.UUID) error
}

type TokensRepositoryImpl struct {
	tokenStore map[string]TokenData
}

func NewTokensRepositoryImpl() *TokensRepositoryImpl {
	p := new(TokensRepositoryImpl)
	p.tokenStore = make(map[string]TokenData)
	return p
}

func (s *TokensRepositoryImpl) Create(ctx context.Context, id, refreshToken string, userId uuid.UUID) error {
	s.tokenStore[id] = TokenData{
		Id:     id,
		Token:  refreshToken,
		UserId: userId,
	}
	return nil
}

func (s *TokensRepositoryImpl) Get(ctx context.Context, id string) (*TokenData, error) {
	token, ok := s.tokenStore[id]
	if !ok {
		return nil, ErrNotFound
	}

	return &token, nil
}

func (s *TokensRepositoryImpl) Delete(ctx context.Context, id string) error {
	delete(s.tokenStore, id)
	return nil
}

func (s *TokensRepositoryImpl) DeleteByUserID(ctx context.Context, userId uuid.UUID) error {
	for _, token := range s.tokenStore {
		if token.UserId == userId {
			delete(s.tokenStore, token.Id)
			break
		}
	}
	return nil
}
