package services

import (
	"context"
	"strings"

	errs "github.com/leokuzmanovic/go-echo-example/internal/errors"
	"github.com/leokuzmanovic/go-echo-example/internal/models"
	"github.com/pkg/errors"
	"golang.org/x/crypto/bcrypt"
	"gopkg.in/guregu/null.v4"
)

const (
	UsernameMaxLength              = 40
	UsernameOptimalGeneratedLength = 20
)

//go:generate mockery --name AuthService
type AuthService interface {
	Login(ctx context.Context, username, password string) (null.String, null.String, error)
	Logout(ctx context.Context, refreshToken string) error
	RefreshToken(ctx context.Context, refreshToken string) (null.String, null.String, error)
}

type AuthServiceImpl struct {
	tokensService           TokensService
	usersRepository         models.UsersRepository
	refreshTokensRepository models.RefreshTokensRepository
}

func NewAuthServiceImpl(usersRepository models.UsersRepository, refreshTokensRepository models.RefreshTokensRepository, tokensService TokensService) *AuthServiceImpl {
	p := new(AuthServiceImpl)
	p.usersRepository = usersRepository
	p.tokensService = tokensService
	p.refreshTokensRepository = refreshTokensRepository
	return p
}

func (s *AuthServiceImpl) Login(ctx context.Context, username, password string) (null.String, null.String, error) {
	user, err := s.usersRepository.GetByUsername(ctx, username)
	if err != nil {
		if errors.Is(err, models.ErrNotFound) {
			return null.String{}, null.String{}, &errs.InvalidCredentialsError{}
		}
		return null.String{}, null.String{}, err
	}

	err = bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(password))
	if err != nil {
		return null.String{}, null.String{}, &errs.InvalidCredentialsError{}
	}

	accessToken, refreshToken, err := s.tokensService.CreateNewTokens(ctx, user.Id)
	return accessToken, refreshToken, err
}

func (s *AuthServiceImpl) Logout(ctx context.Context, refreshToken string) error {
	id, token, err := s.parseRefreshToken(refreshToken)
	if err != nil {
		return &errs.AuthorizationError{}
	}

	tokenData, err := s.refreshTokensRepository.Get(ctx, id)
	if err != nil {
		if errors.Is(err, models.ErrNotFound) {
			return &errs.BadRequestError{}
		}
		return errors.Wrap(err, "db")
	}

	err = bcrypt.CompareHashAndPassword([]byte(tokenData.RefreshToken), []byte(token))
	if err != nil {
		return &errs.BadRequestError{}
	}

	err = errors.Wrap(s.refreshTokensRepository.Delete(ctx, id), "db")
	return err
}

func (s *AuthServiceImpl) RefreshToken(ctx context.Context, refreshToken string) (null.String, null.String, error) {
	id, token, err := s.parseRefreshToken(refreshToken)
	if err != nil {
		return null.String{}, null.String{}, &errs.AuthorizationError{}
	}

	tokenData, err := s.refreshTokensRepository.Get(ctx, id)
	if err != nil {
		if errors.Is(err, models.ErrNotFound) {
			return null.String{}, null.String{}, &errs.AuthorizationError{}
		}
		return null.String{}, null.String{}, errors.Wrap(err, "auth")
	}
	userId := tokenData.UserId

	err = bcrypt.CompareHashAndPassword([]byte(tokenData.RefreshToken), []byte(token))
	if err != nil {
		return null.String{}, null.String{}, &errs.AuthorizationError{}
	}

	err = s.refreshTokensRepository.Delete(ctx, id)
	if err != nil {
		return null.String{}, null.String{}, err
	}

	user, err := s.usersRepository.Get(ctx, userId)
	if err != nil {
		return null.String{}, null.String{}, err
	}

	at, rt, err := s.tokensService.CreateNewTokens(ctx, user.Id)
	return at, rt, errors.Wrap(err, "auth")
}

func (s *AuthServiceImpl) parseRefreshToken(refreshToken string) (string, string, error) {
	tokenParts := strings.Split(refreshToken, "-")
	if len(tokenParts) != 2 {
		return "", "", errors.New("malformed refresh token")
	}
	return tokenParts[0], tokenParts[1], nil
}
