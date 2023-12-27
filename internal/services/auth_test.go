package services

import (
	"context"
	"testing"

	"github.com/dchest/uniuri"
	"github.com/gofrs/uuid"
	errs "github.com/leokuzmanovic/go-echo-example/internal/errors"
	"github.com/leokuzmanovic/go-echo-example/internal/models"
	"github.com/leokuzmanovic/go-echo-example/internal/models/mocks"
	serviceMocks "github.com/leokuzmanovic/go-echo-example/internal/services/mocks"
	"github.com/leokuzmanovic/go-echo-example/internal/utils"
	"github.com/pkg/errors"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"golang.org/x/crypto/bcrypt"
	"gopkg.in/guregu/null.v4"
)

func TestUnit_AuthServiceImpl_Login(t *testing.T) {
	t.Run("error fetching user", func(t *testing.T) {
		userRepositoryMock := mocks.NewUsersRepository(t)
		userRepositoryMock.On("GetByUsername", mock.Anything, mock.Anything).Return(&models.User{}, errors.New("error"))
		tokenServiceMock := serviceMocks.NewTokensService(t)
		refreshTokensRepositoryMock := mocks.NewRefreshTokensRepository(t)

		authService := NewAuthServiceImpl(userRepositoryMock, refreshTokensRepositoryMock, tokenServiceMock)

		ctx := context.TODO()

		username := "username"
		password := "password"
		_, _, err := authService.Login(ctx, username, password)
		assert.Error(t, err)
	})

	t.Run("cannot find user", func(t *testing.T) {
		userRepositoryMock := mocks.NewUsersRepository(t)
		userRepositoryMock.On("GetByUsername", mock.Anything, mock.Anything).Return(&models.User{}, models.ErrNotFound)
		tokenServiceMock := serviceMocks.NewTokensService(t)
		refreshTokensRepositoryMock := mocks.NewRefreshTokensRepository(t)

		authService := NewAuthServiceImpl(userRepositoryMock, refreshTokensRepositoryMock, tokenServiceMock)

		ctx := context.TODO()

		username := "username"
		password := "password"
		_, _, err := authService.Login(ctx, username, password)
		assert.Error(t, err)
		invalidCredentialsError := errs.InvalidCredentialsError{}
		assert.ErrorIs(t, err, &invalidCredentialsError)
	})

	t.Run("password not matching", func(t *testing.T) {
		userRepositoryMock := mocks.NewUsersRepository(t)
		userRepositoryMock.On("GetByUsername", mock.Anything, mock.Anything).Return(&models.User{Username: "username", Password: "password"}, nil)
		tokenServiceMock := serviceMocks.NewTokensService(t)
		refreshTokensRepositoryMock := mocks.NewRefreshTokensRepository(t)

		authService := NewAuthServiceImpl(userRepositoryMock, refreshTokensRepositoryMock, tokenServiceMock)

		ctx := context.TODO()

		username := "username"
		password := "password2"
		_, _, err := authService.Login(ctx, username, password)
		assert.Error(t, err)
		invalidCredentialsError := errs.InvalidCredentialsError{}
		assert.ErrorIs(t, err, &invalidCredentialsError)
	})

	t.Run("error creating token", func(t *testing.T) {
		userRepositoryMock := mocks.NewUsersRepository(t)
		username := "username"
		password := "password"
		passwordHashed, _ := utils.GeneratePassword(password)
		userRepositoryMock.On("GetByUsername", mock.Anything, mock.Anything).Return(&models.User{Username: username, Password: passwordHashed}, nil)
		tokenServiceMock := serviceMocks.NewTokensService(t)
		tokenServiceMock.On("CreateNewTokens", mock.Anything, mock.Anything).Return(null.String{}, null.String{}, errors.New("error"))
		refreshTokensRepositoryMock := mocks.NewRefreshTokensRepository(t)

		authService := NewAuthServiceImpl(userRepositoryMock, refreshTokensRepositoryMock, tokenServiceMock)

		ctx := context.TODO()

		_, _, err := authService.Login(ctx, username, password)
		assert.Error(t, err)
	})

	t.Run("successful login", func(t *testing.T) {
		userRepositoryMock := mocks.NewUsersRepository(t)
		username := "username"
		password := "password"
		passwordHashed, _ := utils.GeneratePassword(password)
		userRepositoryMock.On("GetByUsername", mock.Anything, mock.Anything).Return(&models.User{Username: username, Password: passwordHashed}, nil)
		tokenServiceMock := serviceMocks.NewTokensService(t)
		accessToken := null.StringFrom("accessToken")
		refreshToken := null.StringFrom("refreshToken")
		tokenServiceMock.On("CreateNewTokens", mock.Anything, mock.Anything).Return(accessToken, refreshToken, nil)
		refreshTokensRepositoryMock := mocks.NewRefreshTokensRepository(t)

		authService := NewAuthServiceImpl(userRepositoryMock, refreshTokensRepositoryMock, tokenServiceMock)

		ctx := context.TODO()

		at, rt, err := authService.Login(ctx, username, password)
		assert.NoError(t, err)
		assert.Equal(t, accessToken, at)
		assert.Equal(t, refreshToken, rt)
	})
}

func TestUnit_AuthServiceImpl_Logout(t *testing.T) {
	t.Run("invalid refresh token", func(t *testing.T) {
		userRepositoryMock := mocks.NewUsersRepository(t)
		tokenServiceMock := serviceMocks.NewTokensService(t)
		refreshTokensRepositoryMock := mocks.NewRefreshTokensRepository(t)

		authService := NewAuthServiceImpl(userRepositoryMock, refreshTokensRepositoryMock, tokenServiceMock)

		ctx := context.TODO()

		err := authService.Logout(ctx, "invalid")
		assert.Error(t, err)
		authorizationError := errs.AuthorizationError{}
		assert.ErrorIs(t, err, &authorizationError)
	})

	t.Run("error fetching refresh token", func(t *testing.T) {
		userRepositoryMock := mocks.NewUsersRepository(t)
		tokenServiceMock := serviceMocks.NewTokensService(t)
		refreshTokensRepositoryMock := mocks.NewRefreshTokensRepository(t)
		refreshTokensRepositoryMock.On("Get", mock.Anything, mock.Anything).Return(&models.RefreshTokenData{}, errors.New("error"))

		authService := NewAuthServiceImpl(userRepositoryMock, refreshTokensRepositoryMock, tokenServiceMock)

		ctx := context.TODO()

		err := authService.Logout(ctx, "refresh-token")
		assert.Error(t, err)
	})

	t.Run("refresh token not found", func(t *testing.T) {
		userRepositoryMock := mocks.NewUsersRepository(t)
		tokenServiceMock := serviceMocks.NewTokensService(t)
		refreshTokensRepositoryMock := mocks.NewRefreshTokensRepository(t)
		refreshTokensRepositoryMock.On("Get", mock.Anything, mock.Anything).Return(&models.RefreshTokenData{}, models.ErrNotFound)

		authService := NewAuthServiceImpl(userRepositoryMock, refreshTokensRepositoryMock, tokenServiceMock)

		ctx := context.TODO()

		err := authService.Logout(ctx, "refresh-token")
		assert.Error(t, err)
		badRequestError := errs.BadRequestError{}
		assert.ErrorIs(t, err, &badRequestError)
	})

	t.Run("refresh token not matching", func(t *testing.T) {
		userRepositoryMock := mocks.NewUsersRepository(t)
		tokenServiceMock := serviceMocks.NewTokensService(t)
		refreshTokensRepositoryMock := mocks.NewRefreshTokensRepository(t)
		ctx := context.TODO()
		userId := uuid.Must(uuid.NewV4())
		id := uniuri.NewLen(50)
		code := uniuri.NewLen(72)
		codeHashed, _ := bcrypt.GenerateFromPassword([]byte(code), bcrypt.DefaultCost)
		refreshTokensRepositoryMock.On("Get", mock.Anything, mock.Anything).Return(&models.RefreshTokenData{Id: id, RefreshToken: string(codeHashed), UserId: userId}, nil)

		authService := NewAuthServiceImpl(userRepositoryMock, refreshTokensRepositoryMock, tokenServiceMock)

		err := authService.Logout(ctx, "refresh-token")
		assert.Error(t, err)
		badRequestError := errs.BadRequestError{}
		assert.ErrorIs(t, err, &badRequestError)
	})

	t.Run("error deleting refresh token", func(t *testing.T) {
		userRepositoryMock := mocks.NewUsersRepository(t)
		tokenServiceMock := serviceMocks.NewTokensService(t)
		refreshTokensRepositoryMock := mocks.NewRefreshTokensRepository(t)
		ctx := context.TODO()
		userId := uuid.Must(uuid.NewV4())
		id := uniuri.NewLen(50)
		code := uniuri.NewLen(72)
		codeHashed, _ := bcrypt.GenerateFromPassword([]byte(code), bcrypt.DefaultCost)
		refreshTokensRepositoryMock.On("Get", mock.Anything, mock.Anything).Return(&models.RefreshTokenData{Id: id, RefreshToken: string(codeHashed), UserId: userId}, nil)
		refreshTokensRepositoryMock.On("Delete", mock.Anything, mock.Anything).Return(errors.New("error"))

		authService := NewAuthServiceImpl(userRepositoryMock, refreshTokensRepositoryMock, tokenServiceMock)

		err := authService.Logout(ctx, "refresh-"+string(code))
		assert.Error(t, err)
	})

	t.Run("successful logout", func(t *testing.T) {
		userRepositoryMock := mocks.NewUsersRepository(t)
		tokenServiceMock := serviceMocks.NewTokensService(t)
		refreshTokensRepositoryMock := mocks.NewRefreshTokensRepository(t)
		ctx := context.TODO()
		userId := uuid.Must(uuid.NewV4())
		id := uniuri.NewLen(50)
		code := uniuri.NewLen(72)
		codeHashed, _ := bcrypt.GenerateFromPassword([]byte(code), bcrypt.DefaultCost)
		refreshTokensRepositoryMock.On("Get", mock.Anything, mock.Anything).Return(&models.RefreshTokenData{Id: id, RefreshToken: string(codeHashed), UserId: userId}, nil)
		refreshTokensRepositoryMock.On("Delete", mock.Anything, mock.Anything).Return(nil)

		authService := NewAuthServiceImpl(userRepositoryMock, refreshTokensRepositoryMock, tokenServiceMock)

		err := authService.Logout(ctx, "refresh-"+string(code))
		assert.NoError(t, err)
	})
}

func TestUnit_AuthServiceImpl_RefreshToken(t *testing.T) {
	t.Run("invalid refresh token", func(t *testing.T) {
		userRepositoryMock := mocks.NewUsersRepository(t)
		tokenServiceMock := serviceMocks.NewTokensService(t)
		refreshTokensRepositoryMock := mocks.NewRefreshTokensRepository(t)

		authService := NewAuthServiceImpl(userRepositoryMock, refreshTokensRepositoryMock, tokenServiceMock)

		ctx := context.TODO()

		_, _, err := authService.RefreshToken(ctx, "invalid")
		assert.Error(t, err)
		authorizationError := errs.AuthorizationError{}
		assert.ErrorIs(t, err, &authorizationError)
	})

	t.Run("error fetching refresh token", func(t *testing.T) {
		userRepositoryMock := mocks.NewUsersRepository(t)
		tokenServiceMock := serviceMocks.NewTokensService(t)
		refreshTokensRepositoryMock := mocks.NewRefreshTokensRepository(t)
		refreshTokensRepositoryMock.On("Get", mock.Anything, mock.Anything).Return(&models.RefreshTokenData{}, errors.New("error"))

		authService := NewAuthServiceImpl(userRepositoryMock, refreshTokensRepositoryMock, tokenServiceMock)

		ctx := context.TODO()

		_, _, err := authService.RefreshToken(ctx, "refresh-token")
		assert.Error(t, err)
	})

	t.Run("refresh token not found", func(t *testing.T) {
		userRepositoryMock := mocks.NewUsersRepository(t)
		tokenServiceMock := serviceMocks.NewTokensService(t)
		refreshTokensRepositoryMock := mocks.NewRefreshTokensRepository(t)
		refreshTokensRepositoryMock.On("Get", mock.Anything, mock.Anything).Return(&models.RefreshTokenData{}, models.ErrNotFound)

		authService := NewAuthServiceImpl(userRepositoryMock, refreshTokensRepositoryMock, tokenServiceMock)

		ctx := context.TODO()

		_, _, err := authService.RefreshToken(ctx, "refresh-token")
		assert.Error(t, err)
		authorizationError := errs.AuthorizationError{}
		assert.ErrorIs(t, err, &authorizationError)
	})

	t.Run("refresh token not matching", func(t *testing.T) {
		userRepositoryMock := mocks.NewUsersRepository(t)
		tokenServiceMock := serviceMocks.NewTokensService(t)
		refreshTokensRepositoryMock := mocks.NewRefreshTokensRepository(t)
		ctx := context.TODO()
		userId := uuid.Must(uuid.NewV4())
		id := uniuri.NewLen(50)
		code := uniuri.NewLen(72)
		codeHashed, _ := bcrypt.GenerateFromPassword([]byte(code), bcrypt.DefaultCost)
		refreshTokensRepositoryMock.On("Get", mock.Anything, mock.Anything).Return(&models.RefreshTokenData{Id: id, RefreshToken: string(codeHashed), UserId: userId}, nil)

		authService := NewAuthServiceImpl(userRepositoryMock, refreshTokensRepositoryMock, tokenServiceMock)

		_, _, err := authService.RefreshToken(ctx, "refresh-token")
		assert.Error(t, err)
		authorizationError := errs.AuthorizationError{}
		assert.ErrorIs(t, err, &authorizationError)
	})

	t.Run("error deleting refresh token", func(t *testing.T) {
		userRepositoryMock := mocks.NewUsersRepository(t)
		tokenServiceMock := serviceMocks.NewTokensService(t)
		refreshTokensRepositoryMock := mocks.NewRefreshTokensRepository(t)
		ctx := context.TODO()
		userId := uuid.Must(uuid.NewV4())
		id := uniuri.NewLen(50)
		code := uniuri.NewLen(72)
		codeHashed, _ := bcrypt.GenerateFromPassword([]byte(code), bcrypt.DefaultCost)
		refreshTokensRepositoryMock.On("Get", mock.Anything, mock.Anything).Return(&models.RefreshTokenData{Id: id, RefreshToken: string(codeHashed), UserId: userId}, nil)
		refreshTokensRepositoryMock.On("Delete", mock.Anything, mock.Anything).Return(errors.New("error"))

		authService := NewAuthServiceImpl(userRepositoryMock, refreshTokensRepositoryMock, tokenServiceMock)

		_, _, err := authService.RefreshToken(ctx, "refresh-"+string(code))
		assert.Error(t, err)
	})

	t.Run("error fetching user", func(t *testing.T) {
		userId := uuid.Must(uuid.NewV4())
		userRepositoryMock := mocks.NewUsersRepository(t)
		userRepositoryMock.On("Get", mock.Anything, mock.Anything).Return(&models.User{Id: userId}, errors.New("error"))
		tokenServiceMock := serviceMocks.NewTokensService(t)
		refreshTokensRepositoryMock := mocks.NewRefreshTokensRepository(t)
		ctx := context.TODO()

		id := uniuri.NewLen(50)
		code := uniuri.NewLen(72)
		codeHashed, _ := bcrypt.GenerateFromPassword([]byte(code), bcrypt.DefaultCost)
		refreshTokensRepositoryMock.On("Get", mock.Anything, mock.Anything).Return(&models.RefreshTokenData{Id: id, RefreshToken: string(codeHashed), UserId: userId}, nil)
		refreshTokensRepositoryMock.On("Delete", mock.Anything, mock.Anything).Return(nil)

		authService := NewAuthServiceImpl(userRepositoryMock, refreshTokensRepositoryMock, tokenServiceMock)

		_, _, err := authService.RefreshToken(ctx, "refresh-"+string(code))
		assert.Error(t, err)
	})

	t.Run("error creating new tokens", func(t *testing.T) {
		userId := uuid.Must(uuid.NewV4())
		userRepositoryMock := mocks.NewUsersRepository(t)
		userRepositoryMock.On("Get", mock.Anything, mock.Anything).Return(&models.User{Id: userId}, nil)
		tokenServiceMock := serviceMocks.NewTokensService(t)
		tokenServiceMock.On("CreateNewTokens", mock.Anything, mock.Anything).Return(null.String{}, null.String{}, errors.New("error"))
		refreshTokensRepositoryMock := mocks.NewRefreshTokensRepository(t)
		ctx := context.TODO()

		id := uniuri.NewLen(50)
		code := uniuri.NewLen(72)
		codeHashed, _ := bcrypt.GenerateFromPassword([]byte(code), bcrypt.DefaultCost)
		refreshTokensRepositoryMock.On("Get", mock.Anything, mock.Anything).Return(&models.RefreshTokenData{Id: id, RefreshToken: string(codeHashed), UserId: userId}, nil)
		refreshTokensRepositoryMock.On("Delete", mock.Anything, mock.Anything).Return(nil)

		authService := NewAuthServiceImpl(userRepositoryMock, refreshTokensRepositoryMock, tokenServiceMock)

		_, _, err := authService.RefreshToken(ctx, "refresh-"+string(code))
		assert.Error(t, err)
	})

	t.Run("successful token refresh", func(t *testing.T) {
		userId := uuid.Must(uuid.NewV4())
		userRepositoryMock := mocks.NewUsersRepository(t)
		userRepositoryMock.On("Get", mock.Anything, mock.Anything).Return(&models.User{Id: userId}, nil)
		tokenServiceMock := serviceMocks.NewTokensService(t)
		accessToken := null.StringFrom("accessToken")
		refreshToken := null.StringFrom("refreshToken")
		tokenServiceMock.On("CreateNewTokens", mock.Anything, mock.Anything).Return(accessToken, refreshToken, nil)
		refreshTokensRepositoryMock := mocks.NewRefreshTokensRepository(t)
		ctx := context.TODO()

		id := uniuri.NewLen(50)
		code := uniuri.NewLen(72)
		codeHashed, _ := bcrypt.GenerateFromPassword([]byte(code), bcrypt.DefaultCost)
		refreshTokensRepositoryMock.On("Get", mock.Anything, mock.Anything).Return(&models.RefreshTokenData{Id: id, RefreshToken: string(codeHashed), UserId: userId}, nil)
		refreshTokensRepositoryMock.On("Delete", mock.Anything, mock.Anything).Return(nil)

		authService := NewAuthServiceImpl(userRepositoryMock, refreshTokensRepositoryMock, tokenServiceMock)

		at, rt, err := authService.RefreshToken(ctx, "refresh-"+string(code))
		assert.NoError(t, err)
		assert.Equal(t, accessToken, at)
		assert.Equal(t, refreshToken, rt)
	})
}
