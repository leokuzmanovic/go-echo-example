package controllers

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/labstack/echo/v4"
	"github.com/leokuzmanovic/go-echo-example/api"

	"github.com/leokuzmanovic/go-echo-example/internal/services/mocks"
	utils "github.com/leokuzmanovic/go-echo-example/internal/utils"
	_ "github.com/lib/pq"
	"github.com/pkg/errors"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"gopkg.in/guregu/null.v4"
)

func TestUnit_AuthController_Login(t *testing.T) {
	var body api.AuthLoginRequest
	_ = utils.ParseJSON(strings.NewReader(AuthLoginRequestJSON), &body)

	t.Run("service returns error", func(t *testing.T) {
		e := echo.New()
		request := httptest.NewRequest(http.MethodPost, api.ENDPOINT_AUTH_LOGIN, nil)
		recorder := httptest.NewRecorder()
		ctx := e.NewContext(request, recorder)
		authServiceMock := mocks.NewAuthService(t)
		tokensService := mocks.NewTokensService(t)
		authServiceMock.On("Login", mock.Anything, mock.Anything, mock.Anything).Return(null.String{}, null.String{}, errors.New("error"))

		authController := AuthController{
			authServiceMock,
			tokensService,
		}
		err := authController.login(ctx, &body)

		assert.Error(t, err)
		authServiceMock.AssertCalled(t, "Login", mock.Anything, body.Username, body.Password)
	})

	t.Run("successful login", func(t *testing.T) {
		e := echo.New()
		request := httptest.NewRequest(http.MethodPost, api.ENDPOINT_AUTH_LOGIN, nil)
		recorder := httptest.NewRecorder()
		ctx := e.NewContext(request, recorder)
		authServiceMock := mocks.NewAuthService(t)
		tokensService := mocks.NewTokensService(t)
		accessToken := null.StringFrom("abc123")
		refreshToken := null.StringFrom("def456")
		authServiceMock.On("Login", mock.Anything, mock.Anything, mock.Anything).
			Return(accessToken, refreshToken, nil)

		authController := AuthController{
			authServiceMock,
			tokensService,
		}
		err := authController.login(ctx, &body)

		assert.NoError(t, err)
		authServiceMock.AssertCalled(t, "Login", mock.Anything, body.Username, body.Password)

		assert.Equal(t, http.StatusOK, recorder.Code)
		var response api.AuthResponse
		err = json.Unmarshal(recorder.Body.Bytes(), &response)
		assert.NoError(t, err)
		assert.Equal(t, accessToken.String, response.AccessToken)
		assert.Equal(t, refreshToken.String, response.RefreshToken)
	})
}

func TestUnit_AuthController_Logout(t *testing.T) {
	var body api.RefreshTokenRequest
	_ = utils.ParseJSON(strings.NewReader(RefreshTokenRequestJSON), &body)

	t.Run("service returns error", func(t *testing.T) {
		e := echo.New()
		request := httptest.NewRequest(http.MethodPost, api.ENDPOINT_AUTH_LOGOUT, nil)
		recorder := httptest.NewRecorder()
		ctx := e.NewContext(request, recorder)
		authServiceMock := mocks.NewAuthService(t)
		tokensService := mocks.NewTokensService(t)
		authServiceMock.On("Logout", mock.Anything, mock.Anything).Return(errors.New("error"))

		authController := AuthController{
			authServiceMock,
			tokensService,
		}
		err := authController.logout(ctx, &body)

		assert.Error(t, err)
		authServiceMock.AssertCalled(t, "Logout", mock.Anything, body.RefreshToken)
	})

	t.Run("successful logout", func(t *testing.T) {
		e := echo.New()
		request := httptest.NewRequest(http.MethodPost, api.ENDPOINT_AUTH_LOGOUT, nil)
		recorder := httptest.NewRecorder()
		ctx := e.NewContext(request, recorder)
		authServiceMock := mocks.NewAuthService(t)
		tokensService := mocks.NewTokensService(t)
		authServiceMock.On("Logout", mock.Anything, body.RefreshToken).Return(nil)

		authController := AuthController{
			authServiceMock,
			tokensService,
		}
		err := authController.logout(ctx, &body)

		assert.NoError(t, err)
		authServiceMock.AssertCalled(t, "Logout", mock.Anything, body.RefreshToken)

		assert.Equal(t, http.StatusOK, recorder.Code)
	})
}

func TestUnit_AuthController_RefreshToken(t *testing.T) {
	var body api.RefreshTokenRequest
	_ = utils.ParseJSON(strings.NewReader(RefreshTokenRequestJSON), &body)

	t.Run("service returns error", func(t *testing.T) {
		e := echo.New()
		request := httptest.NewRequest(http.MethodPost, api.ENDPOINT_AUTH_TOKEN, nil)
		recorder := httptest.NewRecorder()
		ctx := e.NewContext(request, recorder)
		authServiceMock := mocks.NewAuthService(t)
		tokensService := mocks.NewTokensService(t)
		authServiceMock.On("RefreshToken", mock.Anything, mock.Anything).Return(null.String{}, null.String{}, errors.New("error"))

		authController := AuthController{
			authServiceMock,
			tokensService,
		}
		err := authController.refreshToken(ctx, &body)

		assert.Error(t, err)
		authServiceMock.AssertCalled(t, "RefreshToken", mock.Anything, body.RefreshToken)
	})

	t.Run("successful token refresh", func(t *testing.T) {
		e := echo.New()
		request := httptest.NewRequest(http.MethodPost, api.ENDPOINT_AUTH_TOKEN, nil)
		recorder := httptest.NewRecorder()
		ctx := e.NewContext(request, recorder)
		authServiceMock := mocks.NewAuthService(t)
		tokensService := mocks.NewTokensService(t)
		accessToken := null.StringFrom("abc123")
		refreshToken := null.StringFrom("def456")
		authServiceMock.On("RefreshToken", mock.Anything, body.RefreshToken).Return(accessToken, refreshToken, nil)

		authController := AuthController{
			authServiceMock,
			tokensService,
		}
		err := authController.refreshToken(ctx, &body)

		assert.NoError(t, err)
		authServiceMock.AssertCalled(t, "RefreshToken", mock.Anything, body.RefreshToken)

		assert.Equal(t, http.StatusOK, recorder.Code)
		var response api.AuthResponse
		err = json.Unmarshal(recorder.Body.Bytes(), &response)
		assert.NoError(t, err)
		assert.Equal(t, accessToken.String, response.AccessToken)
		assert.Equal(t, refreshToken.String, response.RefreshToken)
	})
}
