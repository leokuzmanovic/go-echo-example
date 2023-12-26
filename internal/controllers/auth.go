package controllers

import (
	"net/http"

	"github.com/labstack/echo/v4"

	"github.com/leokuzmanovic/go-echo-example/api"
	"github.com/leokuzmanovic/go-echo-example/internal/constants"
	di "github.com/leokuzmanovic/go-echo-example/internal/dependencyinjection"
	"github.com/leokuzmanovic/go-echo-example/internal/services"
	"github.com/pkg/errors"
)

type AuthController struct {
	authService   services.AuthService
	tokensService services.TokensService
}

func wireAuth(e *echo.Echo) {
	controller := &AuthController{
		authService:   di.Get[services.AuthService](),
		tokensService: di.Get[services.TokensService](),
	}
	e.POST(api.ENDPOINT_AUTH_LOGIN, withValidJsonBody(controller.login), getMiddlewareFunction(constants.TimeoutGenerous))
	e.POST(api.ENDPOINT_AUTH_LOGOUT, withValidJsonBody(controller.logout), getMiddlewareFunction(constants.TimeoutRegular))
	e.POST(api.ENDPOINT_AUTH_TOKEN, withValidJsonBody(controller.refreshToken), getMiddlewareFunction(constants.TimeoutRegular))
}

// @Summary Login with username and password
// @Tags auth
// @Router /auth/login [POST]
// @Param body body api.AuthLoginRequest true "AuthLoginRequest"
// @Accept json
// @Produce json
// @Success 200 {object} api.AuthResponse
// @Failure 400 {object} errors.AppError "InvalidJsonError, InvalidCredentialsError"
func (s *AuthController) login(ctx echo.Context, body *api.AuthLoginRequest) error {
	accessToken, refreshToken, err := s.authService.Login(ctx.Request().Context(), body.Username, body.Password)
	if err != nil {
		return errors.Wrap(err, "auth")
	}
	return errors.Wrap(ctx.JSON(http.StatusOK, api.AuthResponse{AccessToken: accessToken.String, RefreshToken: refreshToken.String}), "json")
}

// @Summary Logout and delete current refresh token
// @Tags auth
// @Router /auth/logout [POST]
// @Param body body api.RefreshTokenRequest true "RefreshTokenRequest"
// @Accept json
// @Success 200 {string} string
// @Failure 400 {object} errors.AppError "InvalidJsonError, BadRequestError, InvalidCredentialsError"
// @Failure 401 {object} errors.AppError "AuthorizationError"
func (s *AuthController) logout(ctx echo.Context, body *api.RefreshTokenRequest) error {
	c := ctx.Request().Context()
	err := s.authService.Logout(c, body.RefreshToken)
	if err != nil {
		return errors.Wrap(err, "logout")
	}

	return errors.Wrap(ctx.NoContent(http.StatusOK), "logout")
}

// @Summary Refresh auth token
// @Tags auth
// @Router /auth/token [POST]
// @Param body body api.RefreshTokenRequest true "RefreshTokenRequest"
// @Accept json
// @Produce json
// @Success 200 {object} views.AuthResponse
// @Failure 400 {object} errors.AppError "InvalidJsonError"
// @Failure 401 {object} errors.AppError "AuthorizationError, InvalidCredentialsError"
func (s *AuthController) refreshToken(ctx echo.Context, body *api.RefreshTokenRequest) error {
	c := ctx.Request().Context()

	accessToken, refreshToken, err := s.authService.RefreshToken(c, body.RefreshToken)
	if err != nil {
		return errors.Wrap(err, "refresh token")
	}

	return errors.Wrap(ctx.JSON(http.StatusOK, api.AuthResponse{AccessToken: accessToken.String, RefreshToken: refreshToken.String}), "json")
}
