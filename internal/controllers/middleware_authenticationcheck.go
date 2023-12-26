package controllers

import (
	"context"
	"net/http"
	"strings"

	"github.com/labstack/echo/v4"
	api "github.com/leokuzmanovic/go-echo-example/api"
	"github.com/leokuzmanovic/go-echo-example/internal/configuration"
	"github.com/leokuzmanovic/go-echo-example/internal/constants"
	errs "github.com/leokuzmanovic/go-echo-example/internal/errors"
	"github.com/leokuzmanovic/go-echo-example/internal/services"
	utils "github.com/leokuzmanovic/go-echo-example/internal/utils"
	"github.com/pkg/errors"
)

const (
	HeaderAuthorizationBearer = "Bearer"
)

type (
	AuthMiddleware struct {
		tokensService          services.TokensService
		endpointsConfigService configuration.EndpointsConfigService
	}
)

func NewAuthMiddleware(tokensService services.TokensService, endpointsConfigService configuration.EndpointsConfigService) *AuthMiddleware {
	p := &AuthMiddleware{tokensService: tokensService, endpointsConfigService: endpointsConfigService}
	return p
}

func (s *AuthMiddleware) Apply(e *echo.Echo) {
	e.Use(s.CheckRequestAuthentication)
}

func (s *AuthMiddleware) CheckRequestAuthentication(next echo.HandlerFunc) echo.HandlerFunc {
	return func(ctx echo.Context) error {
		r := ctx.Request()
		sanitisedUri := utils.SanitizeUri(r.RequestURI)

		if !s.endpointsConfigService.IsAuthRequired(sanitisedUri, r.Method) {
			return next(ctx)
		}

		err := s.checkAuthentication(ctx, r)
		if err != nil {
			return errors.Wrap(err, "auth")
		}
		return next(ctx)
	}
}

func (s *AuthMiddleware) checkAuthentication(ctx echo.Context, r *http.Request) error {
	authenticationHeader := r.Header.Get(api.HeaderAuthorization)
	token, err := getAuthenticationToken(authenticationHeader)
	if err != nil {
		return err
	}

	userId, ok, err := s.tokensService.CheckToken(r.Context(), token)
	if err != nil {
		return errors.Wrap(err, "auth")
	}
	if !ok {
		return errs.AuthorizationError{}
	}

	// set user id in context
	ctx.Set(constants.KeyUserId, userId)
	c := ctx.Request().Context()
	c = context.WithValue(c, constants.KeyUserId, userId)
	_ = ctx.Request().WithContext(c)

	return nil
}

func getAuthenticationToken(authenticationHeader string) (string, error) {
	if authenticationHeader == "" || !strings.HasPrefix(authenticationHeader, HeaderAuthorizationBearer) {
		return "", &errs.AuthorizationError{}
	}

	headerValueParts := strings.Split(authenticationHeader, " ")
	if len(headerValueParts) != 2 {
		return "", &errs.AuthorizationError{}
	}
	token := headerValueParts[1]
	return token, nil
}
