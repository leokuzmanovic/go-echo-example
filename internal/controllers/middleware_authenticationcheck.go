package controllers

import (
	"context"
	"net/http"
	"strings"

	"github.com/labstack/echo/v4"
	api "github.com/leokuzmanovic/go-echo-example/api"
	config "github.com/leokuzmanovic/go-echo-example/internal/configuration"
	"github.com/leokuzmanovic/go-echo-example/internal/constants"
	errs "github.com/leokuzmanovic/go-echo-example/internal/errors"
	"github.com/leokuzmanovic/go-echo-example/internal/services"
	utils "github.com/leokuzmanovic/go-echo-example/internal/utils"
	"github.com/pkg/errors"
)

type (
	AuthMiddleware struct {
		tokensService services.TokensService
	}
)

func NewAuthMiddleware(tokensService services.TokensService) *AuthMiddleware {
	p := &AuthMiddleware{tokensService: tokensService}
	return p
}

func (s *AuthMiddleware) Apply(e *echo.Echo) {
	e.Use(s.AuthorizeRequest)
}

func (s *AuthMiddleware) AuthorizeRequest(next echo.HandlerFunc) echo.HandlerFunc {
	return func(ctx echo.Context) error {
		r := ctx.Request()
		sanitisedUri := utils.SanitizeUri(r.RequestURI)

		if !config.IsAuthRequired(sanitisedUri, r.Method) {
			return next(ctx)
		}

		err := s.checkAuthentication(ctx, r, r.Header.Get(api.HeaderAuthorization))
		if err != nil {
			return errors.Wrap(err, "auth")
		}
		return next(ctx)
	}
}

func (s *AuthMiddleware) checkAuthentication(ctx echo.Context, r *http.Request, header string) error {
	token, err := checkToken(header, api.HeaderAuthorizationBearer)
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

func checkToken(header, tokenPrefix string) (string, error) {
	if header == "" || !strings.HasPrefix(header, tokenPrefix) {
		return "", &errs.AuthorizationError{}
	}
	return getToken(header)
}

func getToken(header string) (string, error) {
	headerValueParts := strings.Split(header, " ")
	if len(headerValueParts) != 2 {
		return "", &errs.AuthorizationError{}
	}
	token := headerValueParts[1]
	return token, nil
}
