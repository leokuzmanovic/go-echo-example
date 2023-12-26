package controllers

import (
	"github.com/labstack/echo/v4"
	"github.com/leokuzmanovic/go-echo-example/internal/configuration"
	di "github.com/leokuzmanovic/go-echo-example/internal/dependencyinjection"
	er "github.com/leokuzmanovic/go-echo-example/internal/errors"
	"github.com/leokuzmanovic/go-echo-example/internal/services"
)

func WireControllers(e *echo.Echo) {
	e.HTTPErrorHandler = er.GlobalErrorHandler
	wireAllMiddleware(e)
	wireAuth(e)
	wireBooks(e)
	wireHealth(e)
}

func wireAllMiddleware(e *echo.Echo) {
	NewContextEnricherMiddleware().Apply(e)

	tokensService := di.Get[services.TokensService]()
	endpointsConfigService := di.Get[configuration.EndpointsConfigService]()

	NewAuthMiddleware(tokensService, endpointsConfigService).Apply(e)
}
