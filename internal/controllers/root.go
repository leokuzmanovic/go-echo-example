package controllers

import (
	"github.com/labstack/echo/v4"
	di "github.com/leokuzmanovic/go-echo-example/internal/dependencyinjection"
	er "github.com/leokuzmanovic/go-echo-example/internal/errors"
	"github.com/leokuzmanovic/go-echo-example/internal/services"
)

func WireControllers(e *echo.Echo) {
	e.HTTPErrorHandler = er.GlobalErrorHandler
	wireMiddleware(e)
	wireAuth(e)
	wireBooks(e)
	wireHealth(e)
}

func wireMiddleware(e *echo.Echo) {
	NewContextEnricherMiddleware().Apply(e)

	tokensService := di.Get[services.TokensService]()
	NewAuthMiddleware(tokensService).Apply(e)
}
