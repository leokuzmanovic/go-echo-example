package controllers

import (
	"net/http"

	"github.com/labstack/echo/v4"
	"github.com/leokuzmanovic/go-echo-example/api"
	"github.com/pkg/errors"
)

type HealthController struct{}

func wireHealth(e *echo.Echo) {
	controller := &HealthController{}
	e.GET(api.ENDPOINT_HEALTH, controller.health)
}

// @Summary Health endpoint
// @Tags health
// @Router / [GET]
// @Success 200
func (s *HealthController) health(ctx echo.Context) error {
	return errors.Wrap(ctx.JSON(http.StatusOK, nil), "health")
}
