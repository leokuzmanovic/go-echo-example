package controllers

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/labstack/echo/v4"
	"github.com/leokuzmanovic/go-echo-example/api"
	"github.com/stretchr/testify/assert"
)

func TestUnit_HealthController_health(t *testing.T) {
	t.Run("health endpoint reports correctly", func(t *testing.T) {
		e := echo.New()

		req := httptest.NewRequest(http.MethodGet, api.ENDPOINT_HEALTH, nil)
		rec := httptest.NewRecorder()
		c := e.NewContext(req, rec)
		h := HealthController{}

		assert.NoError(t, h.health(c))
		assert.Equal(t, http.StatusOK, rec.Code)
	})
}
