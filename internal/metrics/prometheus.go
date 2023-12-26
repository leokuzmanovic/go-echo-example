package metrics

import (
	"github.com/leokuzmanovic/go-echo-example/internal/configuration"
	utils "github.com/leokuzmanovic/go-echo-example/internal/utils"

	"github.com/labstack/echo-contrib/prometheus"
	"github.com/labstack/echo/v4"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

var endpointsConfigService configuration.EndpointsConfigService

func SetupPrometheusServer(e *echo.Echo, username, password string, ecs configuration.EndpointsConfigService) *echo.Echo {
	endpointsConfigService = ecs
	eProm := echo.New()
	eProm.HideBanner = true
	p := prometheus.NewPrometheus("echo", func(c echo.Context) bool {
		return !endpointsConfigService.AreMetricsEnabled(utils.SanitizeUri(c.Request().RequestURI))
	})
	e.Use(p.HandlerFunc)
	p.SetMetricsPath(eProm)

	middlewareFunc := utils.PrepareBasicAuthenticationMiddleware(username, password)
	h := promhttp.Handler()
	e.GET(p.MetricsPath, func(c echo.Context) error {
		h.ServeHTTP(c.Response(), c.Request())
		return nil
	}, middlewareFunc)

	return eProm
}
