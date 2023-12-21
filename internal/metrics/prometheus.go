package metrics

import (
	"github.com/leokuzmanovic/go-echo-example/internal/configuration"
	utils "github.com/leokuzmanovic/go-echo-example/internal/utils"

	"github.com/labstack/echo-contrib/prometheus"
	"github.com/labstack/echo/v4"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

/*
func PreparePrometheusOnSamePort(e *echo.Echo) {
	p := prometheus.NewPrometheus("echo", func(c echo.Context) bool {
		if _, ok := allPrometheusEndpointsMap[c.Path()]; ok {
			return false // only app's endpoints will be tracked
		}
		return true // skip any other endpoints
	})
	e.Use(p.HandlerFunc)

	middlewareFunc := utils.GetBasicAuthMiddlewareFunction("admin", config.Secrets.Auth.MetricsPassword)
	h := promhttp.Handler()
	e.GET(p.MetricsPath, func(c echo.Context) error {
		h.ServeHTTP(c.Response(), c.Request())
		return nil
	}, middlewareFunc)
}
*/

func SetupPrometheusServer(e *echo.Echo, username, password string) *echo.Echo {
	eProm := echo.New()
	eProm.HideBanner = true
	p := prometheus.NewPrometheus("echo", func(c echo.Context) bool {
		return !configuration.AreMetricsEnabled(utils.SanitizeUri(c.Request().RequestURI))
	})
	// Scrape metrics from Main Server
	e.Use(p.HandlerFunc)
	// metrics endpoint hosted on eProm server
	p.SetMetricsPath(eProm)

	middlewareFunc := utils.PrepareBasicAuthenticationMiddleware(username, password)
	h := promhttp.Handler()
	e.GET(p.MetricsPath, func(c echo.Context) error {
		h.ServeHTTP(c.Response(), c.Request())
		return nil
	}, middlewareFunc)

	return eProm
}
