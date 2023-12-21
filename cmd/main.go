package main

import (
	"github.com/labstack/echo/v4"
	"github.com/labstack/echo/v4/middleware"
	"github.com/leokuzmanovic/go-echo-example/internal"
	"github.com/leokuzmanovic/go-echo-example/internal/configuration"
	"github.com/leokuzmanovic/go-echo-example/internal/controllers"
	di "github.com/leokuzmanovic/go-echo-example/internal/dependencyinjection"
	"github.com/leokuzmanovic/go-echo-example/internal/metrics"
	utils "github.com/leokuzmanovic/go-echo-example/internal/utils"
	echoSwagger "github.com/swaggo/echo-swagger"
)

func main() {
	/*
		read config and secrets
		setup: data stores, cache, profiling etc...
		register these dependencies to DI container
	*/
	// using hardcoded configuration for now
	config := &configuration.AppConfig{}
	di.Register(config)

	e := echo.New()

	prepareSwagger(e, config.GetSwaggerUsername(), config.GetSwaggerPassword())
	wireCors(e)
	internal.WireDependencies()
	controllers.WireControllers(e)

	//start prometheus server
	eProm := metrics.SetupPrometheusServer(e, config.GetPrometheusUsername(), config.GetPrometheusPassword())
	go func() {
		eProm.Logger.Fatal(eProm.Start(":9090"))
	}()
	// start main server
	e.Logger.Fatal(e.Start(":5000"))
}

func wireCors(e *echo.Echo) {
	e.Use(middleware.CORSWithConfig(middleware.CORSConfig{
		AllowOrigins: []string{"*"},
		AllowHeaders: []string{"*"},
		AllowMethods: []string{"GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"},
	}))
}

func prepareSwagger(e *echo.Echo, username, password string) {
	middlewareFunc := utils.PrepareBasicAuthenticationMiddleware(username, password)
	e.GET("/swagger/*", echoSwagger.WrapHandler, middlewareFunc)
}
