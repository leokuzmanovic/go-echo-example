package internal

import (
	"github.com/leokuzmanovic/go-echo-example/internal/configuration"
	"github.com/leokuzmanovic/go-echo-example/internal/models"
	"github.com/leokuzmanovic/go-echo-example/internal/services"
)

func WireDependencies() {
	configuration.Wire()
	models.Wire()
	services.Wire()
}
