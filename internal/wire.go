package internal

import (
	"github.com/leokuzmanovic/go-echo-example/internal/models"
	"github.com/leokuzmanovic/go-echo-example/internal/services"
)

func WireDependencies() {
	models.Wire()
	services.Wire()
}
