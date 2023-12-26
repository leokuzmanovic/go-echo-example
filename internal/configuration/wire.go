package configuration

import (
	di "github.com/leokuzmanovic/go-echo-example/internal/dependencyinjection"
)

func Wire() {
	var endpointsConfigService EndpointsConfigService = NewEndpointsConfigService()
	di.Register(endpointsConfigService)
}
