package configuration

import (
	"testing"

	"github.com/leokuzmanovic/go-echo-example/api"
	"github.com/stretchr/testify/assert"
)

func TestUnit_EndpointConfig_IsAuthRequired(t *testing.T) {
	t.Run("various messages without log context", func(t *testing.T) {
		endpointsConfigService := NewEndpointsConfigService()

		endpointConfigsToTest := []struct {
			endpoint     string
			verb         string
			authRequired bool
		}{
			{api.ENDPOINT_BOOKS, "POST", true},
			{api.ENDPOINT_BOOKS_BY_ID, "DELETE", true},
			{api.ENDPOINT_BOOKS_BY_ID, "GET", false},
			{api.ENDPOINT_HEALTH, "GET", false},
			{api.ENDPOINT_METRICS, "GET", false},          // /metrics has basic auth by default
			{api.ENDPOINT_SWAGGER, "GET", false},          // /swagger has basic auth by default
			{api.ENDPOINT_SWAGGER + "/abc", "GET", false}, // /swagger.* has basic auth by default
			{api.ENDPOINT_AUTH_LOGIN, "POST", false},
			{api.ENDPOINT_AUTH_LOGOUT, "POST", true},
			{api.ENDPOINT_AUTH_TOKEN, "POST", false},
		}
		for _, ec := range endpointConfigsToTest {
			assert.Equal(t, endpointsConfigService.IsAuthRequired(ec.endpoint, ec.verb), ec.authRequired)
		}
	})
}

func TestUnit_EndpointConfig_AreMetricsEnabled(t *testing.T) {
	t.Run("various messages without log context", func(t *testing.T) {
		endpointsConfigService := NewEndpointsConfigService()

		endpointConfigsToTest := []struct {
			endpoint       string
			metricsEnabled bool
		}{
			{api.ENDPOINT_BOOKS, true},
			{api.ENDPOINT_BOOKS_BY_ID, true},
			{api.ENDPOINT_HEALTH, true},
			{api.ENDPOINT_METRICS, false},
			{api.ENDPOINT_SWAGGER, false},
			{api.ENDPOINT_AUTH_LOGIN, true},
			{api.ENDPOINT_AUTH_LOGOUT, true},
			{api.ENDPOINT_AUTH_TOKEN, true},
		}
		for _, ec := range endpointConfigsToTest {
			assert.Equal(t, endpointsConfigService.AreMetricsEnabled(ec.endpoint), ec.metricsEnabled)
		}
	})
}
