package configuration

import (
	"regexp"
	"strings"
)

type EndpointConfig struct {
	PathPattern                     string
	EndpointSecurityConfigPerMethod map[string]EndpointSecurityConfig
	MetricsEnabled                  bool
}

type EndpointSecurityConfig struct {
	NoAuthRequired bool // by default, auth is required
}

// BY DEFAULT, authentication and metrics are required/enabled on all endpoints - unless explicitly configured otherwise
var endpointsConfig []EndpointConfig = []EndpointConfig{
	{
		PathPattern: "\\/books\\/.+", // regex: /books/1
		EndpointSecurityConfigPerMethod: map[string]EndpointSecurityConfig{
			"GET": {NoAuthRequired: true},
		},
	},
	{
		PathPattern: "\\/health$", // regex: /health
		EndpointSecurityConfigPerMethod: map[string]EndpointSecurityConfig{
			"GET": {NoAuthRequired: true},
		},
	},
	{
		PathPattern: "\\/metrics$", // regex: /metrics
		EndpointSecurityConfigPerMethod: map[string]EndpointSecurityConfig{
			"GET": {NoAuthRequired: true},
		},
		MetricsEnabled: false,
	},
	{
		PathPattern: "\\/swagger.+", // regex: /swagger/*
		EndpointSecurityConfigPerMethod: map[string]EndpointSecurityConfig{
			"GET": {NoAuthRequired: true},
		},
		MetricsEnabled: false,
	},
	{
		PathPattern: "\\/login$", // regex: /login
		EndpointSecurityConfigPerMethod: map[string]EndpointSecurityConfig{
			"POST": {NoAuthRequired: true},
		},
	},
}

func IsAuthRequired(path, method string) bool {
	for _, endpointConfig := range endpointsConfig {
		match, _ := regexp.MatchString(endpointConfig.PathPattern, strings.ToLower(path))
		if match {
			if endpointSecurityConfig, ok := endpointConfig.EndpointSecurityConfigPerMethod[strings.ToUpper(method)]; ok {
				return !endpointSecurityConfig.NoAuthRequired
			}
		}
	}

	return true
}

func AreMetricsEnabled(path string) bool {
	for _, endpointConfig := range endpointsConfig {
		match, _ := regexp.MatchString(endpointConfig.PathPattern, strings.ToLower(path))
		if match {
			return endpointConfig.MetricsEnabled
		}
	}

	return true
}
