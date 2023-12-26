package configuration

import (
	"regexp"
	"strings"
)

type EndpointConfig struct {
	PathPattern                     string
	EndpointSecurityConfigPerMethod map[string]EndpointSecurityConfig
	MetricsDisabled                 bool
}

type EndpointSecurityConfig struct {
	NoAuthRequired bool // by default, auth is required (false)
}

//go:generate mockery --name EndpointsConfigService
type EndpointsConfigService interface {
	IsAuthRequired(path, method string) bool
	AreMetricsEnabled(path string) bool
}

type EndpointsConfigServiceImpl struct{}

func NewEndpointsConfigService() *EndpointsConfigServiceImpl {
	return &EndpointsConfigServiceImpl{}
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
		MetricsDisabled: true,
	},
	{
		PathPattern: "\\/swagger.+", // regex: /swagger/*
		EndpointSecurityConfigPerMethod: map[string]EndpointSecurityConfig{
			"GET": {NoAuthRequired: true}, // swagger has its own basic auth by default
		},
		MetricsDisabled: true,
	},
	{
		PathPattern: "\\/swagger", // regex: /swagger/*
		EndpointSecurityConfigPerMethod: map[string]EndpointSecurityConfig{
			"GET": {NoAuthRequired: true}, // swagger has its own basic auth by default
		},
		MetricsDisabled: true,
	},
	{
		PathPattern: "\\/auth\\/login$", // regex: /auth/login
		EndpointSecurityConfigPerMethod: map[string]EndpointSecurityConfig{
			"POST": {NoAuthRequired: true},
		},
	},
	{
		PathPattern: "\\/auth\\/token$", // regex: /auth/token
		EndpointSecurityConfigPerMethod: map[string]EndpointSecurityConfig{
			"POST": {NoAuthRequired: true},
		},
	},
}

func (s *EndpointsConfigServiceImpl) IsAuthRequired(path, method string) bool {
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

func (s *EndpointsConfigServiceImpl) AreMetricsEnabled(path string) bool {
	for _, endpointConfig := range endpointsConfig {
		match, _ := regexp.MatchString(endpointConfig.PathPattern, strings.ToLower(path))
		if match {
			return !endpointConfig.MetricsDisabled
		}
	}

	return true
}
