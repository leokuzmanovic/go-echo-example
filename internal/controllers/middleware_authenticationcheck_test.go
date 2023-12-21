package controllers

/*
import (
	"global-auth-service/internal/config"
	"global-auth-service/internal/constants"
	"global-auth-service/internal/models"
	"global-auth-service/internal/services"
	"global-auth-service/internal/utils"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gofrs/uuid"
	"github.com/labstack/echo/v4"
	"github.com/stretchr/testify/assert"
	"gitlab.com/knowunity/go-common/pkg/auth"
	"gitlab.com/knowunity/go-common/pkg/errors"
)

func TestUnit_AuthenticationCheck_AuthorizeRequest(t *testing.T) {
	t.Run("bearer auth required - without 'Authorization'", func(t *testing.T) {
		nextInvoker := NewNextInvoker()
		tokensService := services.TokensServiceMock{}
		h := AuthMiddleware{tokensService: &tokensService}
		var echoHFunc = h.AuthorizeRequest(nextInvoker.Next)
		e := echo.New()
		req := httptest.NewRequest(http.MethodGet, "/some-path", nil)
		rec := httptest.NewRecorder()
		c := e.NewContext(req, rec)

		err := echoHFunc(c)

		assert.Equal(t, err.Error(), "AuthorizationError")
		assert.False(t, nextInvoker.WasNextInvoked)
		assert.False(t, tokensService.CheckAccountAuthenticationTokenCalled)
	})

	t.Run("service2service auth required - without 'Authorization'", func(t *testing.T) {
		nextInvoker := NewNextInvoker()
		tokensService := services.TokensServiceMock{}
		h := AuthMiddleware{tokensService: &tokensService}
		var echoHFunc = h.AuthorizeRequest(nextInvoker.Next)
		e := echo.New()
		req := httptest.NewRequest(http.MethodGet, "/some-path", nil)
		rec := httptest.NewRecorder()
		c := e.NewContext(req, rec)
		h.uriEndpointOptions = map[string]EndpointOptions{
			"GET /some-path": {NoUserAuthRequired: true, ServiceToServiceAuthRequired: true},
		}

		err := echoHFunc(c)

		assert.Equal(t, err.Error(), "AuthorizationError")
		assert.False(t, nextInvoker.WasNextInvoked)
		assert.False(t, tokensService.CheckAccountAuthenticationTokenCalled)
	})

	t.Run("bearer auth required - with service2service 'Authorization'", func(t *testing.T) {
		nextInvoker := NewNextInvoker()
		tokensService := services.TokensServiceMock{}
		h := AuthMiddleware{tokensService: &tokensService}
		var echoHFunc = h.AuthorizeRequest(nextInvoker.Next)
		e := echo.New()
		req := httptest.NewRequest(http.MethodGet, "/some-path", nil)
		rec := httptest.NewRecorder()
		c := e.NewContext(req, rec)
		c.Request().Header.Set("Authorization", constants.HeaderAuthorizationService2Service+" abcdefg1234567890")

		err := echoHFunc(c)

		assert.Equal(t, err.Error(), "AuthorizationError")
		assert.False(t, nextInvoker.WasNextInvoked)
		assert.False(t, tokensService.CheckAccountAuthenticationTokenCalled)
	})

	t.Run("service2service auth required - with bearer 'Authorization'", func(t *testing.T) {
		nextInvoker := NewNextInvoker()
		tokensService := services.TokensServiceMock{}
		h := AuthMiddleware{tokensService: &tokensService}
		var echoHFunc = h.AuthorizeRequest(nextInvoker.Next)
		e := echo.New()
		req := httptest.NewRequest(http.MethodGet, "/some-path", nil)
		rec := httptest.NewRecorder()
		c := e.NewContext(req, rec)
		c.Request().Header.Set("Authorization", constants.HeaderAuthorizationBearer+" abcdefg1234567890")
		h.uriEndpointOptions = map[string]EndpointOptions{
			"GET /some-path": {NoUserAuthRequired: true, ServiceToServiceAuthRequired: true},
		}
		err := echoHFunc(c)

		assert.Equal(t, err.Error(), "AuthorizationError")
		assert.False(t, nextInvoker.WasNextInvoked)
		assert.False(t, tokensService.CheckAccountAuthenticationTokenCalled)
	})

	t.Run("bearer auth required - with 'incorrect Authorization'", func(t *testing.T) {
		nextInvoker := NewNextInvoker()
		tokensService := services.TokensServiceMock{}
		h := AuthMiddleware{tokensService: &tokensService}

		var echoHFunc = h.AuthorizeRequest(nextInvoker.Next)

		assert.NotNil(t, echoHFunc)

		e := echo.New()
		req := httptest.NewRequest(http.MethodGet, "/some-path", nil)
		rec := httptest.NewRecorder()
		c := e.NewContext(req, rec)
		authToken := "some token"
		c.Request().Header.Set("Authorization", authToken)

		err := echoHFunc(c)

		assert.Equal(t, err.Error(), "AuthorizationError")
		assert.False(t, nextInvoker.WasNextInvoked)
		assert.False(t, tokensService.CheckAccountAuthenticationTokenCalled)
	})

	t.Run("service2service auth required - with 'incorrect Authorization'", func(t *testing.T) {
		nextInvoker := NewNextInvoker()
		tokensService := services.TokensServiceMock{}
		h := AuthMiddleware{tokensService: &tokensService}

		var echoHFunc = h.AuthorizeRequest(nextInvoker.Next)

		assert.NotNil(t, echoHFunc)

		e := echo.New()
		req := httptest.NewRequest(http.MethodGet, "/some-path", nil)
		rec := httptest.NewRecorder()
		c := e.NewContext(req, rec)
		authToken := "some token"
		c.Request().Header.Set("Authorization", authToken)
		h.uriEndpointOptions = map[string]EndpointOptions{
			"GET /some-path": {NoUserAuthRequired: true, ServiceToServiceAuthRequired: true},
		}

		err := echoHFunc(c)

		assert.Equal(t, err.Error(), "AuthorizationError")
		assert.False(t, nextInvoker.WasNextInvoked)
		assert.False(t, tokensService.CheckAccountAuthenticationTokenCalled)
	})

	t.Run("bearer auth required - with 'invalid jwt Authorization'", func(t *testing.T) {
		nextInvoker := NewNextInvoker()
		tokensService := &services.TokensServiceMock{}
		h := AuthMiddleware{tokensService: tokensService}

		var echoHFunc = h.AuthorizeRequest(nextInvoker.Next)

		assert.NotNil(t, echoHFunc)

		e := echo.New()
		req := httptest.NewRequest(http.MethodGet, "/some-path", nil)
		rec := httptest.NewRecorder()
		c := e.NewContext(req, rec)
		authToken := constants.HeaderAuthorizationBearer + " abcdefg1234567890"
		c.Request().Header.Set("Authorization", authToken)

		err := echoHFunc(c)

		assert.Equal(t, err.Error(), "AuthorizationError")
		assert.False(t, nextInvoker.WasNextInvoked)
		assert.True(t, tokensService.CheckAccountAuthenticationTokenCalled)
	})

	t.Run("bearer auth required - with 'unknown jwt Authorization'", func(t *testing.T) {
		nextInvoker := NewNextInvoker()
		tokensService := services.TokensServiceMock{
			CheckAccountAuthenticationTokenResult: services.CheckAccountAuthenticationTokenResult{
				Err: errors.New("db"),
			},
		}
		h := AuthMiddleware{tokensService: &tokensService}

		var echoHFunc = h.AuthorizeRequest(nextInvoker.Next)

		assert.NotNil(t, echoHFunc)

		e := echo.New()
		req := httptest.NewRequest(http.MethodGet, "/some-path", nil)
		rec := httptest.NewRecorder()
		c := e.NewContext(req, rec)
		authToken := getValidJWTTestTokenHeader()
		c.Request().Header.Set("Authorization", authToken)

		err := echoHFunc(c)

		assert.NotNil(t, err)
		assert.False(t, nextInvoker.WasNextInvoked)
		assert.True(t, tokensService.CheckAccountAuthenticationTokenCalled)
		assert.Equal(t, tokensService.ArgumentsSpyMap["tokenString"], strings.Replace(authToken, "Bearer ", "", 1))
	})

	t.Run("service2service auth required - with 'unknown Authorization token'", func(t *testing.T) {
		nextInvoker := NewNextInvoker()
		tokensService := services.TokensServiceMock{}
		h := AuthMiddleware{tokensService: &tokensService}

		var echoHFunc = h.AuthorizeRequest(nextInvoker.Next)

		assert.NotNil(t, echoHFunc)

		e := echo.New()
		req := httptest.NewRequest(http.MethodGet, "/some-path", nil)
		rec := httptest.NewRecorder()
		c := e.NewContext(req, rec)
		config.Secrets.Auth.Service2ServiceApiKey = "hijklmn0987654321"
		authToken := constants.HeaderAuthorizationService2Service + " abcdefg1234567890"
		c.Request().Header.Set("Authorization", authToken)
		h.uriEndpointOptions = map[string]EndpointOptions{
			"GET /some-path": {NoUserAuthRequired: true, ServiceToServiceAuthRequired: true},
		}

		err := echoHFunc(c)

		assert.Equal(t, err.Error(), "AuthorizationError")
		assert.False(t, nextInvoker.WasNextInvoked)
		assert.False(t, tokensService.CheckAccountAuthenticationTokenCalled)
	})

	t.Run("bearer auth required - with 'known jwt Authorization'", func(t *testing.T) {
		accountUUID, _ := uuid.NewV4()
		nextInvoker := NewNextInvoker()
		tokensService := services.TokensServiceMock{
			CheckAccountAuthenticationTokenResult: services.CheckAccountAuthenticationTokenResult{
				AccountUUID: accountUUID,
				Roles:       make([]string, 0),
				HasAdmin:    true,
			},
		}
		h := AuthMiddleware{tokensService: &tokensService}

		var echoHFunc = h.AuthorizeRequest(nextInvoker.Next)

		assert.NotNil(t, echoHFunc)

		e := echo.New()
		req := httptest.NewRequest(http.MethodGet, "/some-path", nil)
		rec := httptest.NewRecorder()
		c := e.NewContext(req, rec)

		authToken := getValidJWTTestTokenHeader()
		c.Request().Header.Set("Authorization", authToken)

		err := echoHFunc(c)

		assert.Nil(t, err)
		assert.True(t, nextInvoker.WasNextInvoked)
		assert.Equal(t, c.Get(utils.KeyAccountUUID), accountUUID)
		assert.True(t, tokensService.CheckAccountAuthenticationTokenCalled)
		assert.Equal(t, tokensService.ArgumentsSpyMap["tokenString"], strings.Replace(authToken, "Bearer ", "", 1))
		assert.Len(t, c.Get(utils.KeyAccountRoles), 0)
	})

	t.Run("service2service auth required - with 'known jwt Authorization'", func(t *testing.T) {
		nextInvoker := NewNextInvoker()
		tokensService := services.TokensServiceMock{}
		h := AuthMiddleware{tokensService: &tokensService}

		var echoHFunc = h.AuthorizeRequest(nextInvoker.Next)

		assert.NotNil(t, echoHFunc)

		e := echo.New()
		req := httptest.NewRequest(http.MethodGet, "/some-path", nil)
		rec := httptest.NewRecorder()
		c := e.NewContext(req, rec)
		authToken := "1234567890"
		config.Secrets.Auth.Service2ServiceApiKey = authToken
		c.Request().Header.Set("Authorization", constants.HeaderAuthorizationService2Service+" "+authToken)
		h.uriEndpointOptions = map[string]EndpointOptions{
			"GET /some-path": {NoUserAuthRequired: true, ServiceToServiceAuthRequired: true},
		}

		err := echoHFunc(c)

		assert.Nil(t, err)
		assert.True(t, nextInvoker.WasNextInvoked)
	})

	t.Run("auth not required", func(t *testing.T) {
		nextInvoker := NewNextInvoker()
		accountRepository := models.AccountRepositoryMock{}
		tokensService := services.TokensServiceMock{}
		h := AuthMiddleware{tokensService: &tokensService}
		h.uriEndpointOptions = map[string]EndpointOptions{
			"GET /some-path": {NoUserAuthRequired: true},
		}

		var echoHFunc = h.AuthorizeRequest(nextInvoker.Next)

		assert.NotNil(t, echoHFunc)

		e := echo.New()
		req := httptest.NewRequest(http.MethodGet, "/some-path", nil)
		rec := httptest.NewRecorder()
		c := e.NewContext(req, rec)

		err := echoHFunc(c)

		assert.Nil(t, err)
		assert.True(t, nextInvoker.WasNextInvoked)
		assert.False(t, accountRepository.ExistsByUUIDInvoked)
	})

	t.Run("endpoint to skip", func(t *testing.T) {
		nextInvoker := NewNextInvoker()
		accountRepository := models.AccountRepositoryMock{}
		tokensService := services.TokensServiceMock{}
		h := AuthMiddleware{tokensService: &tokensService}
		h.urisAndMethodToSkip = map[string]string{
			"/metrics": "GET",
		}

		var echoHFunc = h.AuthorizeRequest(nextInvoker.Next)

		assert.NotNil(t, echoHFunc)

		e := echo.New()
		req := httptest.NewRequest(http.MethodGet, "/metrics", nil)
		rec := httptest.NewRecorder()
		c := e.NewContext(req, rec)

		err := echoHFunc(c)

		assert.Nil(t, err)
		assert.True(t, nextInvoker.WasNextInvoked)
		assert.False(t, accountRepository.ExistsByUUIDInvoked)
	})

	t.Run("wildcard endpoint to skip", func(t *testing.T) {
		nextInvoker := NewNextInvoker()
		accountRepository := models.AccountRepositoryMock{}
		tokensService := services.TokensServiceMock{}
		h := AuthMiddleware{tokensService: &tokensService}
		h.wildcardUrisAndMethodToSkip = map[string]string{
			"/metrics/*": "GET",
		}

		var echoHFunc = h.AuthorizeRequest(nextInvoker.Next)

		assert.NotNil(t, echoHFunc)

		e := echo.New()
		req := httptest.NewRequest(http.MethodGet, "/metrics/bla", nil)
		rec := httptest.NewRecorder()
		c := e.NewContext(req, rec)

		err := echoHFunc(c)

		assert.Nil(t, err)
		assert.True(t, nextInvoker.WasNextInvoked)
		assert.False(t, accountRepository.ExistsByUUIDInvoked)
	})
}

func TestUnit_AuthenticationCheck_getUriEndpointOptions(t *testing.T) {
	t.Run("unregistered endpoint", func(t *testing.T) {
		h := AuthMiddleware{}

		h.uriEndpointOptions = map[string]EndpointOptions{
			"POST /some-endpoint": {NoUserAuthRequired: true},
		}
		endpointOptions := h.getUriEndpointOptions("POST", "/some-other-endpoint")
		assert.False(t, endpointOptions.NoUserAuthRequired)
	})

	t.Run("registered endpoint", func(t *testing.T) {
		h := AuthMiddleware{}

		h.uriEndpointOptions = map[string]EndpointOptions{
			"POST /some-endpoint": {NoUserAuthRequired: true},
		}
		endpointOptions := h.getUriEndpointOptions("POST", "/some-endpoint")
		assert.True(t, endpointOptions.NoUserAuthRequired)
	})

	t.Run("check all endpoint uri options", func(t *testing.T) {
		h := NewAuthenticationCheck(&services.TokensServiceMock{})
		testCases := []struct {
			method   string
			endpoint string
			want     EndpointOptions
		}{
			{"PATCH", constants.ENDPOINT_ACCOUNT_EMAIL, EndpointOptions{}},
			{"PATCH", constants.ENDPOINT_ACCOUNT_PASSWORD, EndpointOptions{}},
			{"POST", constants.ENDPOINT_ACCOUNT_RESENDCONFIRMATION, EndpointOptions{}},
			{"POST", constants.ENDPOINT_ACCOUNT_CONFIRMATION, EndpointOptions{NoUserAuthRequired: true}},
			{"PATCH", constants.ENDPOINT_ACCOUNT_ROLES, EndpointOptions{}},
			{"GET", constants.ENDPOINT_ACCOUNT_ROLES, EndpointOptions{}},
			{"DELETE", constants.ENDPOINT_ACCOUNT, EndpointOptions{}},
			{"POST", constants.ENDPOINT_ACCOUNT_ANONYMIZATION, EndpointOptions{ServiceToServiceAuthRequired: true}},

			{"POST", constants.ENDPOINT_AUTH_SIGNUP_EMAIL, EndpointOptions{NoUserAuthRequired: true, ServiceToServiceAuthRequired: false}},
			{"POST", constants.ENDPOINT_AUTH_SIGNUP_GOOGLE, EndpointOptions{NoUserAuthRequired: true, ServiceToServiceAuthRequired: false}},
			{"POST", constants.ENDPOINT_AUTH_SIGNUP_APPLE, EndpointOptions{NoUserAuthRequired: true, ServiceToServiceAuthRequired: false}},
			{"POST", constants.ENDPOINT_AUTH_SIGNIN_EMAIL, EndpointOptions{NoUserAuthRequired: true, ServiceToServiceAuthRequired: false}},
			{"POST", constants.ENDPOINT_AUTH_SIGNIN_GOOGLE, EndpointOptions{NoUserAuthRequired: true, ServiceToServiceAuthRequired: false}},
			{"POST", constants.ENDPOINT_AUTH_SIGNIN_APPLE, EndpointOptions{NoUserAuthRequired: true, ServiceToServiceAuthRequired: false}},
			{"POST", constants.ENDPOINT_AUTH_PASSWORD_RESET, EndpointOptions{NoUserAuthRequired: true, ServiceToServiceAuthRequired: false}},
			{"POST", constants.ENDPOINT_AUTH_PASSWORD_RESET_CONFIRM, EndpointOptions{NoUserAuthRequired: true, ServiceToServiceAuthRequired: false}},

			{"GET", constants.ENDPOINT_HEALTH, EndpointOptions{}},

			{"POST", constants.ENDPOINT_OAUTH_TOKEN, EndpointOptions{NoUserAuthRequired: true}},
			{"POST", constants.ENDPOINT_OAUTH_LOGOUT, EndpointOptions{}},

			{"GET", "/metrics", EndpointOptions{}},
			{"GET", "/swagger/*", EndpointOptions{}},
		}
		for _, tc := range testCases {
			endpointOptions := h.getUriEndpointOptions(tc.method, tc.endpoint)
			assert.Equal(t, tc.want, endpointOptions)
		}
	})
}

func TestUnit_AuthenticationCheck_shouldSkip(t *testing.T) {
	t.Run("uri and method to skip", func(t *testing.T) {
		h := AuthMiddleware{}

		h.urisAndMethodToSkip = map[string]string{
			"/metrics": "GET",
		}
		assert.True(t, h.shouldSkip("/metrics", "GET"))
	})

	t.Run("uri to skip, method not to skip", func(t *testing.T) {
		h := AuthMiddleware{}

		h.urisAndMethodToSkip = map[string]string{
			"/metrics": "GET",
		}
		assert.False(t, h.shouldSkip("/metrics", "POST"))
	})

	t.Run("uri not to skip, method to skip", func(t *testing.T) {
		h := AuthMiddleware{}

		h.urisAndMethodToSkip = map[string]string{
			"/metrics": "GET",
		}
		assert.False(t, h.shouldSkip("/bla", "GET"))
	})

	t.Run("uri and method not to skip", func(t *testing.T) {
		h := AuthMiddleware{}

		h.urisAndMethodToSkip = map[string]string{
			"/metrics": "GET",
		}
		assert.False(t, h.shouldSkip("/bla", "POST"))
	})
}

func getValidJWTTestTokenHeader() string {
	claims := &auth.AccessTokenClaims{}
	accessToken, _ := (&services.AccessTokenGeneratorWithHS512{JWTSecret: []byte("test secret")}).GenerateAccessToken(claims)

	authTokenHeader := constants.HeaderAuthorizationBearer + " " + accessToken
	return authTokenHeader
}
*/
