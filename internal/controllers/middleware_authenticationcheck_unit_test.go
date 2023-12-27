package controllers

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gofrs/uuid"
	"github.com/labstack/echo/v4"
	configMocks "github.com/leokuzmanovic/go-echo-example/internal/configuration/mocks"
	"github.com/leokuzmanovic/go-echo-example/internal/services/mocks"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

func TestUnit_AuthenticationCheck_CheckRequestAuthentication(t *testing.T) {
	t.Run("no header", func(t *testing.T) {
		nextInvoker := NewNextInvoker()
		tokensServiceMock := mocks.NewTokensService(t)
		endpointsConfigServiceMock := configMocks.NewEndpointsConfigService(t)
		endpointsConfigServiceMock.On("IsAuthRequired", mock.Anything, mock.Anything).Return(true)
		h := AuthMiddleware{tokensService: tokensServiceMock, endpointsConfigService: endpointsConfigServiceMock}
		var echoHFunc = h.CheckRequestAuthentication(nextInvoker.Next)
		e := echo.New()
		req := httptest.NewRequest(http.MethodGet, "/some-path", nil)
		rec := httptest.NewRecorder()
		c := e.NewContext(req, rec)

		err := echoHFunc(c)

		assert.Error(t, err)
		assert.False(t, nextInvoker.WasNextInvoked)
		tokensServiceMock.AssertNumberOfCalls(t, "CheckToken", 0)
	})

	t.Run("incorrect 'Authorization'", func(t *testing.T) {
		nextInvoker := NewNextInvoker()
		tokensServiceMock := mocks.NewTokensService(t)
		endpointsConfigServiceMock := configMocks.NewEndpointsConfigService(t)
		endpointsConfigServiceMock.On("IsAuthRequired", mock.Anything, mock.Anything).Return(true)
		h := AuthMiddleware{tokensService: tokensServiceMock, endpointsConfigService: endpointsConfigServiceMock}
		var echoHFunc = h.CheckRequestAuthentication(nextInvoker.Next)
		e := echo.New()
		req := httptest.NewRequest(http.MethodGet, "/some-path", nil)
		rec := httptest.NewRecorder()
		c := e.NewContext(req, rec)
		c.Request().Header.Set("Authorization", "TypeABC abcdefg1234567890")

		err := echoHFunc(c)

		assert.Error(t, err)
		assert.False(t, nextInvoker.WasNextInvoked)
		tokensServiceMock.AssertNumberOfCalls(t, "CheckToken", 0)
	})

	t.Run("expired token", func(t *testing.T) {
		userId, _ := uuid.NewV4()
		nextInvoker := NewNextInvoker()
		tokensServiceMock := mocks.NewTokensService(t)
		tokensServiceMock.On("CheckToken", mock.Anything, mock.Anything).Return(userId, false, nil)
		endpointsConfigServiceMock := configMocks.NewEndpointsConfigService(t)
		endpointsConfigServiceMock.On("IsAuthRequired", mock.Anything, mock.Anything).Return(true)
		h := AuthMiddleware{tokensService: tokensServiceMock, endpointsConfigService: endpointsConfigServiceMock}

		var echoHFunc = h.CheckRequestAuthentication(nextInvoker.Next)

		assert.NotNil(t, echoHFunc)

		e := echo.New()
		req := httptest.NewRequest(http.MethodGet, "/some-path", nil)
		rec := httptest.NewRecorder()
		c := e.NewContext(req, rec)
		authToken := HeaderAuthorizationBearer + " abcdefg1234567890"
		c.Request().Header.Set("Authorization", authToken)

		err := echoHFunc(c)

		assert.Error(t, err)
		assert.False(t, nextInvoker.WasNextInvoked)
		tokensServiceMock.AssertNumberOfCalls(t, "CheckToken", 1)
	})

	t.Run("error checking token", func(t *testing.T) {
		userId, _ := uuid.NewV4()
		nextInvoker := NewNextInvoker()
		tokensServiceMock := mocks.NewTokensService(t)
		tokensServiceMock.On("CheckToken", mock.Anything, mock.Anything).Return(userId, false, errors.New("some error"))
		endpointsConfigServiceMock := configMocks.NewEndpointsConfigService(t)
		endpointsConfigServiceMock.On("IsAuthRequired", mock.Anything, mock.Anything).Return(true)
		h := AuthMiddleware{tokensService: tokensServiceMock, endpointsConfigService: endpointsConfigServiceMock}

		var echoHFunc = h.CheckRequestAuthentication(nextInvoker.Next)

		assert.NotNil(t, echoHFunc)

		e := echo.New()
		req := httptest.NewRequest(http.MethodGet, "/some-path", nil)
		rec := httptest.NewRecorder()
		c := e.NewContext(req, rec)
		authToken := HeaderAuthorizationBearer + " abcdefg1234567890"
		c.Request().Header.Set("Authorization", authToken)

		err := echoHFunc(c)

		assert.Error(t, err)
		assert.False(t, nextInvoker.WasNextInvoked)
		tokensServiceMock.AssertNumberOfCalls(t, "CheckToken", 1)
	})

	t.Run("with correct authorization'", func(t *testing.T) {
		userId, _ := uuid.NewV4()
		nextInvoker := NewNextInvoker()
		tokensServiceMock := mocks.NewTokensService(t)
		tokensServiceMock.On("CheckToken", mock.Anything, mock.Anything).Return(userId, true, nil)
		endpointsConfigServiceMock := configMocks.NewEndpointsConfigService(t)
		endpointsConfigServiceMock.On("IsAuthRequired", mock.Anything, mock.Anything).Return(true)
		h := AuthMiddleware{tokensService: tokensServiceMock, endpointsConfigService: endpointsConfigServiceMock}

		var echoHFunc = h.CheckRequestAuthentication(nextInvoker.Next)

		assert.NotNil(t, echoHFunc)

		e := echo.New()
		req := httptest.NewRequest(http.MethodGet, "/some-path", nil)
		rec := httptest.NewRecorder()
		c := e.NewContext(req, rec)
		authToken := HeaderAuthorizationBearer + " abcdefg1234567890"
		c.Request().Header.Set("Authorization", authToken)

		err := echoHFunc(c)

		assert.NoError(t, err)
		assert.True(t, nextInvoker.WasNextInvoked)
		tokensServiceMock.AssertNumberOfCalls(t, "CheckToken", 1)
	})

	t.Run("auth not required", func(t *testing.T) {
		nextInvoker := NewNextInvoker()
		tokensServiceMock := mocks.NewTokensService(t)
		endpointsConfigServiceMock := configMocks.NewEndpointsConfigService(t)
		endpointsConfigServiceMock.On("IsAuthRequired", mock.Anything, mock.Anything).Return(false)
		h := AuthMiddleware{tokensService: tokensServiceMock, endpointsConfigService: endpointsConfigServiceMock}

		var echoHFunc = h.CheckRequestAuthentication(nextInvoker.Next)

		assert.NotNil(t, echoHFunc)

		e := echo.New()
		req := httptest.NewRequest(http.MethodGet, "/some-path", nil)
		rec := httptest.NewRecorder()
		c := e.NewContext(req, rec)

		err := echoHFunc(c)

		assert.Nil(t, err)
		assert.True(t, nextInvoker.WasNextInvoked)
		tokensServiceMock.AssertNumberOfCalls(t, "CheckToken", 0)
	})
}
