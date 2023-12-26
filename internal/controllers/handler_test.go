package controllers

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/labstack/echo/v4"
	"github.com/leokuzmanovic/go-echo-example/api"
	errs "github.com/leokuzmanovic/go-echo-example/internal/errors"
	"github.com/pkg/errors"
	"github.com/stretchr/testify/assert"
)

func TestUnit_Helpers_withValidJsonBody(t *testing.T) {
	t.Run("handler function is returned", func(t *testing.T) {
		var hFunc = func(ctx echo.Context, body *api.AuthLoginRequest) error {
			return nil
		}
		var echoHFunc = withValidJsonBody(hFunc)

		assert.NotNil(t, echoHFunc)
	})
}

func TestUnit_Helpers_handlerWithJsonBodyFunction(t *testing.T) {
	t.Run("parse pointer body", func(t *testing.T) {
		username := "username"
		password := "password"
		parsedCorrectly := false
		var hFunc = func(ctx echo.Context, body *api.AuthLoginRequest) error {
			if body.Username == username && body.Password == password {
				parsedCorrectly = true
			}
			return nil
		}

		performBindingTest(username, password, hFunc, t, &parsedCorrectly)
	})

	t.Run("parse non pointer body", func(t *testing.T) {
		parsedCorrectly := false
		username := "username"
		password := "password"
		var hFunc = func(ctx echo.Context, body api.AuthLoginRequest) error {
			if body.Username == username && body.Password == password {
				parsedCorrectly = true
			}
			return nil
		}

		performBindingTest(username, password, hFunc, t, &parsedCorrectly)
	})

	t.Run("wrong body", func(t *testing.T) {
		handlerInvoked := false
		var hFunc = func(ctx echo.Context, body *api.AuthLoginRequest) error {
			handlerInvoked = true
			return nil
		}

		e := echo.New()
		req := httptest.NewRequest(http.MethodPost, api.ENDPOINT_AUTH_LOGIN, strings.NewReader(`{"a": "b"}`))
		rec := httptest.NewRecorder()
		c := e.NewContext(req, rec)

		err := handlerWithJsonBodyFunction(c, hFunc)
		assert.False(t, handlerInvoked)
		assert.True(t, errors.Is(err, errs.InvalidJsonError{}))
	})

	t.Run("nil body", func(t *testing.T) {
		handlerInvoked := false
		var hFunc = func(ctx echo.Context, body *api.AuthLoginRequest) error {
			handlerInvoked = true
			return nil
		}

		e := echo.New()
		req := httptest.NewRequest(http.MethodPost, api.ENDPOINT_AUTH_LOGIN, nil)
		rec := httptest.NewRecorder()
		c := e.NewContext(req, rec)

		err := handlerWithJsonBodyFunction(c, hFunc)

		assert.False(t, handlerInvoked)
		assert.True(t, errors.Is(err, errs.InvalidJsonError{}))
	})

}

func performBindingTest[T any](username string, password string, hFunc func(ctx echo.Context, body T) error, t *testing.T, parsedCorrectly *bool) {
	e := echo.New()
	req := httptest.NewRequest(http.MethodPost, api.ENDPOINT_AUTH_LOGIN, strings.NewReader(`{"username": "`+username+`", "password": "`+password+`"}`))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	c := e.NewContext(req, rec)

	err := handlerWithJsonBodyFunction(c, hFunc)
	assert.True(t, *parsedCorrectly)
	assert.Nil(t, err)
}
