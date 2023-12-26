package utils

import (
	"crypto/subtle"
	"encoding/json"
	"io"
	"strings"

	"github.com/labstack/echo/v4"
	"github.com/labstack/echo/v4/middleware"
	errs "github.com/leokuzmanovic/go-echo-example/internal/errors"
)

func PrepareBasicAuthenticationMiddleware(username, password string) echo.MiddlewareFunc {
	middlewareFunc := middleware.BasicAuth(func(username, password string, c echo.Context) (bool, error) {
		usernameMatches := subtle.ConstantTimeCompare([]byte(username), []byte(username)) == 1
		passwordMatches := subtle.ConstantTimeCompare([]byte(password), []byte(password)) == 1
		return usernameMatches && passwordMatches, nil
	})
	return middlewareFunc
}

func SanitizeUri(uri string) string {
	sanitizedUri := strings.ToLower(uri)
	if len(sanitizedUri) > 1 {
		sanitizedUri = strings.TrimSuffix(sanitizedUri, "/")
	}

	return sanitizedUri
}

func ParseJSON(body io.Reader, v interface{}) error {
	err := json.NewDecoder(body).Decode(&v)
	if err != nil {
		return &errs.InvalidJsonError{}
	}
	return nil
}
