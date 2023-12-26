package errors

import (
	"errors"
	"net/http"
	"testing"

	"github.com/labstack/echo/v4"
	"github.com/stretchr/testify/assert"
)

func TestUnit_GlobalErrorHandler(t *testing.T) {
	t.Run("general error", func(t *testing.T) {
		err := errors.New("error details")
		code, message, errorType := getErrorDetails(err)
		assert.Equal(t, http.StatusInternalServerError, code)
		assert.Equal(t, "Internal Server Error", message)
		assert.Equal(t, "InternalServerError", errorType)
	})

	t.Run("app error", func(t *testing.T) {
		err := AppError(InvalidJsonError{})
		code, message, errorType := getErrorDetails(err)
		assert.Equal(t, http.StatusBadRequest, code)
		assert.Equal(t, "Invalid JSON", message)
		assert.Equal(t, "InvalidJsonError", errorType)
	})

	t.Run("http error", func(t *testing.T) {
		err := &echo.HTTPError{Code: http.StatusBadRequest, Message: "Invalid JSON"}
		code, message, errorType := getErrorDetails(err)
		assert.Equal(t, http.StatusBadRequest, code)
		assert.Equal(t, "Invalid JSON", message)
		assert.Equal(t, "Bad Request", errorType)
	})
}
