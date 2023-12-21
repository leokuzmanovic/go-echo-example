package errors

import (
	"errors"
	"net/http"

	"github.com/labstack/echo/v4"
)

func GlobalErrorHandler(err error, c echo.Context) {
	code := http.StatusInternalServerError
	message := "Internal Server Error"
	errorType := "InternalServerError"

	var appErr AppError
	if ok := errors.As(err, &appErr); ok {
		errorData := appErr.GetErrorData()
		code = errorData.Code
		message = errorData.Message
		errorType = errorData.Type
	} else if httpError, ok := err.(*echo.HTTPError); ok {
		code = httpError.Code
		message = httpError.Message.(string)
		errorType = http.StatusText(code)
	} else {
		// log error message taken from "err.Error()" but do not expose internal errors to the client
	}

	_ = c.JSON(code, map[string]interface{}{
		"message": message,
		"type":    errorType,
	})
}

type ErrorData struct {
	Code    int    `json:"code"`
	Type    string `json:"type"`
	Message string `json:"message,omitempty"`
}

type AppError interface {
	Error() string
	GetErrorData() ErrorData
}

type InvalidJsonError struct{}

func (s InvalidJsonError) Error() string {
	return "InvalidJsonError"
}

func (s InvalidJsonError) GetErrorData() ErrorData {
	return ErrorData{Type: "InvalidJsonError", Code: http.StatusBadRequest, Message: "Invalid JSON"}
}

type DublicatedEntityError struct{}

func (s DublicatedEntityError) Error() string {
	return "Conflic"
}

func (s DublicatedEntityError) GetErrorData() ErrorData {
	return ErrorData{Type: "Conflic", Code: http.StatusConflict, Message: "Entity already exists"}
}

type AuthorizationError struct {
}

func (s AuthorizationError) Error() string {
	return "AuthorizationError"
}

func (s AuthorizationError) GetErrorData() ErrorData {
	return ErrorData{Type: "AuthorizationError", Code: http.StatusUnauthorized, Message: "Invalid authorization token"}
}

type BadRequestError struct {
}

func (s BadRequestError) Error() string {
	return "BadRequestError"
}

func (s BadRequestError) GetErrorData() ErrorData {
	return ErrorData{Type: "BadRequestError", Code: http.StatusBadRequest, Message: "Invalid request"}
}

type NotFoundError struct {
}

func (s NotFoundError) Error() string {
	return "NotFoundError"
}

func (s NotFoundError) GetErrorData() ErrorData {
	return ErrorData{Type: "NotFoundError", Code: http.StatusNotFound, Message: "Not found"}
}

type InvalidCredentialsError struct{}

func (s InvalidCredentialsError) Error() string {
	return "InvalidCredentialsError"
}

func (s InvalidCredentialsError) GetErrorData() ErrorData {
	return ErrorData{
		Type:    "InvalidCredentialsError",
		Code:    http.StatusBadRequest,
		Message: "Invalid credentials",
	}
}
