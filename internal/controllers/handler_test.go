package controllers

/*
import (
	"global-auth-service/internal/apierrors"
	"global-auth-service/internal/constants"
	"global-auth-service/internal/views"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/labstack/echo/v4"
	"github.com/stretchr/testify/assert"
	"gitlab.com/knowunity/go-common/pkg/errors"
)

func TestUnit_Helpers_withValidatedBody(t *testing.T) {
	t.Run("returns an echo handler function", func(t *testing.T) {
		var hFunc = func(ctx echo.Context, body *views.AuthSignUpEmailRequest) error {
			return nil
		}
		var echoHFunc = withValidatedBody(hFunc)

		assert.NotNil(t, echoHFunc)
	})
}

func TestUnit_Helpers_withOptionallyValidatedBody(t *testing.T) {
	t.Run("returns an echo handler function", func(t *testing.T) {
		var hFunc = func(ctx echo.Context, body *views.AuthSignUpEmailRequest) error {
			return nil
		}
		var echoHFunc1 = withOptionallyValidatedBody(hFunc, true)
		var echoHFunc2 = withOptionallyValidatedBody(hFunc, false)

		assert.NotNil(t, echoHFunc1)
		assert.NotNil(t, echoHFunc2)
	})
}

func TestUnit_Helpers_handlerFunctionInvoker(t *testing.T) {
	t.Run("cannot parse nil body", func(t *testing.T) {
		handlerInvoked := false
		var hFunc = func(ctx echo.Context, body *views.AuthSignUpEmailRequest) error {
			handlerInvoked = true
			return nil
		}

		e := echo.New()
		req := httptest.NewRequest(http.MethodPost, constants.ENDPOINT_AUTH_SIGNUP_EMAIL, nil)
		rec := httptest.NewRecorder()
		c := e.NewContext(req, rec)

		err := handlerFunctionInvoker(c, true, hFunc)

		assert.False(t, handlerInvoked)
		assert.True(t, errors.Is(err, &apierrors.InvalidJSONPayloadError{}))
	})

	t.Run("bad body - no validation", func(t *testing.T) {
		var parsedCorrectly = true
		var hFunc = func(ctx echo.Context, body *views.AuthSignUpEmailRequest) error {
			if body.Email == "" && body.Password == "" {
				parsedCorrectly = false
			}
			return nil
		}

		e := echo.New()
		req := httptest.NewRequest(http.MethodPost, constants.ENDPOINT_AUTH_SIGNUP_EMAIL, strings.NewReader(AuthSignUpGoogleRequestJSON))
		rec := httptest.NewRecorder()
		c := e.NewContext(req, rec)

		err := handlerFunctionInvoker(c, false, hFunc)
		assert.False(t, parsedCorrectly)
		assert.Nil(t, err)
	})

	t.Run("bad body - with validation", func(t *testing.T) {
		handlerInvoked := false
		var hFunc = func(ctx echo.Context, body *views.AuthSignUpEmailRequest) error {
			handlerInvoked = true
			return nil
		}

		e := echo.New()
		req := httptest.NewRequest(http.MethodPost, constants.ENDPOINT_AUTH_SIGNUP_EMAIL, strings.NewReader(AuthSignUpGoogleRequestJSON))
		rec := httptest.NewRecorder()
		c := e.NewContext(req, rec)

		err := handlerFunctionInvoker(c, true, hFunc)
		assert.False(t, handlerInvoked)
		assert.NotNil(t, err)
	})

	t.Run("parse body - no validation", func(t *testing.T) {
		parsedCorrectly := false
		var hFunc = func(ctx echo.Context, body *views.AuthSignUpEmailRequest) error {
			if body.Email != "" && body.Password != "" {
				parsedCorrectly = true
			}
			return nil
		}

		e := echo.New()
		req := httptest.NewRequest(http.MethodPost, constants.ENDPOINT_AUTH_SIGNUP_EMAIL, strings.NewReader(AuthSignUpEmailRequestJSON))
		rec := httptest.NewRecorder()
		c := e.NewContext(req, rec)

		err := handlerFunctionInvoker(c, false, hFunc)
		assert.True(t, parsedCorrectly)
		assert.Nil(t, err)
	})

	t.Run("parse body - with validation", func(t *testing.T) {
		parsedCorrectly := false
		var hFunc = func(ctx echo.Context, body *views.AuthSignUpEmailRequest) error {
			if body.Email != "" && body.Password != "" {
				parsedCorrectly = true
			}
			return nil
		}

		e := echo.New()
		req := httptest.NewRequest(http.MethodPost, constants.ENDPOINT_AUTH_SIGNUP_EMAIL, strings.NewReader(AuthSignUpEmailRequestJSON))
		rec := httptest.NewRecorder()
		c := e.NewContext(req, rec)

		err := handlerFunctionInvoker(c, true, hFunc)
		assert.True(t, parsedCorrectly)
		assert.Nil(t, err)
	})

	t.Run("parse non pointer body - with validation", func(t *testing.T) {
		parsedCorrectly := false
		var hFunc = func(ctx echo.Context, body views.AuthSignUpEmailRequest) error {
			if body.Email != "" && body.Password != "" {
				parsedCorrectly = true
			}
			return nil
		}

		e := echo.New()
		req := httptest.NewRequest(http.MethodPost, constants.ENDPOINT_AUTH_SIGNUP_EMAIL, strings.NewReader(AuthSignUpEmailRequestJSON))
		rec := httptest.NewRecorder()
		c := e.NewContext(req, rec)

		err := handlerFunctionInvoker(c, true, hFunc)
		assert.True(t, parsedCorrectly)
		assert.Nil(t, err)
	})
}

func TestUnit_Helpers_getBotDetectionData(t *testing.T) {
	t.Run("headers not set", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPost, constants.ENDPOINT_AUTH_SIGNUP_EMAIL, nil)

		botDetectionData := GetBotDetectionData(req)

		assert.False(t, botDetectionData.Disable)
		assert.False(t, botDetectionData.IPCountryCode.Valid)
		assert.Equal(t, "", botDetectionData.IPAddress)
		assert.False(t, botDetectionData.HCaptchaToken.Valid)
	})

	t.Run("headers set - HeaderXFrontendE2ETesting true", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPost, constants.ENDPOINT_AUTH_SIGNUP_EMAIL, nil)
		// #nosec G101 -- This is not a hard-coded secret
		headerHCaptchaToken := "some headerHCaptchaToken"
		headerCloudflareIPCountry := "some headerCloudflareIPCountry"
		headerCloudflareConnectingIP := "192.168.1.100"
		req.Header.Set(constants.HeaderHCaptchaToken, headerHCaptchaToken)
		req.Header.Set(constants.HeaderCloudflareIPCountry, headerCloudflareIPCountry)
		req.Header.Set(constants.HeaderXFrontendE2ETesting, "true")
		req.Header.Set(constants.HeaderCloudflareConnectingIP, headerCloudflareConnectingIP)

		botDetectionData := GetBotDetectionData(req)

		assert.True(t, botDetectionData.Disable)
		assert.Equal(t, headerCloudflareIPCountry, botDetectionData.IPCountryCode.String)
		assert.Equal(t, headerCloudflareConnectingIP, botDetectionData.IPAddress)
		assert.Equal(t, headerHCaptchaToken, botDetectionData.HCaptchaToken.String)
	})

	t.Run("headers set - HeaderXFrontendE2ETesting false", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPost, constants.ENDPOINT_AUTH_SIGNUP_EMAIL, nil)
		headerHCaptchaToken := "some token"
		headerCloudflareIPCountry := "some ip country"
		headerCloudflareConnectingIP := "192.168.1.100"
		req.Header.Set(constants.HeaderHCaptchaToken, headerHCaptchaToken)
		req.Header.Set(constants.HeaderCloudflareIPCountry, headerCloudflareIPCountry)
		req.Header.Set(constants.HeaderXFrontendE2ETesting, "false")
		req.Header.Set(constants.HeaderCloudflareConnectingIP, headerCloudflareConnectingIP)

		botDetectionData := GetBotDetectionData(req)

		assert.False(t, botDetectionData.Disable)
		assert.Equal(t, headerCloudflareIPCountry, botDetectionData.IPCountryCode.String)
		assert.Equal(t, headerCloudflareConnectingIP, botDetectionData.IPAddress)
		assert.Equal(t, headerHCaptchaToken, botDetectionData.HCaptchaToken.String)
	})
}
*/
