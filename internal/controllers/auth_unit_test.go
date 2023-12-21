package controllers

/*
import (
	"fmt"
	"global-auth-service/internal/apierrors"
	"global-auth-service/internal/constants"
	"global-auth-service/internal/services"
	"global-auth-service/internal/utils"
	"global-auth-service/internal/views"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gofrs/uuid"
	"github.com/labstack/echo/v4"
	_ "github.com/lib/pq"
	"github.com/stretchr/testify/assert"
	"gitlab.com/knowunity/go-common/pkg/errors"
	"gopkg.in/guregu/null.v4"
)

func TestUnit_AuthController_signUpUsername(t *testing.T) {
	var body views.AuthSignUpUsernameRequest
	_ = ParseJSON(strings.NewReader(AuthSignUpUsernameRequestJSON), &body)

	t.Run("signup username processing fails - controller returns error", func(t *testing.T) {
		// Setup
		e := echo.New()
		req := httptest.NewRequest(http.MethodPost, constants.ENDPOINT_AUTH_SIGNUP_USERNAME, nil)
		rec := httptest.NewRecorder()
		c := e.NewContext(req, rec)
		authService := createTestAuthServiceForSignUpWithErrors(nil, nil, nil, &apierrors.InternalServerError{})
		tokensService := &services.TokensServiceMock{}
		h := AuthController{
			authService,
			&services.PasswordResetServiceMock{},
			&services.TokensServiceMock{},
		}

		// Assertions
		err := h.signUpUsername(c, &body)
		assert.False(t, tokensService.GetOauthTokensForAccountCalled)
		verifySignUpUsernameArguments(t, authService.ArgumentsSpyMap, body)
		assert.True(t, errors.Is(err, &apierrors.InternalServerError{}))
	})

	t.Run("retrieving auth tokens fails - controller returns error", func(t *testing.T) {
		// Setup
		e := echo.New()
		req := httptest.NewRequest(http.MethodPost, constants.ENDPOINT_AUTH_SIGNUP_USERNAME, nil)
		rec := httptest.NewRecorder()
		c := e.NewContext(req, rec)
		authService := createTestAuthServiceForSignUpWithErrors(nil, nil, nil, nil)
		tokensService := &services.TokensServiceMock{
			GetOauthTokensForAccountResult: services.GetOauthTokensResult{
				Err: &apierrors.InternalServerError{},
			},
		}
		h := AuthController{
			authService,
			&services.PasswordResetServiceMock{},
			tokensService,
		}

		// Assertions
		err := h.signUpUsername(c, &body)
		verifySignUpUsernameArguments(t, authService.ArgumentsSpyMap, body)
		assert.True(t, errors.Is(err, &apierrors.InternalServerError{}))
	})

	t.Run("signup with username successful", func(t *testing.T) {
		// Setup
		accessToken := null.StringFrom("abc123")
		refreshToken := null.StringFrom("def456")
		e := echo.New()
		req := httptest.NewRequest(http.MethodPost, constants.ENDPOINT_AUTH_SIGNUP_USERNAME, nil)
		rec := httptest.NewRecorder()
		c := e.NewContext(req, rec)
		authService := createTestAuthServiceWithTokenResponse(accessToken, refreshToken)
		tokensService := &services.TokensServiceMock{
			GetOauthTokensForAccountResult: services.GetOauthTokensResult{
				AccessToken: accessToken, RefreshToken: refreshToken, Err: nil,
			},
		}
		h := AuthController{
			authService,
			&services.PasswordResetServiceMock{},
			tokensService,
		}

		// Assertions
		if assert.NoError(t, h.signUpUsername(c, &body)) {
			assert.Equal(t, http.StatusCreated, rec.Code)
			verifySignUpUsernameArguments(t, authService.ArgumentsSpyMap, body)
			assert.Contains(t, rec.Body.String(), fmt.Sprintf("\"accessToken\":\"%s\"", accessToken.String))
			assert.Contains(t, rec.Body.String(), fmt.Sprintf("\"refreshToken\":\"%s\"", refreshToken.String))
		}
	})
}

func TestUnit_AuthController_signUpEmail(t *testing.T) {
	var body views.AuthSignUpEmailRequest
	_ = ParseJSON(strings.NewReader(AuthSignUpEmailRequestJSON), &body)

	t.Run("signup email processing fails - controller returns error", func(t *testing.T) {
		// Setup
		e := echo.New()
		req := httptest.NewRequest(http.MethodPost, constants.ENDPOINT_AUTH_SIGNUP_EMAIL, nil)
		rec := httptest.NewRecorder()
		c := e.NewContext(req, rec)
		authService := createTestAuthServiceForSignUpWithErrors(&apierrors.InternalServerError{}, nil, nil, nil)
		tokensService := &services.TokensServiceMock{}
		h := AuthController{
			authService,
			&services.PasswordResetServiceMock{},
			&services.TokensServiceMock{},
		}

		// Assertions
		err := h.signUpEmail(c, &body)
		assert.False(t, tokensService.GetOauthTokensForAccountCalled)
		verifySignUpEmailArguments(t, authService.ArgumentsSpyMap, body)
		assert.True(t, errors.Is(err, &apierrors.InternalServerError{}))
	})

	t.Run("retrieving auth tokens fails - controller returns error", func(t *testing.T) {
		// Setup
		e := echo.New()
		req := httptest.NewRequest(http.MethodPost, constants.ENDPOINT_AUTH_SIGNUP_EMAIL, nil)
		rec := httptest.NewRecorder()
		c := e.NewContext(req, rec)
		authService := createTestAuthServiceForSignUpWithErrors(nil, nil, nil, &apierrors.InternalServerError{})
		tokensService := &services.TokensServiceMock{
			GetOauthTokensForAccountResult: services.GetOauthTokensResult{
				Err: &apierrors.InternalServerError{},
			},
		}
		h := AuthController{
			authService,
			&services.PasswordResetServiceMock{},
			tokensService,
		}

		// Assertions
		err := h.signUpEmail(c, &body)
		verifySignUpEmailArguments(t, authService.ArgumentsSpyMap, body)
		assert.True(t, errors.Is(err, &apierrors.InternalServerError{}))
	})

	t.Run("signup with email successful", func(t *testing.T) {
		// Setup
		accessToken := null.StringFrom("abc123")
		refreshToken := null.StringFrom("def456")
		e := echo.New()
		req := httptest.NewRequest(http.MethodPost, constants.ENDPOINT_AUTH_SIGNUP_EMAIL, nil)
		rec := httptest.NewRecorder()
		c := e.NewContext(req, rec)
		authService := createTestAuthServiceWithTokenResponse(accessToken, refreshToken)
		tokensService := &services.TokensServiceMock{
			GetOauthTokensForAccountResult: services.GetOauthTokensResult{
				AccessToken: accessToken, RefreshToken: refreshToken, Err: nil,
			},
		}
		h := AuthController{
			authService,
			&services.PasswordResetServiceMock{},
			tokensService,
		}

		// Assertions
		if assert.NoError(t, h.signUpEmail(c, &body)) {
			assert.Equal(t, http.StatusCreated, rec.Code)
			verifySignUpEmailArguments(t, authService.ArgumentsSpyMap, body)
			assert.Contains(t, rec.Body.String(), fmt.Sprintf("\"accessToken\":\"%s\"", accessToken.String))
			assert.Contains(t, rec.Body.String(), fmt.Sprintf("\"refreshToken\":\"%s\"", refreshToken.String))
		}
	})
}

func TestUnit_AuthController_signUpGoogle(t *testing.T) {
	var body views.AuthSignUpGoogleRequest
	err := ParseJSON(strings.NewReader(AuthSignUpGoogleRequestJSON), &body)
	assert.NoError(t, err)

	t.Run("signup Google processing fails - controller returns error", func(t *testing.T) {
		// Setup
		e := echo.New()
		req := httptest.NewRequest(http.MethodPost, constants.ENDPOINT_AUTH_SIGNUP_GOOGLE, nil)
		rec := httptest.NewRecorder()
		c := e.NewContext(req, rec)

		authService := createTestAuthServiceForSignUpWithErrors(nil, &apierrors.InternalServerError{}, nil, nil)
		tokensService := &services.TokensServiceMock{}
		h := AuthController{
			authService,
			&services.PasswordResetServiceMock{},
			tokensService,
		}

		// Assertions
		err := h.signUpGoogle(c, &body)
		assert.False(t, tokensService.GetOauthTokensForAccountCalled)
		verifySignUpGoogleArguments(t, authService.ArgumentsSpyMap, body)
		assert.True(t, errors.Is(err, &apierrors.InternalServerError{}))
	})

	t.Run("retrieving auth tokens fails - controller returns error", func(t *testing.T) {
		// Setup
		e := echo.New()
		req := httptest.NewRequest(http.MethodPost, constants.ENDPOINT_AUTH_SIGNUP_GOOGLE, nil)
		rec := httptest.NewRecorder()
		c := e.NewContext(req, rec)
		authService := createTestAuthServiceForSignUpWithErrors(nil, nil, nil, &apierrors.InternalServerError{})
		tokensService := &services.TokensServiceMock{
			GetOauthTokensForAccountResult: services.GetOauthTokensResult{
				Err: &apierrors.InternalServerError{},
			},
		}
		h := AuthController{
			authService,
			&services.PasswordResetServiceMock{},
			tokensService,
		}

		// Assertions
		err := h.signUpGoogle(c, &body)
		verifySignUpGoogleArguments(t, authService.ArgumentsSpyMap, body)
		assert.True(t, errors.Is(err, &apierrors.InternalServerError{}))
	})

	t.Run("signup with Google successful", func(t *testing.T) {
		// Setup
		accessToken := null.StringFrom("abc123")
		refreshToken := null.StringFrom("def456")
		e := echo.New()
		req := httptest.NewRequest(http.MethodPost, constants.ENDPOINT_AUTH_SIGNUP_GOOGLE, nil)
		rec := httptest.NewRecorder()
		c := e.NewContext(req, rec)
		authService := createTestAuthServiceWithTokenResponse(accessToken, refreshToken)
		tokensService := &services.TokensServiceMock{
			GetOauthTokensForAccountResult: services.GetOauthTokensResult{
				AccessToken: accessToken, RefreshToken: refreshToken, Err: nil,
			},
		}
		h := AuthController{
			authService,
			&services.PasswordResetServiceMock{},
			tokensService,
		}

		// Assertions
		if assert.NoError(t, h.signUpGoogle(c, &body)) {
			assert.Equal(t, http.StatusCreated, rec.Code)
			verifySignUpGoogleArguments(t, authService.ArgumentsSpyMap, body)
			assert.Contains(t, rec.Body.String(), fmt.Sprintf("\"accessToken\":\"%s\"", accessToken.String))
			assert.Contains(t, rec.Body.String(), fmt.Sprintf("\"refreshToken\":\"%s\"", refreshToken.String))
		}
	})
}

func TestUnit_AuthController_signUpApple(t *testing.T) {
	var body views.AuthSignUpAppleRequest
	_ = ParseJSON(strings.NewReader(AuthSignUpAppleRequestJSON), &body)

	t.Run("signup Apple processing fails - controller returns error", func(t *testing.T) {
		// Setup
		e := echo.New()
		req := httptest.NewRequest(http.MethodPost, constants.ENDPOINT_AUTH_SIGNUP_APPLE, nil)
		rec := httptest.NewRecorder()
		c := e.NewContext(req, rec)
		authService := createTestAuthServiceForSignUpWithErrors(nil, nil, &apierrors.InternalServerError{}, nil)
		tokensService := &services.TokensServiceMock{}
		h := AuthController{
			authService,
			&services.PasswordResetServiceMock{},
			tokensService,
		}

		// Assertions
		err := h.signUpApple(c, &body)
		assert.False(t, tokensService.GetOauthTokensForAccountCalled)
		verifySignUpAppleArguments(t, authService.ArgumentsSpyMap, body)
		assert.True(t, errors.Is(err, &apierrors.InternalServerError{}))
	})

	t.Run("retrieving auth tokens fails - controller returns error", func(t *testing.T) {
		// Setup
		e := echo.New()
		req := httptest.NewRequest(http.MethodPost, constants.ENDPOINT_AUTH_SIGNUP_APPLE, nil)
		rec := httptest.NewRecorder()
		c := e.NewContext(req, rec)
		authService := createTestAuthServiceForSignUpWithErrors(nil, nil, nil, &apierrors.InternalServerError{})
		tokensService := &services.TokensServiceMock{
			GetOauthTokensForAccountResult: services.GetOauthTokensResult{
				Err: &apierrors.InternalServerError{},
			},
		}
		h := AuthController{
			authService,
			&services.PasswordResetServiceMock{},
			tokensService,
		}

		// Assertions
		err := h.signUpApple(c, &body)
		verifySignUpAppleArguments(t, authService.ArgumentsSpyMap, body)
		assert.True(t, errors.Is(err, &apierrors.InternalServerError{}))
	})

	t.Run("signup with Apple successful", func(t *testing.T) {
		// Setup
		accessToken := null.StringFrom("abc123")
		refreshToken := null.StringFrom("def456")
		e := echo.New()
		req := httptest.NewRequest(http.MethodPost, constants.ENDPOINT_AUTH_SIGNUP_APPLE, nil)
		rec := httptest.NewRecorder()
		c := e.NewContext(req, rec)
		authService := createTestAuthServiceWithTokenResponse(accessToken, refreshToken)
		tokensService := &services.TokensServiceMock{
			GetOauthTokensForAccountResult: services.GetOauthTokensResult{
				AccessToken: accessToken, RefreshToken: refreshToken, Err: nil,
			},
		}
		h := AuthController{
			authService,
			&services.PasswordResetServiceMock{},
			tokensService,
		}

		// Assertions
		if assert.NoError(t, h.signUpApple(c, &body)) {
			assert.Equal(t, http.StatusCreated, rec.Code)
			verifySignUpAppleArguments(t, authService.ArgumentsSpyMap, body)
			assert.Contains(t, rec.Body.String(), fmt.Sprintf("\"accessToken\":\"%s\"", accessToken.String))
			assert.Contains(t, rec.Body.String(), fmt.Sprintf("\"refreshToken\":\"%s\"", refreshToken.String))
		}
	})
}

func TestUnit_AuthController_signInEmail(t *testing.T) {
	var body views.AuthSignInEmailRequest
	_ = ParseJSON(strings.NewReader(AuthSignInEmailRequestJSON), &body)

	t.Run("sign in with email processing fails - controller returns error", func(t *testing.T) {
		// Setup
		e := echo.New()
		req := httptest.NewRequest(http.MethodPost, constants.ENDPOINT_AUTH_SIGNIN_EMAIL, nil)
		rec := httptest.NewRecorder()
		c := e.NewContext(req, rec)
		authService := createTestAuthServiceForSignInWithErrors(&apierrors.InternalServerError{}, nil, nil, nil)
		h := AuthController{
			authService,
			&services.PasswordResetServiceMock{},
			&services.TokensServiceMock{},
		}

		// Assertions
		err := h.signInEmail(c, &body)
		verifySignInEmailArguments(t, authService.ArgumentsSpyMap, body)
		assert.True(t, errors.Is(err, &apierrors.InternalServerError{}))
	})

	t.Run("sign in with email successful", func(t *testing.T) {
		// Setup
		accessToken := null.StringFrom("abc123")
		refreshToken := null.StringFrom("def456")
		e := echo.New()
		req := httptest.NewRequest(http.MethodPost, constants.ENDPOINT_AUTH_SIGNIN_EMAIL, nil)
		rec := httptest.NewRecorder()
		c := e.NewContext(req, rec)
		authService := createTestAuthServiceWithTokenResponse(accessToken, refreshToken)
		h := AuthController{
			authService,
			&services.PasswordResetServiceMock{},
			&services.TokensServiceMock{},
		}

		// Assertions
		if assert.NoError(t, h.signInEmail(c, &body)) {
			assert.Equal(t, http.StatusOK, rec.Code)
			verifySignInEmailArguments(t, authService.ArgumentsSpyMap, body)
			assert.Contains(t, rec.Body.String(), fmt.Sprintf("\"accessToken\":\"%s\"", accessToken.String))
			assert.Contains(t, rec.Body.String(), fmt.Sprintf("\"refreshToken\":\"%s\"", refreshToken.String))
		}
	})
}

func TestUnit_AuthController_signInUsername(t *testing.T) {
	var body views.AuthSignInUsernameRequest
	_ = ParseJSON(strings.NewReader(AuthSignInUsernameRequestJSON), &body)

	t.Run("sign in with username processing fails - controller returns error", func(t *testing.T) {
		// Setup
		e := echo.New()
		req := httptest.NewRequest(http.MethodPost, constants.ENDPOINT_AUTH_SIGNIN_USERNAME, nil)
		rec := httptest.NewRecorder()
		c := e.NewContext(req, rec)
		authService := createTestAuthServiceForSignInWithErrors(nil, nil, nil, &apierrors.InternalServerError{})
		h := AuthController{
			authService,
			&services.PasswordResetServiceMock{},
			&services.TokensServiceMock{},
		}

		// Assertions
		err := h.signInUsername(c, &body)
		verifySignInUsernameArguments(t, authService.ArgumentsSpyMap, body)
		assert.True(t, errors.Is(err, &apierrors.InternalServerError{}))
	})

	t.Run("sign in with username successful", func(t *testing.T) {
		// Setup
		accessToken := null.StringFrom("abc123")
		refreshToken := null.StringFrom("def456")
		e := echo.New()
		req := httptest.NewRequest(http.MethodPost, constants.ENDPOINT_AUTH_SIGNIN_USERNAME, nil)
		rec := httptest.NewRecorder()
		c := e.NewContext(req, rec)
		authService := createTestAuthServiceWithTokenResponse(accessToken, refreshToken)
		h := AuthController{
			authService,
			&services.PasswordResetServiceMock{},
			&services.TokensServiceMock{},
		}

		// Assertions
		if assert.NoError(t, h.signInUsername(c, &body)) {
			assert.Equal(t, http.StatusOK, rec.Code)
			verifySignInUsernameArguments(t, authService.ArgumentsSpyMap, body)
			assert.Contains(t, rec.Body.String(), fmt.Sprintf("\"accessToken\":\"%s\"", accessToken.String))
			assert.Contains(t, rec.Body.String(), fmt.Sprintf("\"refreshToken\":\"%s\"", refreshToken.String))
		}
	})
}

func TestUnit_AuthController_signInGoogle(t *testing.T) {
	var body views.AuthSignInGoogleRequest
	_ = ParseJSON(strings.NewReader(AuthSignInGoogleRequestJSON), &body)

	t.Run("sign in with Google processing fails - controller returns error", func(t *testing.T) {
		// Setup
		e := echo.New()
		req := httptest.NewRequest(http.MethodPost, constants.ENDPOINT_AUTH_SIGNIN_GOOGLE, nil)
		rec := httptest.NewRecorder()
		c := e.NewContext(req, rec)
		authService := createTestAuthServiceForSignInWithErrors(nil, &apierrors.InternalServerError{}, nil, nil)
		h := AuthController{
			authService,
			&services.PasswordResetServiceMock{},
			&services.TokensServiceMock{},
		}

		// Assertions
		err := h.signInGoogle(c, &body)
		verifySignInGoogleArguments(t, authService.ArgumentsSpyMap, body)
		assert.True(t, errors.Is(err, &apierrors.InternalServerError{}))
	})

	t.Run("sign in with Google successful", func(t *testing.T) {
		// Setup
		accessToken := null.StringFrom("abc123")
		refreshToken := null.StringFrom("def456")
		e := echo.New()
		req := httptest.NewRequest(http.MethodPost, constants.ENDPOINT_AUTH_SIGNIN_GOOGLE, nil)
		rec := httptest.NewRecorder()
		c := e.NewContext(req, rec)
		authService := createTestAuthServiceWithTokenResponse(accessToken, refreshToken)
		h := AuthController{
			authService,
			&services.PasswordResetServiceMock{},
			&services.TokensServiceMock{},
		}

		// Assertions
		if assert.NoError(t, h.signInGoogle(c, &body)) {
			assert.Equal(t, http.StatusOK, rec.Code)
			verifySignInGoogleArguments(t, authService.ArgumentsSpyMap, body)
			assert.Contains(t, rec.Body.String(), fmt.Sprintf("\"accessToken\":\"%s\"", accessToken.String))
			assert.Contains(t, rec.Body.String(), fmt.Sprintf("\"refreshToken\":\"%s\"", refreshToken.String))
		}
	})
}

func TestUnit_AuthController_signInApple(t *testing.T) {
	var body views.AuthSignInAppleRequest
	_ = ParseJSON(strings.NewReader(AuthSignInAppleRequestJSON), &body)

	t.Run("sign in with Apple processing fails - controller returns error", func(t *testing.T) {
		// Setup
		e := echo.New()
		req := httptest.NewRequest(http.MethodPost, constants.ENDPOINT_AUTH_SIGNIN_APPLE, nil)
		rec := httptest.NewRecorder()
		c := e.NewContext(req, rec)
		authService := createTestAuthServiceForSignInWithErrors(nil, nil, &apierrors.InternalServerError{}, nil)
		h := AuthController{
			authService,
			&services.PasswordResetServiceMock{},
			&services.TokensServiceMock{},
		}

		// Assertions
		err := h.signInApple(c, &body)
		verifySignInAppleArguments(t, authService.ArgumentsSpyMap, body)
		assert.True(t, errors.Is(err, &apierrors.InternalServerError{}))
	})

	t.Run("sign in with Apple successful", func(t *testing.T) {
		// Setup
		accessToken := null.StringFrom("abc123")
		refreshToken := null.StringFrom("def456")
		e := echo.New()
		req := httptest.NewRequest(http.MethodPost, constants.ENDPOINT_AUTH_SIGNIN_APPLE, nil)
		rec := httptest.NewRecorder()
		c := e.NewContext(req, rec)
		authService := createTestAuthServiceWithTokenResponse(accessToken, refreshToken)
		h := AuthController{
			authService,
			&services.PasswordResetServiceMock{},
			&services.TokensServiceMock{},
		}

		// Assertions
		if assert.NoError(t, h.signInApple(c, &body)) {
			assert.Equal(t, http.StatusOK, rec.Code)
			verifySignInAppleArguments(t, authService.ArgumentsSpyMap, body)
			assert.Contains(t, rec.Body.String(), fmt.Sprintf("\"accessToken\":\"%s\"", accessToken.String))
			assert.Contains(t, rec.Body.String(), fmt.Sprintf("\"refreshToken\":\"%s\"", refreshToken.String))
		}
	})
}

func TestUnit_AuthController_passwordReset(t *testing.T) {
	var body views.AccountPasswordResetRequest
	_ = ParseJSON(strings.NewReader(AccountPasswordResetRequestJSON), &body)

	t.Run("password reset fails - controller returns error", func(t *testing.T) {
		// Setup
		e := echo.New()
		req := httptest.NewRequest(http.MethodPost, constants.ENDPOINT_AUTH_PASSWORD_RESET, nil)
		rec := httptest.NewRecorder()
		c := e.NewContext(req, rec)
		passwordResetService := createTestPasswordResetServiceForPasswordReset(&apierrors.InternalServerError{}, nil)
		h := AuthController{
			&services.AuthServiceMock{},
			passwordResetService,
			&services.TokensServiceMock{},
		}

		// Assertions
		err := h.passwordReset(c, &body)
		verifyPasswordResetArguments(t, passwordResetService.ArgumentsSpyMap, body)
		assert.True(t, errors.Is(err, &apierrors.InternalServerError{}))
	})

	t.Run("password reset successful", func(t *testing.T) {
		// Setup
		e := echo.New()
		req := httptest.NewRequest(http.MethodPost, constants.ENDPOINT_AUTH_PASSWORD_RESET, nil)
		rec := httptest.NewRecorder()
		c := e.NewContext(req, rec)
		passwordResetService := createTestPasswordResetServiceForPasswordReset(nil, nil)
		h := AuthController{
			&services.AuthServiceMock{},
			passwordResetService,
			&services.TokensServiceMock{},
		}

		// Assertions
		if assert.NoError(t, h.passwordReset(c, &body)) {
			assert.Equal(t, http.StatusOK, rec.Code)
			verifyPasswordResetArguments(t, passwordResetService.ArgumentsSpyMap, body)
		}
	})
}

func TestUnit_AuthController_passwordResetConfirm(t *testing.T) {
	var body views.AccountPasswordResetConfirmRequest
	_ = ParseJSON(strings.NewReader(AccountPasswordResetConfirmRequestJSON), &body)

	t.Run("password reset confirm fails - controller returns error", func(t *testing.T) {
		// Setup
		e := echo.New()
		req := httptest.NewRequest(http.MethodPost, constants.ENDPOINT_AUTH_PASSWORD_RESET_CONFIRM, nil)
		rec := httptest.NewRecorder()
		c := e.NewContext(req, rec)
		passwordResetService := createTestPasswordResetServiceForPasswordReset(nil, &apierrors.InternalServerError{})
		h := AuthController{
			&services.AuthServiceMock{},
			passwordResetService,
			&services.TokensServiceMock{},
		}

		// Assertions
		err := h.passwordResetConfirm(c, &body)
		verifyPasswordResetConfirmArguments(t, passwordResetService.ArgumentsSpyMap, body)
		assert.True(t, errors.Is(err, &apierrors.InternalServerError{}))
	})

	t.Run("password reset confirm successful", func(t *testing.T) {
		// Setup
		e := echo.New()
		req := httptest.NewRequest(http.MethodPost, constants.ENDPOINT_AUTH_PASSWORD_RESET_CONFIRM, nil)
		rec := httptest.NewRecorder()
		c := e.NewContext(req, rec)
		passwordResetService := createTestPasswordResetServiceForPasswordReset(nil, nil)
		h := AuthController{
			&services.AuthServiceMock{},
			passwordResetService,
			&services.TokensServiceMock{},
		}

		// Assertions
		if assert.NoError(t, h.passwordResetConfirm(c, &body)) {
			verifyPasswordResetConfirmArguments(t, passwordResetService.ArgumentsSpyMap, body)
			assert.Equal(t, http.StatusOK, rec.Code)
		}
	})
}

func createTestAuthServiceForSignInWithErrors(signInEmailError, signInGoogleError, signInAppleError, signInUsernameError error) *services.AuthServiceMock {
	return &services.AuthServiceMock{
		SignInEmailResult:    services.GetOauthTokensResult{AccessToken: null.String{}, RefreshToken: null.String{}, Err: signInEmailError},
		SignInGoogleResult:   services.GetOauthTokensResult{AccessToken: null.String{}, RefreshToken: null.String{}, Err: signInGoogleError},
		SignInAppleResult:    services.GetOauthTokensResult{AccessToken: null.String{}, RefreshToken: null.String{}, Err: signInAppleError},
		SignInUsernameResult: services.GetOauthTokensResult{AccessToken: null.String{}, RefreshToken: null.String{}, Err: signInUsernameError},
	}
}

func createTestAuthServiceForSignUpWithErrors(signUpEmailError, signUpGoogleError, signUpAppleError, signUpUsernameError error) *services.AuthServiceMock {
	return &services.AuthServiceMock{
		SignUpEmailResult:    services.SignUpResult{Uuid: uuid.NullUUID{}, HasAdminAccess: false, Err: signUpEmailError},
		SignUpGoogleResult:   services.SignUpResult{Uuid: uuid.NullUUID{}, HasAdminAccess: false, Err: signUpGoogleError},
		SignUpAppleResult:    services.SignUpResult{Uuid: uuid.NullUUID{}, HasAdminAccess: false, Err: signUpAppleError},
		SignUpUsernameResult: services.SignUpResult{Uuid: uuid.NullUUID{}, HasAdminAccess: false, Err: signUpUsernameError},
	}
}

func createTestPasswordResetServiceForPasswordReset(passwordResetError, confirmPasswordResetError error) *services.PasswordResetServiceMock {
	return &services.PasswordResetServiceMock{PasswordResetError: passwordResetError, ConfirmPasswordResetError: confirmPasswordResetError}
}

func createTestAuthServiceWithTokenResponse(accessToken, refreshToken null.String) *services.AuthServiceMock {
	return &services.AuthServiceMock{
		SignUpEmailResult:    services.SignUpResult{Uuid: uuid.NullUUID{}, HasAdminAccess: false, Err: nil},
		SignUpGoogleResult:   services.SignUpResult{Uuid: uuid.NullUUID{}, HasAdminAccess: false, Err: nil},
		SignUpAppleResult:    services.SignUpResult{Uuid: uuid.NullUUID{}, HasAdminAccess: false, Err: nil},
		SignUpUsernameResult: services.SignUpResult{Uuid: uuid.NullUUID{}, HasAdminAccess: false, Err: nil},
		SignInEmailResult:    services.GetOauthTokensResult{AccessToken: accessToken, RefreshToken: refreshToken, Err: nil},
		SignInGoogleResult:   services.GetOauthTokensResult{AccessToken: accessToken, RefreshToken: refreshToken, Err: nil},
		SignInAppleResult:    services.GetOauthTokensResult{AccessToken: accessToken, RefreshToken: refreshToken, Err: nil},
		SignInUsernameResult: services.GetOauthTokensResult{AccessToken: accessToken, RefreshToken: refreshToken, Err: nil},
	}
}

func verifySignUpUsernameArguments(t *testing.T, spyMap map[string]interface{}, body views.AuthSignUpUsernameRequest) {
	assert.Equal(t, spyMap["username"], body.Username)
	assert.Equal(t, spyMap["password"], body.Password)
	verifyAuthSignUpRequest(t, spyMap, body.AuthSignUpRequest)
}

func verifySignUpEmailArguments(t *testing.T, spyMap map[string]interface{}, body views.AuthSignUpEmailRequest) {
	assert.Equal(t, spyMap["email"], body.Email)
	assert.Equal(t, spyMap["password"], body.Password)
	assert.Equal(t, spyMap["name"], body.Name.String)
	verifyAuthSignUpRequest(t, spyMap, body.AuthSignUpRequest)
}

func verifySignUpGoogleArguments(t *testing.T, spyMap map[string]interface{}, body views.AuthSignUpGoogleRequest) {
	assert.Equal(t, spyMap["idToken"], body.IDToken)
	verifyAuthSignUpRequest(t, spyMap, body.AuthSignUpRequest)
}

func verifySignUpAppleArguments(t *testing.T, spyMap map[string]interface{}, body views.AuthSignUpAppleRequest) {
	assert.Equal(t, spyMap["idToken"], body.IDToken)
	assert.Equal(t, spyMap["name"], body.Name)
	verifyAuthSignUpRequest(t, spyMap, body.AuthSignUpRequest)
}

func verifySignInEmailArguments(t *testing.T, spyMap map[string]interface{}, body views.AuthSignInEmailRequest) {
	assert.Equal(t, spyMap["email"], body.Email)
	assert.Equal(t, spyMap["password"], body.Password)
	assert.Equal(t, spyMap["twoFactorAuthenticationToken"], body.TwoFactorAuthenticationToken)
}

func verifySignInUsernameArguments(t *testing.T, spyMap map[string]interface{}, body views.AuthSignInUsernameRequest) {
	assert.Equal(t, spyMap["username"], body.Username)
	assert.Equal(t, spyMap["password"], body.Password)
	assert.Equal(t, spyMap["twoFactorAuthenticationToken"], body.TwoFactorAuthenticationToken)
}

func verifySignInGoogleArguments(t *testing.T, spyMap map[string]interface{}, body views.AuthSignInGoogleRequest) {
	assert.Equal(t, spyMap["idToken"], body.IDToken)
	assert.Equal(t, spyMap["HasAdminAccess"], body.HasAdminAccess)
}

func verifySignInAppleArguments(t *testing.T, spyMap map[string]interface{}, body views.AuthSignInAppleRequest) {
	assert.Equal(t, spyMap["idToken"], body.IDToken)
}

func verifyPasswordResetArguments(t *testing.T, spyMap map[string]interface{}, body views.AccountPasswordResetRequest) {
	assert.Equal(t, spyMap["email"], body.Email)
}

func verifyPasswordResetConfirmArguments(t *testing.T, spyMap map[string]interface{}, body views.AccountPasswordResetConfirmRequest) {
	assert.Equal(t, spyMap["password"], body.Password)
	assert.Equal(t, spyMap["token"], body.Token)
}

func verifyAuthSignUpRequest(t *testing.T, spyMap map[string]interface{}, body views.AuthSignUpRequest) {
	assert.Equal(t, spyMap["countryCode"], body.CountryCode)
	assert.Equal(t, spyMap["interfaceLanguageCode"], body.InterfaceLanguageCode)
	assert.Equal(t, utils.GetNullStringFromInterface(spyMap["userType"]), body.UserType)
	assert.Equal(t, spyMap["subscribedToNewsletter"], body.SubscribedToNewsletter)
	//todo: check this one too: assert.Equal(t, spyMap["issueSubjectsIDs"], body.IssueSubjectsIDs)
	assert.Equal(t, utils.GetNullStringFromInterface(spyMap["schoolUuid"]).String, body.SchoolUUID.UUID.String())
	assert.Equal(t, utils.GetNullIntFromInterface(spyMap["schoolTypeID"]), body.SchoolTypeID)
	assert.Equal(t, utils.GetNullIntFromInterface(spyMap["gradeID"]), body.GradeID)
	assert.Equal(t, utils.GetNullIntFromInterface(spyMap["regionID"]), body.RegionID)
	// The spy map converts this integer to a float. This doesn't have any negative impact on the actual code
	assert.Equal(t, utils.GetNullFloatFromInterface(spyMap["primaryContentLanguageId"]), null.NewFloat(float64(body.PrimaryContentLanguageID.Int64), body.PrimaryContentLanguageID.Valid))
	// TODO: Implement slice comparison
	// assert.Equal(t, spyMap["secondaryContentLanguageIds"], body.SecondaryContentLanguageIDs)
	assert.Equal(t, utils.GetNullStringFromInterface(spyMap["sourceOriginIdentifier"]), body.SourceOriginIdentifier)
	assert.Equal(t, utils.GetNullStringFromInterface(spyMap["source"]), body.Source)
	assert.Equal(t, utils.GetNullStringFromInterface(spyMap["sourceCampaign"]), body.SourceCampaign)
	assert.Equal(t, utils.GetNullStringFromInterface(spyMap["referredByUsername"]), body.ReferredByUsername)
}
*/
