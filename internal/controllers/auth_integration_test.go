package controllers
/*
import (
	"context"
	"database/sql"
	"encoding/json"
	"global-auth-service/app"
	"global-auth-service/internal/constants"
	"global-auth-service/internal/utils"
	"global-auth-service/internal/views"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/gofrs/uuid"
	_ "github.com/lib/pq"
	"github.com/stretchr/testify/assert"
	cloudscommon "gitlab.com/knowunity/go-common/pkg/clouds"
	"gitlab.com/knowunity/go-common/pkg/errors"
	"gopkg.in/guregu/null.v4"
)

func TestIntegration_AuthController(t *testing.T) {
	e := startTestServer()
	defer stopTestServer(e)

	cloudscommon.IpApiClientMockRequestSingleResponse = cloudscommon.IpResponse{CountryCode: "DE"}

	t.Run("signup username", func(t *testing.T) {
		signupRand, _ := utils.RandomString(10)
		signupUsername := "test_signupuserNAME" + signupRand
		signupPassword := "test_signupusernamepassword" + signupRand
		err, resp := doSignupUsername(signupRand, signupUsername, signupPassword, testServerAddress)
		assert.NoError(t, err)
		defer resp.Body.Close()

		defer func(Body io.ReadCloser) {
			_ = Body.Close()
		}(resp.Body)
		verifyAuthTokenResponse(t, resp, http.StatusCreated)

		account, err := app.GetAccountRepository().GetByUsernameAuth(context.Background(), strings.ToLower(signupUsername))
		assert.NoError(t, err)
		assert.True(t, account.Username.Valid)
		assert.Equal(t, account.Username.String, strings.ToLower(signupUsername))
	})

	t.Run("signup email", func(t *testing.T) {
		signupRand, _ := utils.RandomString(10)
		signupEmail := "test_signupemail" + signupRand + "@gmail.com"
		signupPassword := "test_signupemailpassword" + signupRand
		err, resp := doSignupEmail(signupRand, signupEmail, signupPassword, testServerAddress)
		assert.NoError(t, err)
		defer resp.Body.Close()

		defer func(Body io.ReadCloser) {
			_ = Body.Close()
		}(resp.Body)
		verifyAuthTokenResponse(t, resp, http.StatusCreated)

		account, err := app.GetAccountRepository().GetByEmailAuth(context.Background(), strings.ToLower(signupEmail))
		assert.NoError(t, err)
		assert.True(t, account.Username.Valid)
		assert.True(t, account.Email.Valid)
		assert.Equal(t, account.Email.String, strings.ToLower(signupEmail))
	})

	t.Run("signup google", func(t *testing.T) {
		rand, _ := utils.RandomString(10)
		googleAuthService.ClaimsEmail = "test" + rand + "@gmail.com"
		googleAuthService.ClaimsSubject = rand

		err, resp := doSignupGoogle(rand, testServerAddress)
		assert.NoError(t, err)
		defer resp.Body.Close()

		defer func(Body io.ReadCloser) {
			_ = Body.Close()
		}(resp.Body)
		verifyAuthTokenResponse(t, resp, http.StatusCreated)

		account, err := app.GetAccountRepository().GetByEmailAuth(context.Background(), strings.ToLower(googleAuthService.ClaimsEmail))
		assert.NoError(t, err)
		assert.True(t, account.Username.Valid)
		assert.True(t, account.Email.Valid)
		assert.Equal(t, account.Email.String, strings.ToLower(googleAuthService.ClaimsEmail))
	})

	t.Run("signup apple", func(t *testing.T) {
		rand, _ := utils.RandomString(20)
		appleAuthService.ClaimsEmail = "test" + rand + "@gmail.com"
		appleAuthService.ClaimsSubject = rand
		err, resp := doSignupApple(t, rand, testServerAddress)
		assert.NoError(t, err)
		defer resp.Body.Close()

		defer func(Body io.ReadCloser) {
			_ = Body.Close()
		}(resp.Body)
		verifyAuthTokenResponse(t, resp, http.StatusCreated)

		account, err := app.GetAccountRepository().GetByEmailAuth(context.Background(), strings.ToLower(appleAuthService.ClaimsEmail))
		assert.NoError(t, err)
		assert.True(t, account.Username.Valid)
		assert.True(t, account.Email.Valid)
		assert.Equal(t, account.Email.String, strings.ToLower(appleAuthService.ClaimsEmail))
	})

	t.Run("sign in username", func(t *testing.T) {
		signinRand, _ := utils.RandomString(10)
		signinUsername := "test_signinuserNAME" + signinRand
		signinPassword := "test_signinusernamepassword" + signinRand
		err, resp := doSignupUsername(signinRand, signinUsername, signinPassword, testServerAddress)
		assert.NoError(t, err)
		defer resp.Body.Close()

		rand, _ := utils.RandomString(10)
		reqBody := views.AuthSignInUsernameRequest{
			Username:                     signinUsername,
			Password:                     signinPassword,
			TwoFactorAuthenticationToken: null.StringFrom(rand),
		}
		bodyByteArray, err := json.Marshal(reqBody)
		if err != nil {
			assert.NoError(t, err)
		}
		bodyString := string(bodyByteArray)

		req, err := http.NewRequest(http.MethodPost, "http://localhost"+testServerAddress+constants.ENDPOINT_AUTH_SIGNIN_USERNAME,
			strings.NewReader(bodyString))
		assert.NoError(t, err)
		req.Header.Add("Content-Type", "application/json")

		client := &http.Client{Timeout: time.Second * 3}
		resp, err = client.Do(req)
		assert.NoError(t, err)
		defer resp.Body.Close()

		verifyAuthTokenResponse(t, resp, http.StatusOK)
	})

	t.Run("sign in email", func(t *testing.T) {
		signinRand, _ := utils.RandomString(10)
		signinEmail := "test_signinemail" + signinRand + "@gmail.com"
		signinPassword := "test_signinemailpassword" + signinRand
		err, resp := doSignupEmail(signinRand, signinEmail, signinPassword, testServerAddress)
		assert.NoError(t, err)
		defer resp.Body.Close()

		rand, _ := utils.RandomString(10)
		reqBody := views.AuthSignInEmailRequest{
			Email:                        signinEmail,
			Password:                     signinPassword,
			TwoFactorAuthenticationToken: null.StringFrom(rand),
		}
		bodyByteArray, err := json.Marshal(reqBody)
		if err != nil {
			assert.NoError(t, err)
		}
		bodyString := string(bodyByteArray)

		req, err := http.NewRequest(http.MethodPost, "http://localhost"+testServerAddress+constants.ENDPOINT_AUTH_SIGNIN_EMAIL,
			strings.NewReader(bodyString))
		assert.NoError(t, err)
		req.Header.Add("Content-Type", "application/json")

		client := &http.Client{Timeout: time.Second * 3}
		resp, err = client.Do(req)
		assert.NoError(t, err)
		defer resp.Body.Close()

		verifyAuthTokenResponse(t, resp, http.StatusOK)
	})

	t.Run("sign in google", func(t *testing.T) {
		rand, _ := utils.RandomString(10)
		claimsEmail := "test" + rand + "@gmail.com"
		claimsSubject := rand
		googleAuthService.ClaimsEmail = claimsEmail
		googleAuthService.ClaimsSubject = claimsSubject
		err, resp := doSignupGoogle(rand, testServerAddress)
		assert.NoError(t, err)
		defer resp.Body.Close()

		reqBody := views.AuthSignInGoogleRequest{
			IDToken:        rand,
			HasAdminAccess: false,
		}
		bodyByteArray, err := json.Marshal(reqBody)
		if err != nil {
			assert.NoError(t, err)
		}
		bodyString := string(bodyByteArray)

		req, err := http.NewRequest(http.MethodPost, "http://localhost"+testServerAddress+constants.ENDPOINT_AUTH_SIGNIN_GOOGLE,
			strings.NewReader(bodyString))
		assert.NoError(t, err)
		req.Header.Add("Content-Type", "application/json")

		client := &http.Client{Timeout: time.Second * 3}
		resp, err = client.Do(req)
		assert.NoError(t, err)
		defer resp.Body.Close()

		verifyAuthTokenResponse(t, resp, http.StatusOK)
	})

	t.Run("sign in apple", func(t *testing.T) {
		rand, _ := utils.RandomString(10)
		claimsEmail := "test" + rand + "@gmail.com"
		claimsSubject := rand
		googleAuthService.ClaimsEmail = claimsEmail
		googleAuthService.ClaimsSubject = claimsSubject
		err, resp := doSignupApple(t, rand, testServerAddress)
		assert.NoError(t, err)
		defer resp.Body.Close()

		reqBody := views.AuthSignInAppleRequest{
			IDToken: rand,
		}
		bodyByteArray, err := json.Marshal(reqBody)
		if err != nil {
			assert.NoError(t, err)
		}
		bodyString := string(bodyByteArray)

		req, err := http.NewRequest(http.MethodPost, "http://localhost"+testServerAddress+constants.ENDPOINT_AUTH_SIGNIN_APPLE,
			strings.NewReader(bodyString))
		assert.NoError(t, err)
		req.Header.Add("Content-Type", "application/json")

		client := &http.Client{Timeout: time.Second * 3}
		resp, err = client.Do(req)
		assert.NoError(t, err)
		defer resp.Body.Close()
		verifyAuthTokenResponse(t, resp, http.StatusOK)
	})

	t.Run("password reset", func(t *testing.T) {
		signinRand, _ := utils.RandomString(10)
		signinEmail := "test_signinemail" + signinRand + "@gmail.com"
		signinPassword := "test_signinemailpassword" + signinRand
		err, resp := doSignupEmail(signinRand, signinEmail, signinPassword, testServerAddress)
		assert.NoError(t, err)
		defer resp.Body.Close()

		reqBody := views.AccountPasswordResetRequest{
			Email: signinEmail,
		}
		bodyByteArray, err := json.Marshal(reqBody)
		if err != nil {
			assert.NoError(t, err)
		}
		bodyString := string(bodyByteArray)

		req, err := http.NewRequest(http.MethodPost, "http://localhost"+testServerAddress+constants.ENDPOINT_AUTH_PASSWORD_RESET,
			strings.NewReader(bodyString))
		assert.NoError(t, err)
		req.Header.Add("Content-Type", "application/json")
		req.Header.Add(constants.HeaderHCaptchaToken, signinRand)

		client := &http.Client{Timeout: time.Second * 3}
		resp, err = client.Do(req)
		assert.NoError(t, err)
		defer resp.Body.Close()

		defer func(Body io.ReadCloser) {
			_ = Body.Close()
		}(resp.Body)
		assert.Equal(t, resp.StatusCode, http.StatusOK)
	})

	t.Run("password reset confirm", func(t *testing.T) {
		// create new user
		signinRand, _ := utils.RandomString(10)
		signinEmail := "test_signinemail" + signinRand + "@gmail.com"
		signinPassword := "test_signinemailpassword" + signinRand
		err, resp := doSignupEmail(signinRand, signinEmail, signinPassword, testServerAddress)
		assert.NoError(t, err)
		defer resp.Body.Close()

		// simulate password reset
		ctx := context.TODO()
		account, _ := app.GetAccountRepository().GetByEmail(ctx, strings.ToLower(signinEmail))
		passwordResetToken := signinRand
		dbManager := app.GetDBManager()
		tx, _ := dbManager.BeginDBTx(ctx, &sql.TxOptions{})
		_ = app.GetPasswordResetRepository().Create(ctx, tx, passwordResetToken, account.UUID)
		_ = tx.Commit()

		// run test
		reqBody := views.AccountPasswordResetConfirmRequest{
			Token:    signinRand,
			Password: signinRand,
		}
		bodyByteArray, err := json.Marshal(reqBody)
		if err != nil {
			assert.NoError(t, err)
		}
		bodyString := string(bodyByteArray)

		req, err := http.NewRequest(http.MethodPost, "http://localhost"+testServerAddress+constants.ENDPOINT_AUTH_PASSWORD_RESET_CONFIRM,
			strings.NewReader(bodyString))
		assert.NoError(t, err)
		req.Header.Add("Content-Type", "application/json")
		req.Header.Add(constants.HeaderHCaptchaToken, signinRand)

		client := &http.Client{Timeout: time.Second * 3}
		resp, err = client.Do(req)
		assert.NoError(t, err)
		defer resp.Body.Close()

		assert.Equal(t, resp.StatusCode, http.StatusOK)
	})
}

func doSignupApple(t *testing.T, rand string, testServerAddress string) (error, *http.Response) {
	reqBody := views.AuthSignUpAppleRequest{
		IDToken: rand,
		Name:    "test_signupapple " + rand,
		AuthSignUpRequest: views.AuthSignUpRequest{
			ReferredByUsername:          null.StringFrom("test_signupapplereferal"),
			Source:                      null.StringFrom("test_signupapplesource"),
			SourceCampaign:              null.StringFrom("test_signupapplecampaign"),
			SourceOriginIdentifier:      null.StringFrom("test_signupappleoriginidentifies"),
			CountryCode:                 "DE",
			RegionID:                    null.IntFrom(1),
			PrimaryContentLanguageID:    null.IntFrom(1),
			SecondaryContentLanguageIDs: []int64{1},
			GradeID:                     null.IntFrom(1),
			SchoolTypeID:                null.IntFrom(1),
			InterfaceLanguageCode:       "DE",
			IssueSubjectsIDs:            []int64{1, 2, 3},
			SchoolUUID:                  uuid.NullUUID{UUID: uuid.Must(uuid.NewV4()), Valid: true},
			SubscribedToNewsletter:      true,
			UserType:                    null.StringFrom("test_signupappleusertype"),
		},
	}
	bodyByteArray, err := json.Marshal(reqBody)
	if err != nil {
		assert.NoError(t, err)
	}
	bodyString := string(bodyByteArray)

	req, err := http.NewRequest(http.MethodPost, "http://localhost"+testServerAddress+constants.ENDPOINT_AUTH_SIGNUP_APPLE,
		strings.NewReader(bodyString))
	assert.NoError(t, err)
	req.Header.Add("Content-Type", "application/json")

	client := &http.Client{Timeout: time.Second * 3}
	resp, err := client.Do(req)
	return errors.Wrap(err, "http"), resp
}
*/