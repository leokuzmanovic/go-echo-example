package controllers

/*
import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"global-auth-service/app"
	"global-auth-service/internal/config"
	"global-auth-service/internal/constants"
	"global-auth-service/internal/database"
	"global-auth-service/internal/models"
	"global-auth-service/internal/services"
	"global-auth-service/internal/utils"
	"global-auth-service/internal/views"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/gofrs/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	cloudscommon "gitlab.com/knowunity/go-common/pkg/clouds"
	"gitlab.com/knowunity/go-common/pkg/errors"
	"gopkg.in/guregu/null.v4"
)

func TestIntegration_AccountController(t *testing.T) {
	e := startTestServer()
	defer stopTestServer(e)

	t.Run("update username", func(t *testing.T) {
		if ipApiServiceMock, converted := app.GetIpApiClient().(*cloudscommon.MockIpApiClient); converted {
			ipApiServiceMock.EXPECT().RequestSingle(mock.Anything).Return(cloudscommon.IpResponse{
				CountryCode: "DE",
			}, nil)
		}
		// we want to create a user with email here to prove that update username works with that signup also
		signinRand, _ := utils.RandomString(10)
		signinEmail := "test_updateemail" + signinRand + "@gmail.com"
		signinPassword := "test_updateemailpassword" + signinRand
		accountUUID, accessToken, _ := prepareTestUser(signinRand, signinEmail, signinPassword)

		newUsername := "test_updateuserNAME" + signinRand + "_new"
		reqBody := views.AccountUsernameUpdateRequest{
			NewUsername: newUsername,
		}
		bodyByteArray, err := json.Marshal(reqBody)
		if err != nil {
			assert.NoError(t, err)
		}
		bodyString := string(bodyByteArray)

		req, err := http.NewRequest(http.MethodPatch, "http://localhost"+testServerAddress+
			strings.Replace(constants.ENDPOINT_ACCOUNT_USERNAME, ":accountUUID", accountUUID.String(), 1),
			strings.NewReader(bodyString))
		assert.NoError(t, err)
		req.Header.Add("Content-Type", "application/json")
		req.Header.Add("Authorization", fmt.Sprintf("Bearer %s", accessToken))

		client := &http.Client{Timeout: time.Second * 3}
		resp, err := client.Do(req)
		assert.NoError(t, err)

		defer resp.Body.Close()
		assert.Equal(t, resp.StatusCode, http.StatusOK)

		bodyBytes, err := io.ReadAll(resp.Body)
		assert.NoError(t, err)

		respBodyString := string(bodyBytes)
		var authTokenResponse views.AccountPrivateResponse
		err = ParseJSON(strings.NewReader(respBodyString), &authTokenResponse)
		assert.NoError(t, err)
		assert.Equal(t, authTokenResponse.UUID, accountUUID)
		assert.Equal(t, authTokenResponse.Username, strings.ToLower(newUsername))
		assert.False(t, authTokenResponse.Email.Valid)

		account, err := app.GetAccountRepository().GetAccountByUUID(context.Background(), accountUUID)
		assert.NoError(t, err)
		assert.Equal(t, account.Username.String, strings.ToLower(newUsername))
	})

	t.Run("update email", func(t *testing.T) {
		signinRand, _ := utils.RandomString(10)
		// we want to create a user with username here to prove that update email works with that signup also
		signinUsername := "test_updateusername" + signinRand
		signinPassword := "test_updateemailpassword" + signinRand
		accountUUID, accessToken, _ := prepareTestUserWithUsername(signinRand, signinUsername, signinPassword)

		newEmail := "test_updateemail" + signinRand + "_new" + "@gmail.com"
		reqBody := views.AccountEmailUpdateRequest{
			NewEmail: newEmail,
			Password: null.StringFrom(signinPassword),
		}
		bodyByteArray, err := json.Marshal(reqBody)
		if err != nil {
			assert.NoError(t, err)
		}
		bodyString := string(bodyByteArray)

		req, err := http.NewRequest(http.MethodPatch, "http://localhost"+testServerAddress+
			strings.Replace(constants.ENDPOINT_ACCOUNT_EMAIL, ":accountUUID", accountUUID.String(), 1),
			strings.NewReader(bodyString))
		assert.NoError(t, err)
		req.Header.Add("Content-Type", "application/json")
		req.Header.Add("Authorization", fmt.Sprintf("Bearer %s", accessToken))

		client := &http.Client{Timeout: time.Second * 3}
		resp, err := client.Do(req)
		assert.NoError(t, err)

		defer resp.Body.Close()
		assert.Equal(t, resp.StatusCode, http.StatusOK)

		bodyBytes, err := io.ReadAll(resp.Body)
		assert.NoError(t, err)

		respBodyString := string(bodyBytes)
		var authTokenResponse views.AccountPrivateResponse
		err = ParseJSON(strings.NewReader(respBodyString), &authTokenResponse)
		assert.NoError(t, err)
		assert.Equal(t, authTokenResponse.UUID, accountUUID)
		assert.Equal(t, authTokenResponse.Email.String, strings.ToLower(newEmail))

		account, err := app.GetAccountRepository().GetAccountByUUID(context.Background(), accountUUID)
		assert.NoError(t, err)
		assert.Equal(t, account.Email.String, strings.ToLower(newEmail))
	})

	t.Run("update password", func(t *testing.T) {
		signinRand, _ := utils.RandomString(10)
		signinEmail := "test_updatepassword" + signinRand + "@gmail.com"
		signinPassword := "test_updatepasswordpassword" + signinRand
		accountUUID, accessToken, _ := prepareTestUser(signinRand, signinEmail, signinPassword)

		newPassword := signinPassword + "_new"
		reqBody := views.AccountPasswordUpdateRequest{
			OldPassword: signinPassword,
			NewPassword: newPassword,
		}
		bodyByteArray, err := json.Marshal(reqBody)
		if err != nil {
			assert.NoError(t, err)
		}
		bodyString := string(bodyByteArray)

		req, err := http.NewRequest(http.MethodPatch, "http://localhost"+testServerAddress+
			strings.Replace(constants.ENDPOINT_ACCOUNT_PASSWORD, ":accountUUID", accountUUID.String(), 1),
			strings.NewReader(bodyString))
		assert.NoError(t, err)
		req.Header.Add("Content-Type", "application/json")
		req.Header.Add("Authorization", fmt.Sprintf("Bearer %s", accessToken))

		client := &http.Client{Timeout: time.Second * 3}
		resp, err := client.Do(req)
		assert.NoError(t, err)
		defer resp.Body.Close()
		assert.Equal(t, resp.StatusCode, http.StatusOK)

		assert.NoError(t, doSigninEmail(signinEmail, newPassword, signinRand))
	})

	t.Run("resent confirmation", func(t *testing.T) {
		signinRand, _ := utils.RandomString(10)
		signinEmail := "test_resentconfirmation" + signinRand + "@gmail.com"
		signinPassword := "test_resentconfirmation" + signinRand
		accountUUID, accessToken, _ := prepareTestUser(signinRand, signinEmail, signinPassword)

		req, err := http.NewRequest(http.MethodPost, "http://localhost"+testServerAddress+
			strings.Replace(constants.ENDPOINT_ACCOUNT_RESENDCONFIRMATION, ":accountUUID", accountUUID.String(), 1), nil)
		assert.NoError(t, err)
		req.Header.Add("Content-Type", "application/json")
		req.Header.Add("Authorization", fmt.Sprintf("Bearer %s", accessToken))

		client := &http.Client{Timeout: time.Second * 3}
		resp, err := client.Do(req)
		assert.NoError(t, err)
		defer resp.Body.Close()
		assert.Equal(t, resp.StatusCode, http.StatusOK)
	})

	t.Run("confirm email", func(t *testing.T) {
		signinRand, _ := utils.RandomString(10)
		email := strings.ToLower("test_confirmemail" + signinRand + "@gmail.com")
		password := "test_confirmemail" + signinRand
		accountUUID, _, _ := prepareTestUser(signinRand, email, password)

		ctx := context.TODO()
		accountConfirmation, _ := app.GetAccountConfirmationRepository().GetByEmailAndAccountUUID(ctx, email, accountUUID)
		reqBody := views.AccountEmailConfirmRequest{
			ConformationToken: accountConfirmation.Token,
		}
		bodyByteArray, err := json.Marshal(reqBody)
		if err != nil {
			assert.NoError(t, err)
		}
		bodyString := string(bodyByteArray)

		req, err := http.NewRequest(http.MethodPost, "http://localhost"+testServerAddress+constants.ENDPOINT_ACCOUNT_CONFIRMATION,
			strings.NewReader(bodyString))
		assert.NoError(t, err)
		req.Header.Add("Content-Type", "application/json")

		client := &http.Client{Timeout: time.Second * 3}
		resp, err := client.Do(req)
		assert.NoError(t, err)
		defer resp.Body.Close()
		assert.Equal(t, resp.StatusCode, http.StatusOK)

		account, err := app.GetAccountRepository().GetAccountByUUID(ctx, accountUUID)
		assert.NoError(t, err)
		assert.True(t, account.IsEmailConfirmed)
	})

	t.Run("update roles", func(t *testing.T) {
		signinRand, _ := utils.RandomString(10)
		email := strings.ToLower("test_updateroles" + signinRand + "@knowunity.com")
		accountUUID, accessToken := prepareTestAdminUser(signinRand, email)

		reqBody := views.AccountRoleUpdateRequest{
			Admin:                   true,
			Sales:                   true,
			Content:                 true,
			CustomerSupport:         true,
			Report:                  true,
			Product:                 true,
			Finance:                 true,
			Expansion:               true,
			ExperimentationPlatform: true,
		}
		bodyByteArray, err := json.Marshal(reqBody)
		if err != nil {
			assert.NoError(t, err)
		}
		bodyString := string(bodyByteArray)

		req, err := http.NewRequest(http.MethodPatch,
			"http://localhost"+testServerAddress+strings.Replace(constants.ENDPOINT_ACCOUNT_ROLES, ":accountUUID", accountUUID.String(), 1),
			strings.NewReader(bodyString))
		assert.NoError(t, err)
		req.Header.Add("Content-Type", "application/json")
		req.Header.Add("Authorization", fmt.Sprintf("Bearer %s", accessToken))

		client := &http.Client{Timeout: time.Second * 3}
		resp, err := client.Do(req)
		assert.NoError(t, err)
		defer resp.Body.Close()
		assert.Equal(t, resp.StatusCode, http.StatusOK)
	})

	t.Run("list roles", func(t *testing.T) {
		signinRand, _ := utils.RandomString(10)
		email := strings.ToLower("test_listroles" + signinRand + "@knowunity.com")
		accountUUID, accessToken := prepareTestAdminUser(signinRand, email)

		req, err := http.NewRequest(http.MethodGet,
			"http://localhost"+testServerAddress+strings.Replace(constants.ENDPOINT_ACCOUNT_ROLES, ":accountUUID", accountUUID.String(), 1), nil)
		assert.NoError(t, err)
		req.Header.Add("Content-Type", "application/json")
		req.Header.Add("Authorization", fmt.Sprintf("Bearer %s", accessToken))

		client := &http.Client{Timeout: time.Second * 3}
		resp, err := client.Do(req)
		assert.NoError(t, err)
		defer resp.Body.Close()

		bodyBytes, err := io.ReadAll(resp.Body)
		assert.NoError(t, err)

		respBodyString := string(bodyBytes)
		var content utils.Content
		_ = ParseJSON(strings.NewReader(respBodyString), &content)

		assert.Equal(t, resp.StatusCode, http.StatusOK)
		if c, converted := content.Content.([]interface{}); converted {
			assert.Equal(t, len(c), 1)
		}
	})

	t.Run("delete", func(t *testing.T) {
		cloudscommon.MessagingClientMockLastType = ""
		cloudscommon.MessagingClientMockLastBody = ""

		signinRand, _ := utils.RandomString(10)
		signinEmail := "test_delete" + signinRand + "@gmail.com"
		signinPassword := "test_delete" + signinRand
		accountUUID, accessToken, _ := prepareTestUser(signinRand, signinEmail, signinPassword)

		req, err := http.NewRequest(http.MethodDelete,
			"http://localhost"+testServerAddress+strings.Replace(constants.ENDPOINT_ACCOUNT, ":accountUUID", accountUUID.String(), 1), nil)
		assert.NoError(t, err)
		req.Header.Add("Content-Type", "application/json")
		req.Header.Add("Authorization", fmt.Sprintf("Bearer %s", accessToken))

		client := &http.Client{Timeout: time.Second * 3}
		resp, err := client.Do(req)
		assert.NoError(t, err)
		defer resp.Body.Close()
		assert.NoError(t, err)

		assert.Equal(t, resp.StatusCode, http.StatusOK)

		// NOTE: this type of mocks prevents us from running tests in parallel
		assert.Equal(t, cloudscommon.MessagingClientMockLastType, "ACCOUNT_DELETION_REQUESTED")
		assert.Equal(t, cloudscommon.MessagingClientMockLastBody, "{\"accountUuid\":\""+accountUUID.String()+"\",\"employeeAccountUuid\":null,\"ipAddress\":\"\",\"ipCountryCode\":null}")

		cloudscommon.MessagingClientMockLastType = ""
		cloudscommon.MessagingClientMockLastBody = ""
	})

	t.Run("anonymize accounts", func(t *testing.T) {
		dbManager := app.GetDBManager()
		ctx := context.TODO()

		accountUUIDs := prepareTestAccountsForAnonymization(t, dbManager, ctx)

		req, err := http.NewRequest(http.MethodPost, "http://localhost"+testServerAddress+constants.ENDPOINT_ACCOUNT_ANONYMIZATION, nil)
		assert.NoError(t, err)
		req.Header.Add("Content-Type", "application/json")
		accessToken := "someaccesstoken123"
		config.Secrets.Auth.Service2ServiceApiKey = accessToken
		req.Header.Add("Authorization", fmt.Sprintf("%s %s", constants.HeaderAuthorizationService2Service, accessToken))

		client := &http.Client{Timeout: time.Second * 3}
		resp, err := client.Do(req)
		time.Sleep(5 * time.Second)
		assert.NoError(t, err)
		defer resp.Body.Close()
		assert.Equal(t, resp.StatusCode, http.StatusOK)

		verifyAnonymizedAccounts(t, accountUUIDs, dbManager, ctx)
	})
}

func doSigninEmail(email, password, rand string) error {
	reqBody := views.AuthSignInEmailRequest{
		Email:                        email,
		Password:                     password,
		TwoFactorAuthenticationToken: null.StringFrom(rand),
	}
	bodyByteArray, err := json.Marshal(reqBody)
	if err != nil {
		return errors.Wrap(err, "json")
	}
	bodyString := string(bodyByteArray)

	req, err := http.NewRequest(http.MethodPost, "http://localhost"+testServerAddress+constants.ENDPOINT_AUTH_SIGNIN_EMAIL,
		strings.NewReader(bodyString))
	if err != nil {
		return errors.Wrap(err, "http")
	}
	req.Header.Add("Content-Type", "application/json")

	client := &http.Client{Timeout: time.Second * 3}
	resp, err := client.Do(req)
	if err != nil {
		return errors.Wrap(err, "http")
	}
	defer resp.Body.Close()
	if err != nil || resp.StatusCode != http.StatusOK {
		return errors.Wrap(err, "http")
	}
	return nil
}

func verifyAnonymizedAccounts(t *testing.T, accountUUIDs []uuid.UUID, dbManager database.DBManager, ctx context.Context) {
	var accounts []models.Account
	for _, accountUUID := range accountUUIDs {
		fmt.Println(accountUUID)
		var email string
		_ = dbManager.GetDBro().QueryRowContext(ctx, `SELECT email FROM _account WHERE _account.uuid = $1`, accountUUID).Scan(&email)
		accounts = append(accounts, models.Account{Email: null.StringFrom(email)})
	}
	// deleted but not yet ready to be anonymized
	assert.NotEmpty(t, accounts[0].Email.String)
	assert.NotEmpty(t, accounts[1].Email.String)
	// deleted and freshly anonymized
	assert.Empty(t, accounts[2].Email.String)
	assert.Empty(t, accounts[3].Email.String)
	// deleted and previously anonymized
	assert.Empty(t, accounts[4].Email.String)
	assert.Empty(t, accounts[5].Email.String)
	// active users
	assert.NotEmpty(t, accounts[6].Email.String)
	assert.NotEmpty(t, accounts[7].Email.String)
}

func prepareTestAccountsForAnonymization(t *testing.T, dbManager database.DBManager, ctx context.Context) []uuid.UUID {
	var accountUUIDs []uuid.UUID
	// 8 users, 4 deleted on different dates, 2 anonymized and 2 active
	for i := 0; i < 8; i++ {
		signinRand, _ := utils.RandomString(10)
		signinEmail := "test_anonymize" + signinRand + "@gmail.com"
		signinPassword := "test_anonymize" + signinRand
		accountUUID, _, _ := prepareTestUser(signinRand, signinEmail, signinPassword)
		accountUUIDs = append(accountUUIDs, accountUUID)
	}
	// make 4 account deleted on different dates
	deletedOnOffsets := []time.Duration{
		-24 * 1 * time.Hour,
		-24 * 4 * time.Hour,
		-24 * 8 * time.Hour,
		-24 * 12 * time.Hour,
	}
	for i, deletedOnOffset := range deletedOnOffsets {
		newTime := time.Now().Add(deletedOnOffset)
		fmt.Println(newTime)
		_, _ = dbManager.GetDB().Exec("update account set deleted_on = $1 where uuid = $2", time.Now().Add(deletedOnOffset), accountUUIDs[i])
	}
	// make 2 accounts already anonymized
	tx, _ := dbManager.BeginDBTx(ctx, &sql.TxOptions{})
	for i := 4; i < 6; i++ {
		_ = app.GetAccountRepository().AnonymizeAccount(ctx, tx, accountUUIDs[i])
	}
	err := tx.Commit()
	assert.NoError(t, err)
	return accountUUIDs
}

func prepareTestAdminUser(rand, signinEmail string) (uuid.UUID, string) {
	googleAuthService.ClaimsEmail = signinEmail
	googleAuthService.ClaimsSubject = rand

	err, resp := doSignupGoogle(rand, testServerAddress)
	if err != nil {
		return uuid.UUID{}, ""
	}
	defer resp.Body.Close()
	ctx := context.TODO()
	account, _ := app.GetAccountRepository().GetByEmail(ctx, strings.ToLower(signinEmail))
	dbManager := app.GetDBManager()
	tx, _ := dbManager.BeginDBTx(ctx, &sql.TxOptions{})
	_ = app.GetAccountRoleRepository().Create(ctx, tx, account.UUID, utils.AdminRole)
	_ = tx.Commit()
	accessToken, _, _ := app.GetAuthService().SignInGoogle(ctx, rand, true, services.BotDetectionData{}, false)

	return account.UUID, accessToken.String
}
*/
