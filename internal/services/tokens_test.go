package services

/*
import (
	"context"
	"encoding/base64"
	"global-auth-service/internal/models"
	"testing"
	"time"

	"github.com/gofrs/uuid"
	"github.com/golang-jwt/jwt/v4"
	"github.com/stretchr/testify/assert"
	"gitlab.com/knowunity/go-common/pkg/auth"
	"gitlab.com/knowunity/go-common/pkg/errors"
)

// #nosec G101 -- This is not a hard-coded secret
const TEST_ACCESS_TOKEN_PRIVATE_KEY = "LS0tLS1CRUdJTiBSU0EgUFJJVkFURSBLRVktLS0tLQpNSUlDWGdJQkFBS0JnUUNPVlNYWWJpTENtYmRrczRlbFpUYmxxMTFEUW5WaWR1bnh3ZEVHRmJiMGp0Z1dXTCtQClFLVU1RYlY1OWduQmlqcWxELzFwNnB5bW9HL1RvN3NoNXd3SGRoeTlBellhcjhxYWh5YmlQWlg1cFNYU2oxMFUKVU9Ka09yU1l5MGpiQi9IUUUzZnZzRXlIQVVEUFNZblZQek1LMU1RL1BwZFhObzFpRUoyRDFLVEU2d0lEQVFBQgpBb0dBU2RKQjRjSWx4emJBMXJzQ3hMYjlSUnVmTUk1Y29hZzVhRWwxSnluR0RZdTA2Y28zK0kyM3pPYWJ3RmpxCjhIWElPdXBUTGtjZjNwQmh6NndoRjlGay9BY25IeXh3OG92OGhOSlBvTlEyNmVuUmdESHM5RGdPWFhwM1VJVmYKVVFXZC9Pbm10QXlyWHExSEdJZFpiVnlxWTdNMHhLUjMwNUwyV0dDNGZHV3VmUEVDUVFETnVDOGdoakk5dER1TgpkVXBZckpScFJSc3JCZHR3UkVPZGVrWXpnNXR2V3FpOVFiOUZXSDhqWWs5c0ljSk8zbkJ1ZENWdnl1T0ROQ1ZSCjU2YzFhemFKQWtFQXNSN2RHcWJ3TEdJOGZZY1ArODhoNmFXVVpkaUsrRHRWZkdSMzdhcmEvQWo0eDBpV3RzeUMKeGpyU0prK1ZncFBDUEg2NHFueDMxai90NENhZkFadkMwd0pCQUthdFEybTdzUHN6aTBpNnJta1lNd3J6MWVaTwowWk90aTRjTktkSFZJTnZnL1hTUno1STArSlhIc29mdTlrc0dpTnZGT1F2UnUvSnpEb1hGQmtJT3d0a0NRUUNCCkNkMUh4NHQrcW1zcmdMU3lYYXQxVDM2WDNIVVNlQmZGc21SMU1GNnQ4OU5iVEpVUXhGb2FGVXg1UU0zSi9lQXEKdHAvUEJUTkJVZjM1cWVsNkFJS2xBa0VBa2tJaU5tYVdBNlExMlRXWURrV0xZOU50NFp1UVRnejRvLzJMNXVWbApnR3FNRXN0U2tqSmpFOGxLRElINjh2TmtyT0NnZGMzdlJocnNDRDJXK2xYZ0lRPT0KLS0tLS1FTkQgUlNBIFBSSVZBVEUgS0VZLS0tLS0="

// #nosec G101 -- This is not a hard-coded secret
const TEST_ACCESS_TOKEN_PUBLIC_KEY = "LS0tLS1CRUdJTiBQVUJMSUMgS0VZLS0tLS0KTUlHZk1BMEdDU3FHU0liM0RRRUJBUVVBQTRHTkFEQ0JpUUtCZ1FDT1ZTWFliaUxDbWJka3M0ZWxaVGJscTExRApRblZpZHVueHdkRUdGYmIwanRnV1dMK1BRS1VNUWJWNTlnbkJpanFsRC8xcDZweW1vRy9UbzdzaDV3d0hkaHk5CkF6WWFyOHFhaHliaVBaWDVwU1hTajEwVVVPSmtPclNZeTBqYkIvSFFFM2Z2c0V5SEFVRFBTWW5WUHpNSzFNUS8KUHBkWE5vMWlFSjJEMUtURTZ3SURBUUFCCi0tLS0tRU5EIFBVQkxJQyBLRVktLS0tLQ=="

func TestUnit_TokenServiceImpl(t *testing.T) {
	t.Run("constructor", func(t *testing.T) {
		generator := &AccessTokenGeneratorMock{}
		parser1 := auth.NewAccessTokenParserWithHS512("some secret")
		parser2 := auth.NewAccessTokenParserWithRS256(TEST_ACCESS_TOKEN_PUBLIC_KEY, "")
		tokenValidator := auth.NewAccessTokenValidatorImpl(parser1, parser2)
		tokensService := NewTokensServiceImpl(generator, tokenValidator, &models.OauthRefreshTokenRepositoryMock{}, &models.AccountRepositoryMock{})

		assert.NotNil(t, tokensService)
	})

	t.Run("error preparing claims", func(t *testing.T) {
		generator := &AccessTokenGeneratorMock{}
		parser := auth.NewAccessTokenParserWithRS256(TEST_ACCESS_TOKEN_PUBLIC_KEY, "")
		tokenValidator := auth.NewAccessTokenValidatorImpl(parser)

		tokensService := NewTokensServiceImpl(generator, tokenValidator, &models.OauthRefreshTokenRepositoryMock{}, &models.AccountRepositoryMock{
			GetRolesError: errors.New("some error"),
		})

		accountUUID := uuid.Must(uuid.NewV4())
		accessToken, refreshToken, err := tokensService.GetOauthTokensForAccount(context.Background(), accountUUID, true)
		assert.Error(t, err)
		assert.Empty(t, accessToken)
		assert.Empty(t, refreshToken)
	})

	t.Run("error generating access token", func(t *testing.T) {
		generator := &AccessTokenGeneratorMock{
			GenerateAccessTokenError: errors.New("some error"),
		}
		parser := auth.NewAccessTokenParserWithRS256(TEST_ACCESS_TOKEN_PUBLIC_KEY, "")
		tokenValidator := auth.NewAccessTokenValidatorImpl(parser)
		tokensService := NewTokensServiceImpl(generator, tokenValidator, &models.OauthRefreshTokenRepositoryMock{}, &models.AccountRepositoryMock{})
		accountUUID := uuid.Must(uuid.NewV4())
		accessToken, refreshToken, err := tokensService.GetOauthTokensForAccount(context.Background(), accountUUID, true)
		assert.Error(t, err)
		assert.Empty(t, accessToken)
		assert.Empty(t, refreshToken)
	})

	t.Run("error generating refresh token", func(t *testing.T) {
		generator := &AccessTokenGeneratorMock{}
		parser := auth.NewAccessTokenParserWithRS256(TEST_ACCESS_TOKEN_PUBLIC_KEY, "")
		tokenValidator := auth.NewAccessTokenValidatorImpl(parser)
		tokensService := NewTokensServiceImpl(generator, tokenValidator, &models.OauthRefreshTokenRepositoryMock{
			CreateError: errors.New("some error"),
		}, &models.AccountRepositoryMock{})

		accountUUID := uuid.Must(uuid.NewV4())
		accessToken, refreshToken, err := tokensService.GetOauthTokensForAccount(context.Background(), accountUUID, true)
		assert.Error(t, err)
		assert.Empty(t, accessToken)
		assert.Empty(t, refreshToken)
	})

	t.Run("tokens generated", func(t *testing.T) {
		generator := NewAccessTokenGeneratorWithRS256(TEST_ACCESS_TOKEN_PRIVATE_KEY)
		parser := auth.NewAccessTokenParserWithRS256(TEST_ACCESS_TOKEN_PUBLIC_KEY, "")
		tokenValidator := auth.NewAccessTokenValidatorImpl(parser)
		tokensService := NewTokensServiceImpl(generator, tokenValidator, &models.OauthRefreshTokenRepositoryMock{}, &models.AccountRepositoryMock{})
		accountUUID := uuid.Must(uuid.NewV4())
		accessToken, refreshToken, err := tokensService.GetOauthTokensForAccount(context.Background(), accountUUID, true)
		assert.NoError(t, err)
		assert.NotEmpty(t, accessToken)
		assert.NotEmpty(t, refreshToken)
	})

	t.Run("validator returned error", func(t *testing.T) {
		generator := &AccessTokenGeneratorMock{}
		parser := auth.NewAccessTokenParserWithRS256(TEST_ACCESS_TOKEN_PUBLIC_KEY, "")
		tokenValidator := auth.NewAccessTokenValidatorImpl(parser)
		tokensService := NewTokensServiceImpl(generator, tokenValidator, &models.OauthRefreshTokenRepositoryMock{}, &models.AccountRepositoryMock{})

		_, _, ok, err := tokensService.CheckAccessToken(context.Background(), "invalid token")
		assert.NoError(t, err)
		assert.False(t, ok)
	})

	t.Run("invalid accountUUID in claims", func(t *testing.T) {
		generator := NewAccessTokenGeneratorWithRS256(TEST_ACCESS_TOKEN_PRIVATE_KEY)
		parser := auth.NewAccessTokenParserWithRS256(TEST_ACCESS_TOKEN_PUBLIC_KEY, "")
		tokenValidator := auth.NewAccessTokenValidatorImpl(parser)
		tokensService := NewTokensServiceImpl(generator, tokenValidator, &models.OauthRefreshTokenRepositoryMock{}, &models.AccountRepositoryMock{})
		invalidAccountUUID := "invalid uuid"

		claims := auth.AccessTokenClaims{
			RegisteredClaims: jwt.RegisteredClaims{
				Subject:   invalidAccountUUID,
				Issuer:    TOKEN_ISSUER,
				Audience:  []string{"*.knowunity.de"},
				ExpiresAt: jwt.NewNumericDate(time.Now().UTC().Add(30 * time.Minute)),
				IssuedAt:  jwt.NewNumericDate(time.Now().UTC()),
			},
		}

		accessToken, _ := generator.GenerateAccessToken(&claims)

		_, _, ok, err := tokensService.CheckAccessToken(context.Background(), accessToken)
		assert.Error(t, err)
		assert.False(t, ok)
	})

	t.Run("accountRepository returns error", func(t *testing.T) {
		generator := NewAccessTokenGeneratorWithRS256(TEST_ACCESS_TOKEN_PRIVATE_KEY)
		parser := auth.NewAccessTokenParserWithRS256(TEST_ACCESS_TOKEN_PUBLIC_KEY, "")
		tokenValidator := auth.NewAccessTokenValidatorImpl(parser)
		tokensService := NewTokensServiceImpl(generator, tokenValidator, &models.OauthRefreshTokenRepositoryMock{}, &models.AccountRepositoryMock{
			ExistsByUUIDError: errors.New("some error"),
		})
		accountUUID := uuid.Must(uuid.NewV4())
		accessToken, _, _ := tokensService.GetOauthTokensForAccount(context.Background(), accountUUID, true)
		_, _, ok, err := tokensService.CheckAccessToken(context.Background(), accessToken.String)
		assert.Error(t, err)
		assert.False(t, ok)
	})

	t.Run("accountRepository cannot find account", func(t *testing.T) {
		generator := NewAccessTokenGeneratorWithRS256(TEST_ACCESS_TOKEN_PRIVATE_KEY)
		parser := auth.NewAccessTokenParserWithRS256(TEST_ACCESS_TOKEN_PUBLIC_KEY, "")
		tokenValidator := auth.NewAccessTokenValidatorImpl(parser)
		tokensService := NewTokensServiceImpl(generator, tokenValidator, &models.OauthRefreshTokenRepositoryMock{}, &models.AccountRepositoryMock{
			ExistsByUUIDResult: false,
		})
		accountUUID := uuid.Must(uuid.NewV4())
		accessToken, _, _ := tokensService.GetOauthTokensForAccount(context.Background(), accountUUID, true)
		_, _, ok, err := tokensService.CheckAccessToken(context.Background(), accessToken.String)
		assert.NoError(t, err)
		assert.False(t, ok)
	})

	t.Run("access token successfully checked", func(t *testing.T) {
		generator := NewAccessTokenGeneratorWithRS256(TEST_ACCESS_TOKEN_PRIVATE_KEY)
		parser := auth.NewAccessTokenParserWithRS256(TEST_ACCESS_TOKEN_PUBLIC_KEY, "")
		tokenValidator := auth.NewAccessTokenValidatorImpl(parser)
		tokensService := NewTokensServiceImpl(generator, tokenValidator, &models.OauthRefreshTokenRepositoryMock{}, &models.AccountRepositoryMock{
			ExistsByUUIDResult: true,
		})
		accountUUID := uuid.Must(uuid.NewV4())
		accessToken, _, _ := tokensService.GetOauthTokensForAccount(context.Background(), accountUUID, true)
		accountUUIDOut, roles, ok, err := tokensService.CheckAccessToken(context.Background(), accessToken.String)
		assert.NoError(t, err)
		assert.Equal(t, accountUUID, accountUUIDOut)
		assert.Equal(t, []string{}, roles)
		assert.True(t, ok)
	})
}

func TestUnit_AccessTokenGeneratorWithHS512(t *testing.T) {
	t.Run("construction without jwt secret", func(t *testing.T) {
		defer func() {
			r := recover()
			err, ok := r.(error)
			assert.True(t, ok)
			assert.Error(t, err)
		}()
		NewAccessTokenGeneratorWithHS512("")
	})

	t.Run("construction with jwt secret", func(t *testing.T) {
		generator := NewAccessTokenGeneratorWithHS512("some secret")
		assert.NotNil(t, generator)
	})

	t.Run("generate access token with empty claims", func(t *testing.T) {
		generator := NewAccessTokenGeneratorWithHS512("some secret")
		token, err := generator.GenerateAccessToken(nil)
		assert.NoError(t, err)
		assert.NotEmpty(t, token)
	})

	t.Run("generate access token with claims", func(t *testing.T) {
		generator := NewAccessTokenGeneratorWithHS512("some secret")
		claims := auth.AccessTokenClaims{
			RegisteredClaims: jwt.RegisteredClaims{
				Subject:   "some subject",
				Issuer:    "some issuer",
				Audience:  jwt.ClaimStrings{"some audience"},
				ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Hour)),
				IssuedAt:  jwt.NewNumericDate(time.Now()),
				NotBefore: jwt.NewNumericDate(time.Now()),
			},
		}
		token, err := generator.GenerateAccessToken(&claims)
		assert.NoError(t, err)
		assert.NotEmpty(t, token)
	})
}

func TestUnit_AccessTokenGeneratorWithRS256(t *testing.T) {
	t.Run("construction without jwt private key", func(t *testing.T) {
		defer func() {
			r := recover()
			err, ok := r.(error)
			assert.True(t, ok)
			assert.Error(t, err)
		}()
		NewAccessTokenGeneratorWithRS256("")
	})

	t.Run("construction with incorrect jwt private key", func(t *testing.T) {
		defer func() {
			r := recover()
			err, ok := r.(error)
			assert.True(t, ok)
			assert.Error(t, err)
		}()
		NewAccessTokenGeneratorWithRS256("incorrect private key")
	})

	t.Run("construction with invalid jwt private key", func(t *testing.T) {
		defer func() {
			r := recover()
			err, ok := r.(error)
			assert.True(t, ok)
			assert.Error(t, err)
		}()
		NewAccessTokenGeneratorWithRS256(base64.StdEncoding.EncodeToString([]byte("incorrect private key")))
	})

	t.Run("construction with correct jwt private key", func(t *testing.T) {
		generator := NewAccessTokenGeneratorWithRS256(TEST_ACCESS_TOKEN_PRIVATE_KEY)
		assert.NotNil(t, generator)
	})

	t.Run("generate access token with empty claims", func(t *testing.T) {
		generator := NewAccessTokenGeneratorWithRS256(TEST_ACCESS_TOKEN_PRIVATE_KEY)
		token, err := generator.GenerateAccessToken(nil)
		assert.NoError(t, err)
		assert.NotEmpty(t, token)
	})

	t.Run("generate access token with claims", func(t *testing.T) {
		generator := NewAccessTokenGeneratorWithRS256(TEST_ACCESS_TOKEN_PRIVATE_KEY)
		claims := auth.AccessTokenClaims{
			RegisteredClaims: jwt.RegisteredClaims{
				Subject:   "some subject",
				Issuer:    "some issuer",
				Audience:  jwt.ClaimStrings{"some audience"},
				ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Hour)),
				IssuedAt:  jwt.NewNumericDate(time.Now()),
				NotBefore: jwt.NewNumericDate(time.Now()),
			},
			Roles: []string{"some role"},
		}
		token, err := generator.GenerateAccessToken(&claims)
		assert.NoError(t, err)
		assert.NotEmpty(t, token)
	})
}
*/
