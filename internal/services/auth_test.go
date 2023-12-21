package services

/*
import (
	"context"
	"global-auth-service/internal/apierrors"
	"global-auth-service/internal/clouds"
	"global-auth-service/internal/config"
	"global-auth-service/internal/database"
	"global-auth-service/internal/metrics"
	"global-auth-service/internal/models"
	"global-auth-service/internal/utils"
	"testing"

	"github.com/stretchr/testify/assert"
	"gitlab.com/knowunity/go-common/pkg/auth"
	cloudscommon "gitlab.com/knowunity/go-common/pkg/clouds"
)

const (
	SIGNUP_EMAIL            = "account@gmail.com"
	SIGNUP_PASSWORD         = "password123"
	INTERFACE_LANGUAGE_CODE = "de"
)

var configParser ConfigParser
var twoFactorAuthenticationRepository models.TwoFactorAuthenticationRepository
var accountRoleRepository models.AccountRoleRepository
var googleAuthClient clouds.GoogleAuthClient
var appleAuthClient clouds.AppleAuthClient
var rateLimitingService RateLimitingService
var authService AuthService

func initAuthTest(enableSignUpRateLimiting bool, rateLimitServiceLimitReached bool) AuthService {
	prometheusRegister = metrics.PrometheusRegisterMock{}
	authCompliance = AuthComplianceMock{}
	accountAttributesRepository = models.AccountAttributesRepositoryMock{}
	auditService = NewAuditService(&auditLog, &RateLimitServiceMock{})
	oauthRefreshTokenRepository = models.OauthRefreshTokenRepositoryMock{}
	dataCenterNotifierService = DataCenterNotifierServiceMock{}
	accountRepository = models.AccountRepositoryMock{}
	dbManager = &database.DBManagerMock{}
	accountConfirmationRepository = models.AccountConfirmationRepositoryMock{}
	amazonSQSClient = clouds.AmazonSQSClientMock{}
	configParser = ConfigParserMock{
		parameters: config.ParameterData{
			EnableSignUpRateLimiting: enableSignUpRateLimiting,
		},
	}
	twoFactorAuthenticationRepository = models.TwoFactorAuthenticationRepositoryMock{}
	accountRoleRepository = models.AccountRoleRepositoryMock{}
	googleAuthClient = &clouds.GoogleAuthClientMock{}
	appleAuthClient = &clouds.AppleAuthClientMock{}
	rateLimitingService = &RateLimitServiceMock{LimitReached: rateLimitServiceLimitReached}
	messagingService = cloudscommon.MessagingClientMock{}
	jwtSecret := "jwt_secret"
	accessTokenGenerator := NewAccessTokenGeneratorWithHS512(jwtSecret)
	parser := auth.NewAccessTokenParserWithHS512(jwtSecret)
	tokenValidator := auth.NewAccessTokenValidatorImpl(parser)
	accountService = NewAccountServiceImpl(&accountRepository, &dbManager, &accountConfirmationRepository, auditService,
		&amazonSQSClient, &prometheusRegister, &authCompliance, &accountAttributesRepository,
		&oauthRefreshTokenRepository, &dataCenterNotifierService, messagingService)
	tokenService := NewTokensServiceImpl(accessTokenGenerator, tokenValidator, &oauthRefreshTokenRepository, &accountRepository)
	authService = NewAuthServiceImpl(configParser, auditService, &authCompliance, &dbManager, accountService, &oauthRefreshTokenRepository, &accountRepository, twoFactorAuthenticationRepository, accountRoleRepository, googleAuthClient, appleAuthClient, &amazonSQSClient, &dataCenterNotifierService, rateLimitingService, tokenService)
	return authService
}

func TestUnit_AuthServiceImpl_SignUpWithEmail(t *testing.T) {
	t.Run("Create account with email with rate limiting", func(t *testing.T) {
		authService := initAuthTest(true, true)
		ctx := context.TODO()

		botDetectionData := BotDetectionData{
			RequestIPData: RequestIPData{
				IPAddress: "my-ip",
			},
		}
		_, _, err := authService.SignUpEmail(ctx, AccountProfile{}, "password", botDetectionData, false)
		assert.Error(t, err)
		tooManyRequestsError := apierrors.TooManyRequestsError{}
		assert.ErrorIs(t, err, &tooManyRequestsError)
	})
}

func TestUnit_AuthServiceImpl_SignUpWithUsername(t *testing.T) {
	t.Run("Create account with username containing invalid characters", func(t *testing.T) {
		authService := initAuthTest(true, false)
		ctx := context.TODO()

		_, _, err := authService.SignUpUsername(ctx, AccountProfile{Username: "azAZ._%$"}, "pass", BotDetectionData{}, false)
		assert.Error(t, err)
		badRequestError := &apierrors.FormValidationError{}
		assert.ErrorAs(t, err, &badRequestError)
	})

	t.Run("Create account with to short username", func(t *testing.T) {
		authService := initAuthTest(true, false)
		ctx := context.TODO()

		smallUsername, err := utils.RandomString(USERNAME_MIN_LENGTH - 1)
		assert.NoError(t, err)

		_, _, err = authService.SignUpUsername(ctx, AccountProfile{Username: smallUsername}, "pass", BotDetectionData{}, false)
		assert.Error(t, err)
		badRequestError := &apierrors.FormValidationError{}
		assert.ErrorAs(t, err, &badRequestError)
	})
}
*/
