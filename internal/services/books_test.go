package services

/*
import (
	"context"
	"database/sql"
	"global-auth-service/internal/apierrors"
	"global-auth-service/internal/clouds"
	"global-auth-service/internal/config"
	"global-auth-service/internal/database"
	"global-auth-service/internal/metrics"
	"global-auth-service/internal/models"
	"global-auth-service/internal/utils"
	"testing"

	"github.com/gofrs/uuid"
	"github.com/stretchr/testify/assert"
	cloudscommon "gitlab.com/knowunity/go-common/pkg/clouds"
	"gitlab.com/knowunity/go-common/pkg/errors"
	"golang.org/x/crypto/bcrypt"
	"gopkg.in/guregu/null.v4"
)

var prometheusRegister = metrics.PrometheusRegisterMock{}
var authCompliance = AuthComplianceMock{}
var accountAttributesRepository = models.AccountAttributesRepositoryMock{}
var auditLog = models.AuditLogMock{}
var oauthRefreshTokenRepository = models.OauthRefreshTokenRepositoryMock{}
var dataCenterNotifierService = DataCenterNotifierServiceMock{}
var accountRepository = models.AccountRepositoryMock{}
var dbManager database.DBManager = &database.DBManagerMock{}
var accountConfirmationRepository = models.AccountConfirmationRepositoryMock{}
var amazonSQSClient = clouds.AmazonSQSClientMock{}
var accountService AccountService
var auditService AuditService
var messagingService cloudscommon.MessagingClientMock

func initTest() {
	prometheusRegister = metrics.PrometheusRegisterMock{}
	authCompliance = AuthComplianceMock{}
	accountAttributesRepository = models.AccountAttributesRepositoryMock{}
	auditLog = models.AuditLogMock{}
	oauthRefreshTokenRepository = models.OauthRefreshTokenRepositoryMock{}
	dataCenterNotifierService = DataCenterNotifierServiceMock{}
	accountRepository = models.AccountRepositoryMock{}
	dbManager = &database.DBManagerMock{}
	accountConfirmationRepository = models.AccountConfirmationRepositoryMock{}
	amazonSQSClient = clouds.AmazonSQSClientMock{}
	messagingService = cloudscommon.MessagingClientMock{}
	cloudscommon.MessagingClientMockLastQueueURL = ""
	cloudscommon.MessagingClientMockLastType = ""
	cloudscommon.MessagingClientMockLastBody = ""
	cloudscommon.MessagingClientMockLastDelaySeconds = 0
	cloudscommon.MessagingClientMockBatch = make([]cloudscommon.MessagingMessageMock, 0)

	auditService = NewAuditService(&auditLog, &RateLimitServiceMock{})
	accountService = NewAccountServiceImpl(&accountRepository, &dbManager, &accountConfirmationRepository, auditService,
		&amazonSQSClient, &prometheusRegister, &authCompliance, &accountAttributesRepository,
		&oauthRefreshTokenRepository, &dataCenterNotifierService, &messagingService)
}

func TestUnit_AccountServiceImpl_CreateAccountWithEmail(t *testing.T) {
	t.Run("employee email", func(t *testing.T) {
		initTest()
		ctx := context.TODO()
		tx, _ := dbManager.BeginDBTx(ctx, nil)

		u, ect, err := accountService.CreateAccountWithEmail(ctx, tx, "test@knowunity.com", "username", "DE", "DE", null.StringFrom("pass"), false)
		assert.Error(t, err)
		assert.Equal(t, err.Error(), apierrors.ContactCustomerSupportError{}.Error())
		assert.False(t, accountRepository.CreateInvoked)
		assert.False(t, accountConfirmationRepository.CreateInvoked)
		assert.False(t, amazonSQSClient.SendMessageInvoked)
		assert.Equal(t, u, uuid.NullUUID{})
		assert.Equal(t, ect, null.String{})
	})

	t.Run("account create fails", func(t *testing.T) {
		initTest()
		accountRepository.CreateError = errors.New("sql error")
		ctx := context.TODO()
		tx, _ := dbManager.BeginDBTx(ctx, nil)

		u, ect, err := accountService.CreateAccountWithEmail(ctx, tx, "test@gmail.com", "username", "DE", "DE", null.StringFrom("pass"), false)
		assert.Error(t, err)
		assert.Equal(t, err.Error(), "db: sql error")
		assert.True(t, accountRepository.CreateInvoked)
		assert.False(t, accountConfirmationRepository.CreateInvoked)
		assert.False(t, amazonSQSClient.SendMessageInvoked)
		assert.Equal(t, u, uuid.NullUUID{})
		assert.Equal(t, ect, null.String{})
	})

	t.Run("account confirmation repo fails", func(t *testing.T) {
		initTest()
		accountConfirmationRepository.CreateError = errors.New("sql error")
		ctx := context.TODO()
		tx, _ := dbManager.BeginDBTx(ctx, nil)

		u, ect, err := accountService.CreateAccountWithEmail(ctx, tx, "test@gmail.com", "username", "DE", "DE", null.StringFrom("pass"), false)
		assert.Error(t, err)
		assert.Equal(t, err.Error(), "db: sql error")
		assert.True(t, accountRepository.CreateInvoked)
		assert.True(t, accountConfirmationRepository.CreateInvoked)
		assert.False(t, amazonSQSClient.SendMessageInvoked)
		assert.Equal(t, u, uuid.NullUUID{})
		assert.Equal(t, ect, null.String{})
	})

	t.Run("email confirmation fails", func(t *testing.T) {
		initTest()
		amazonSQSClient.SendMessageErrors = []error{errors.New("http error")}
		ctx := context.TODO()
		tx, _ := dbManager.BeginDBTx(ctx, nil)

		u, ect, err := accountService.CreateAccountWithEmail(ctx, tx, "test@gmail.com", "username", "DE", "DE", null.StringFrom("pass"), false)
		assert.Error(t, err)
		assert.Equal(t, err.Error(), "sqs: http error")
		assert.True(t, accountRepository.CreateInvoked)
		assert.True(t, accountConfirmationRepository.CreateInvoked)
		assert.True(t, amazonSQSClient.SendMessageInvoked)
		assert.Equal(t, u, uuid.NullUUID{})
		assert.Equal(t, ect, null.String{})
	})

	t.Run("account created", func(t *testing.T) {
		initTest()
		accountUUID, _ := uuid.NewV4()
		accountRepository.CreateResult = uuid.NullUUID{UUID: accountUUID, Valid: true}
		ctx := context.TODO()
		tx, _ := dbManager.BeginDBTx(ctx, nil)

		u, ect, err := accountService.CreateAccountWithEmail(ctx, tx, "test@gmail.com", "username", "DE", "DE", null.StringFrom("pass"), false)
		assert.NoError(t, err)
		assert.True(t, accountRepository.CreateInvoked)
		assert.True(t, accountConfirmationRepository.CreateInvoked)
		assert.True(t, amazonSQSClient.SendMessageInvoked)
		assert.Equal(t, u.UUID.String(), accountUUID.String())
		assert.NotEmpty(t, ect)
	})

	t.Run("account created with load test", func(t *testing.T) {
		initTest()
		accountUUID, _ := uuid.NewV4()
		accountRepository.CreateResult = uuid.NullUUID{UUID: accountUUID, Valid: true}
		ctx := context.TODO()
		tx, _ := dbManager.BeginDBTx(ctx, nil)

		u, ect, err := accountService.CreateAccountWithEmail(ctx, tx, "test@gmail.com", "username", "DE", "DE", null.StringFrom("pass"), true)
		assert.NoError(t, err)
		assert.True(t, accountRepository.CreateInvoked)
		assert.True(t, accountConfirmationRepository.CreateInvoked)
		assert.False(t, amazonSQSClient.SendMessageInvoked)
		assert.Equal(t, u.UUID.String(), accountUUID.String())
		assert.NotEmpty(t, ect)
	})
}

func TestUnit_AccountServiceImpl_CreateAccountWithGoogle(t *testing.T) {
	t.Run("employee email with invalid google id", func(t *testing.T) {
		initTest()
		ctx := context.TODO()
		tx, _ := dbManager.BeginDBTx(ctx, nil)

		u, ect, err := accountService.CreateAccountWithGoogle(ctx, tx, "test@knowunity.com", "username", "DE", "DE", false, null.String{}, false)
		assert.Error(t, err)
		assert.Equal(t, err.Error(), apierrors.ContactCustomerSupportError{}.Error())
		assert.False(t, accountRepository.CreateInvoked)
		assert.False(t, accountConfirmationRepository.CreateInvoked)
		assert.False(t, amazonSQSClient.SendMessageInvoked)
		assert.Equal(t, u, uuid.NullUUID{})
		assert.Equal(t, ect, null.String{})
	})

	t.Run("account create fails", func(t *testing.T) {
		initTest()
		accountRepository.CreateError = errors.New("sql error")
		ctx := context.TODO()
		tx, _ := dbManager.BeginDBTx(ctx, nil)

		u, ect, err := accountService.CreateAccountWithGoogle(ctx, tx, "test@gmail.com", "username", "DE", "DE", false, null.StringFrom("google id"), false)
		assert.Error(t, err)
		assert.Equal(t, err.Error(), "db: sql error")
		assert.True(t, accountRepository.CreateInvoked)
		assert.False(t, accountConfirmationRepository.CreateInvoked)
		assert.False(t, amazonSQSClient.SendMessageInvoked)
		assert.Equal(t, u, uuid.NullUUID{})
		assert.Equal(t, ect, null.String{})
	})

	t.Run("account confirmation repo fails", func(t *testing.T) {
		initTest()
		accountConfirmationRepository.CreateError = errors.New("sql error")
		ctx := context.TODO()
		tx, _ := dbManager.BeginDBTx(ctx, nil)

		u, ect, err := accountService.CreateAccountWithGoogle(ctx, tx, "test@gmail.com", "username", "DE", "DE", false, null.StringFrom("google id"), false)
		assert.Error(t, err)
		assert.Equal(t, err.Error(), "db: sql error")
		assert.True(t, accountRepository.CreateInvoked)
		assert.True(t, accountConfirmationRepository.CreateInvoked)
		assert.False(t, amazonSQSClient.SendMessageInvoked)
		assert.Equal(t, u, uuid.NullUUID{})
		assert.Equal(t, ect, null.String{})
	})

	t.Run("email confirmation fails", func(t *testing.T) {
		initTest()
		amazonSQSClient.SendMessageErrors = []error{errors.New("http error")}
		ctx := context.TODO()
		tx, _ := dbManager.BeginDBTx(ctx, nil)

		u, ect, err := accountService.CreateAccountWithGoogle(ctx, tx, "test@gmail.com", "username", "DE", "DE", false, null.StringFrom("google id"), false)
		assert.Error(t, err)
		assert.Equal(t, err.Error(), "sqs: http error")
		assert.True(t, accountRepository.CreateInvoked)
		assert.True(t, accountConfirmationRepository.CreateInvoked)
		assert.True(t, amazonSQSClient.SendMessageInvoked)
		assert.Equal(t, u, uuid.NullUUID{})
		assert.Equal(t, ect, null.String{})
	})

	t.Run("account created with unconfirmed email", func(t *testing.T) {
		initTest()
		accountUUID, _ := uuid.NewV4()
		accountRepository.CreateResult = uuid.NullUUID{UUID: accountUUID, Valid: true}
		ctx := context.TODO()
		tx, _ := dbManager.BeginDBTx(ctx, nil)

		u, ect, err := accountService.CreateAccountWithGoogle(ctx, tx, "test@gmail.com", "username", "DE", "DE", false, null.StringFrom("google id"), false)
		assert.NoError(t, err)
		assert.True(t, accountRepository.CreateInvoked)
		assert.True(t, accountConfirmationRepository.CreateInvoked)
		assert.True(t, amazonSQSClient.SendMessageInvoked)
		assert.Equal(t, u.UUID.String(), accountUUID.String())
		assert.NotEmpty(t, ect)
	})

	t.Run("account created with confirmed email", func(t *testing.T) {
		initTest()
		accountUUID, _ := uuid.NewV4()
		accountRepository.CreateResult = uuid.NullUUID{UUID: accountUUID, Valid: true}
		ctx := context.TODO()
		tx, _ := dbManager.BeginDBTx(ctx, nil)

		u, ect, err := accountService.CreateAccountWithGoogle(ctx, tx, "test@gmail.com", "username", "DE", "DE", true, null.StringFrom("google id"), false)
		assert.NoError(t, err)
		assert.True(t, accountRepository.CreateInvoked)
		assert.False(t, accountConfirmationRepository.CreateInvoked)
		assert.False(t, amazonSQSClient.SendMessageInvoked)
		assert.Equal(t, u.UUID.String(), accountUUID.String())
		assert.Empty(t, ect)
	})

	t.Run("account created with load test", func(t *testing.T) {
		initTest()
		accountUUID, _ := uuid.NewV4()
		accountRepository.CreateResult = uuid.NullUUID{UUID: accountUUID, Valid: true}
		ctx := context.TODO()
		tx, _ := dbManager.BeginDBTx(ctx, nil)

		u, ect, err := accountService.CreateAccountWithGoogle(ctx, tx, "test@gmail.com", "username", "DE", "DE", false, null.StringFrom("google id"), true)
		assert.NoError(t, err)
		assert.True(t, accountRepository.CreateInvoked)
		assert.True(t, accountConfirmationRepository.CreateInvoked)
		assert.False(t, amazonSQSClient.SendMessageInvoked)
		assert.Equal(t, u.UUID.String(), accountUUID.String())
		assert.NotEmpty(t, ect)
	})
}

func TestUnit_AccountServiceImpl_CreateAccountWithApple(t *testing.T) {
	t.Run("employee email with invalid apple id", func(t *testing.T) {
		initTest()
		ctx := context.TODO()
		tx, _ := dbManager.BeginDBTx(ctx, nil)

		u, ect, err := accountService.CreateAccountWithApple(ctx, tx, "test@knowunity.com", "username", "DE", "DE", false, null.String{}, false)
		assert.Error(t, err)
		assert.Equal(t, err.Error(), apierrors.ContactCustomerSupportError{}.Error())
		assert.False(t, accountRepository.CreateInvoked)
		assert.False(t, accountConfirmationRepository.CreateInvoked)
		assert.False(t, amazonSQSClient.SendMessageInvoked)
		assert.Equal(t, u, uuid.NullUUID{})
		assert.Equal(t, ect, null.String{})
	})

	t.Run("account create fails", func(t *testing.T) {
		initTest()
		accountRepository.CreateError = errors.New("sql error")
		ctx := context.TODO()
		tx, _ := dbManager.BeginDBTx(ctx, nil)

		u, ect, err := accountService.CreateAccountWithApple(ctx, tx, "test@gmail.com", "username", "DE", "DE", false, null.StringFrom("apple id"), false)
		assert.Error(t, err)
		assert.Equal(t, err.Error(), "db: sql error")
		assert.True(t, accountRepository.CreateInvoked)
		assert.False(t, accountConfirmationRepository.CreateInvoked)
		assert.False(t, amazonSQSClient.SendMessageInvoked)
		assert.Equal(t, u, uuid.NullUUID{})
		assert.Equal(t, ect, null.String{})
	})

	t.Run("account confirmation repo fails", func(t *testing.T) {
		initTest()
		accountConfirmationRepository.CreateError = errors.New("sql error")
		ctx := context.TODO()
		tx, _ := dbManager.BeginDBTx(ctx, nil)

		u, ect, err := accountService.CreateAccountWithApple(ctx, tx, "test@gmail.com", "username", "DE", "DE", false, null.StringFrom("apple id"), false)
		assert.Error(t, err)
		assert.Equal(t, err.Error(), "db: sql error")
		assert.True(t, accountRepository.CreateInvoked)
		assert.True(t, accountConfirmationRepository.CreateInvoked)
		assert.False(t, amazonSQSClient.SendMessageInvoked)
		assert.Equal(t, u, uuid.NullUUID{})
		assert.Equal(t, ect, null.String{})
	})

	t.Run("email confirmation fails", func(t *testing.T) {
		initTest()
		amazonSQSClient.SendMessageErrors = []error{errors.New("http error")}
		ctx := context.TODO()
		tx, _ := dbManager.BeginDBTx(ctx, nil)

		u, ect, err := accountService.CreateAccountWithApple(ctx, tx, "test@gmail.com", "username", "DE", "DE", false, null.StringFrom("apple id"), false)
		assert.Error(t, err)
		assert.Equal(t, err.Error(), "sqs: http error")
		assert.True(t, accountRepository.CreateInvoked)
		assert.True(t, accountConfirmationRepository.CreateInvoked)
		assert.True(t, amazonSQSClient.SendMessageInvoked)
		assert.Equal(t, u, uuid.NullUUID{})
		assert.Equal(t, ect, null.String{})
	})

	t.Run("account created with unconfirmed email", func(t *testing.T) {
		initTest()
		accountUUID, _ := uuid.NewV4()
		accountRepository.CreateResult = uuid.NullUUID{UUID: accountUUID, Valid: true}
		ctx := context.TODO()
		tx, _ := dbManager.BeginDBTx(ctx, nil)

		u, ect, err := accountService.CreateAccountWithApple(ctx, tx, "test@gmail.com", "username", "DE", "DE", false, null.StringFrom("apple id"), false)
		assert.NoError(t, err)
		assert.True(t, accountRepository.CreateInvoked)
		assert.True(t, accountConfirmationRepository.CreateInvoked)
		assert.True(t, amazonSQSClient.SendMessageInvoked)
		assert.Equal(t, u.UUID.String(), accountUUID.String())
		assert.NotEmpty(t, ect)
	})

	t.Run("account created with confirmed email", func(t *testing.T) {
		initTest()
		accountUUID, _ := uuid.NewV4()
		accountRepository.CreateResult = uuid.NullUUID{UUID: accountUUID, Valid: true}
		ctx := context.TODO()
		tx, _ := dbManager.BeginDBTx(ctx, nil)

		u, ect, err := accountService.CreateAccountWithApple(ctx, tx, "test@gmail.com", "username", "DE", "DE", true, null.StringFrom("apple id"), false)
		assert.NoError(t, err)
		assert.True(t, accountRepository.CreateInvoked)
		assert.False(t, accountConfirmationRepository.CreateInvoked)
		assert.False(t, amazonSQSClient.SendMessageInvoked)
		assert.Equal(t, u.UUID.String(), accountUUID.String())
		assert.Empty(t, ect)
	})

	t.Run("account created with load test", func(t *testing.T) {
		initTest()
		accountUUID, _ := uuid.NewV4()
		accountRepository.CreateResult = uuid.NullUUID{UUID: accountUUID, Valid: true}
		ctx := context.TODO()
		tx, _ := dbManager.BeginDBTx(ctx, nil)

		u, ect, err := accountService.CreateAccountWithApple(ctx, tx, "test@gmail.com", "username", "DE", "DE", false, null.StringFrom("apple id"), true)
		assert.NoError(t, err)
		assert.True(t, accountRepository.CreateInvoked)
		assert.True(t, accountConfirmationRepository.CreateInvoked)
		assert.False(t, amazonSQSClient.SendMessageInvoked)
		assert.Equal(t, u.UUID.String(), accountUUID.String())
		assert.NotEmpty(t, ect)
	})
}

func TestUnit_AccountServiceImpl_UpdateEmail(t *testing.T) {
	t.Run("new email is employee email", func(t *testing.T) {
		initTest()
		ctx := context.TODO()

		err := accountService.UpdateEmail(ctx, uuid.UUID{}, uuid.UUID{}, "test@knowunity.com", null.StringFrom("password"), BotDetectionData{})
		assert.Error(t, err)
		assert.Equal(t, err.Error(), apierrors.ContactCustomerSupportError{}.Error())
		assert.False(t, authCompliance.IsValidSignupEmailInvoked)
		assert.False(t, accountRepository.GetAuthUUIDInvoked)
		assert.False(t, accountRepository.UpdateEmailInvoked)
		assert.False(t, auditLog.CreateInvoked)
		assert.False(t, amazonSQSClient.SendMessageInvoked)
	})

	t.Run("new email invalid", func(t *testing.T) {
		initTest()
		authCompliance.TrashEmailError = errors.New("bad email")
		ctx := context.TODO()

		err := accountService.UpdateEmail(ctx, uuid.UUID{}, uuid.UUID{}, "test@gmail.com", null.StringFrom("password"), BotDetectionData{})
		assert.Error(t, err)
		badRequestErr := apierrors.BadRequestError{}
		assert.Equal(t, err.Error(), badRequestErr.Error())
		assert.True(t, authCompliance.IsValidSignupEmailInvoked)
		assert.False(t, accountRepository.GetAuthUUIDInvoked)
		assert.False(t, accountRepository.UpdateEmailInvoked)
		assert.False(t, auditLog.CreateInvoked)
		assert.False(t, amazonSQSClient.SendMessageInvoked)
	})

	t.Run("no email account found", func(t *testing.T) {
		initTest()
		accountRepository.GetAuthUUIDError = sql.ErrNoRows
		ctx := context.TODO()

		err := accountService.UpdateEmail(ctx, uuid.UUID{}, uuid.UUID{}, "test@gmail.com", null.StringFrom("password"), BotDetectionData{})
		assert.Error(t, err)
		notFoundError := apierrors.NotFoundError{}
		assert.Equal(t, err.Error(), notFoundError.Error())
		assert.True(t, authCompliance.IsValidSignupEmailInvoked)
		assert.True(t, accountRepository.GetAuthUUIDInvoked)
		assert.False(t, accountRepository.UpdateEmailInvoked)
		assert.False(t, auditLog.CreateInvoked)
		assert.False(t, amazonSQSClient.SendMessageInvoked)
	})

	t.Run("unauthorized update", func(t *testing.T) {
		initTest()
		accountUUID, _ := uuid.NewV4()
		authenticatedAccountUUID, _ := uuid.NewV4()
		ctx := context.TODO()

		err := accountService.UpdateEmail(ctx, authenticatedAccountUUID, accountUUID, "test@gmail.com", null.StringFrom("password"), BotDetectionData{})
		assert.Error(t, err)
		forbiddenError := apierrors.ForbiddenError{}
		assert.Equal(t, err.Error(), forbiddenError.Error())
		assert.True(t, authCompliance.IsValidSignupEmailInvoked)
		assert.True(t, accountRepository.GetAuthUUIDInvoked)
		assert.False(t, accountRepository.UpdateEmailInvoked)
		assert.False(t, auditLog.CreateInvoked)
		assert.False(t, amazonSQSClient.SendMessageInvoked)
	})

	t.Run("invalid password", func(t *testing.T) {
		initTest()
		accountUUID, _ := uuid.NewV4()
		accountRepository.GetAuthUUIDResult = models.AccountAuth{UUID: accountUUID, Email: null.StringFrom("email@mail.com")}
		ctx := context.TODO()

		err := accountService.UpdateEmail(ctx, accountUUID, accountUUID, "test@gmail.com", null.StringFrom("password"), BotDetectionData{})
		assert.Error(t, err)
		invalidCredentialsError := apierrors.InvalidCredentialsError{}
		assert.Equal(t, err.Error(), invalidCredentialsError.Error())
		assert.True(t, authCompliance.IsValidSignupEmailInvoked)
		assert.True(t, accountRepository.GetAuthUUIDInvoked)
		assert.False(t, accountRepository.UpdateEmailInvoked)
		assert.True(t, auditLog.CreateInvoked)
		assert.False(t, amazonSQSClient.SendMessageInvoked)
	})

	t.Run("missing password", func(t *testing.T) {
		initTest()
		accountUUID, _ := uuid.NewV4()
		accountRepository.GetAuthUUIDResult = models.AccountAuth{UUID: accountUUID, Email: null.StringFrom("email@mail.com")}
		ctx := context.TODO()

		err := accountService.UpdateEmail(ctx, accountUUID, accountUUID, "test@gmail.com", null.String{}, BotDetectionData{})
		assert.Error(t, err)
		badRequestError := apierrors.BadRequestError{}
		assert.Equal(t, err.Error(), badRequestError.Error())
		assert.True(t, authCompliance.IsValidSignupEmailInvoked)
		assert.True(t, accountRepository.GetAuthUUIDInvoked)
		assert.False(t, accountRepository.UpdateEmailInvoked)
		assert.True(t, auditLog.CreateInvoked)
		assert.False(t, amazonSQSClient.SendMessageInvoked)
	})

	t.Run("new email in use", func(t *testing.T) {
		initTest()
		accountUUID, _ := uuid.NewV4()
		password := "password"
		hashedPassword, _ := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
		accountAuth := models.AccountAuth{UUID: accountUUID, Password: null.StringFrom(string(hashedPassword))}
		accountRepository.GetAuthUUIDResult = accountAuth
		accountRepository.ExistsByEmailResult = true
		ctx := context.TODO()

		err := accountService.UpdateEmail(ctx, accountUUID, accountUUID, "test@gmail.com", null.StringFrom(password), BotDetectionData{})
		assert.Error(t, err)
		invalidCredentialsError := apierrors.EmailInUseError{}
		assert.Equal(t, err.Error(), invalidCredentialsError.Error())
		assert.True(t, authCompliance.IsValidSignupEmailInvoked)
		assert.True(t, accountRepository.GetAuthUUIDInvoked)
		assert.False(t, accountRepository.UpdateEmailInvoked)
		assert.False(t, auditLog.CreateInvoked)
		assert.False(t, amazonSQSClient.SendMessageInvoked)
	})

	t.Run("old email is employee email", func(t *testing.T) {
		initTest()
		accountUUID, _ := uuid.NewV4()
		password := "password"
		hashedPassword, _ := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
		accountAuth := models.AccountAuth{Email: null.StringFrom("test@knowunity.com"), UUID: accountUUID, Password: null.StringFrom(string(hashedPassword))}
		accountRepository.GetAuthUUIDResult = accountAuth
		accountRepository.ExistsByEmailResult = false
		ctx := context.TODO()

		err := accountService.UpdateEmail(ctx, accountUUID, accountUUID, "test@gmail.com", null.StringFrom(password), BotDetectionData{})
		assert.Error(t, err)
		assert.Equal(t, err.Error(), apierrors.ContactCustomerSupportError{}.Error())
		assert.True(t, authCompliance.IsValidSignupEmailInvoked)
		assert.True(t, accountRepository.GetAuthUUIDInvoked)
		assert.False(t, accountRepository.UpdateEmailInvoked)
		assert.False(t, auditLog.CreateInvoked)
		assert.False(t, amazonSQSClient.SendMessageInvoked)
	})

	t.Run("cannot persist email change", func(t *testing.T) {
		initTest()
		accountUUID, _ := uuid.NewV4()
		password := "password"
		hashedPassword, _ := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
		accountAuth := models.AccountAuth{Email: null.StringFrom("test@gmail.com"), UUID: accountUUID, Password: null.StringFrom(string(hashedPassword))}
		accountRepository.UpdateEmailError = errors.New("db: db")
		accountRepository.GetAuthUUIDResult = accountAuth
		accountRepository.ExistsByEmailResult = false
		ctx := context.TODO()

		err := accountService.UpdateEmail(ctx, accountUUID, accountUUID, "test@gmail.com", null.StringFrom(password), BotDetectionData{})
		assert.Error(t, err)
		assert.Equal(t, err.Error(), "db: db: db")
		assert.True(t, authCompliance.IsValidSignupEmailInvoked)
		assert.True(t, accountRepository.GetAuthUUIDInvoked)
		assert.True(t, accountRepository.UpdateEmailInvoked)
		assert.False(t, auditLog.CreateInvoked)
		assert.False(t, amazonSQSClient.SendMessageInvoked)
	})

	t.Run("cannot create audit log", func(t *testing.T) {
		initTest()
		accountUUID, _ := uuid.NewV4()
		password := "password"
		hashedPassword, _ := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
		accountAuth := models.AccountAuth{Email: null.StringFrom("test@gmail.com"), UUID: accountUUID, Password: null.StringFrom(string(hashedPassword))}
		accountRepository.GetAuthUUIDResult = accountAuth
		accountRepository.ExistsByEmailResult = false
		auditLog.CreateWithTransactionError = errors.New("error")
		ctx := context.TODO()

		err := accountService.UpdateEmail(ctx, accountUUID, accountUUID, "test@gmail.com", null.StringFrom(password), BotDetectionData{})
		assert.Error(t, err)
		assert.Equal(t, err.Error(), "db: db: error")
		assert.True(t, authCompliance.IsValidSignupEmailInvoked)
		assert.True(t, accountRepository.GetAuthUUIDInvoked)
		assert.True(t, accountRepository.UpdateEmailInvoked)
		assert.False(t, auditLog.CreateInvoked)
		assert.False(t, amazonSQSClient.SendMessageInvoked)
	})

	t.Run("cannot creat account confirmation", func(t *testing.T) {
		initTest()
		accountUUID, _ := uuid.NewV4()
		password := "password"
		hashedPassword, _ := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
		accountAuth := models.AccountAuth{Email: null.StringFrom("test@gmail.com"), UUID: accountUUID, Password: null.StringFrom(string(hashedPassword))}
		accountRepository.GetAuthUUIDResult = accountAuth
		accountRepository.ExistsByEmailResult = false
		accountConfirmationRepository.CreateError = errors.New("error")
		ctx := context.TODO()

		err := accountService.UpdateEmail(ctx, accountUUID, accountUUID, "test@gmail.com", null.StringFrom(password), BotDetectionData{})
		assert.Error(t, err)
		assert.Equal(t, err.Error(), "db: error")
		assert.True(t, authCompliance.IsValidSignupEmailInvoked)
		assert.True(t, accountRepository.GetAuthUUIDInvoked)
		assert.True(t, accountRepository.UpdateEmailInvoked)
		assert.False(t, auditLog.CreateInvoked)
		assert.False(t, amazonSQSClient.SendMessageInvoked)
	})

	t.Run("cannot send confirmation message to sqs", func(t *testing.T) {
		initTest()
		accountUUID, _ := uuid.NewV4()
		password := "password"
		hashedPassword, _ := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
		accountAuth := models.AccountAuth{Email: null.StringFrom("test@gmail.com"), UUID: accountUUID, Password: null.StringFrom(string(hashedPassword))}
		accountRepository.GetAuthUUIDResult = accountAuth
		accountRepository.ExistsByEmailResult = false
		amazonSQSClient.SendMessageErrors = []error{errors.New("error")}
		ctx := context.TODO()

		err := accountService.UpdateEmail(ctx, accountUUID, accountUUID, "test@gmail.com", null.StringFrom(password), BotDetectionData{})
		assert.Error(t, err)
		assert.Equal(t, err.Error(), "sqs: error")
		assert.True(t, authCompliance.IsValidSignupEmailInvoked)
		assert.True(t, accountRepository.GetAuthUUIDInvoked)
		assert.True(t, accountRepository.UpdateEmailInvoked)
		assert.False(t, auditLog.CreateInvoked)
		assert.True(t, amazonSQSClient.SendMessageInvoked)
	})

	t.Run("cannot sync profile with data centers", func(t *testing.T) {
		initTest()
		accountUUID, _ := uuid.NewV4()
		password := "password"
		hashedPassword, _ := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
		accountAuth := models.AccountAuth{Email: null.StringFrom("test@gmail.com"), UUID: accountUUID, Password: null.StringFrom(string(hashedPassword))}
		accountRepository.GetAuthUUIDResult = accountAuth
		accountRepository.ExistsByEmailResult = false
		dataCenterNotifierService.NotifyDataCentersForProfileUpdatesError = errors.New("error")
		ctx := context.TODO()

		err := accountService.UpdateEmail(ctx, accountUUID, accountUUID, "test@gmail.com", null.StringFrom(password), BotDetectionData{})
		assert.Error(t, err)
		assert.True(t, authCompliance.IsValidSignupEmailInvoked)
		assert.True(t, accountRepository.GetAuthUUIDInvoked)
		assert.True(t, accountRepository.UpdateEmailInvoked)
		assert.False(t, auditLog.CreateInvoked)
		assert.True(t, amazonSQSClient.SendMessageInvoked)
	})

	t.Run("db transaction fails", func(t *testing.T) {
		initTest()
		dbManager = &database.DBManagerMock{TxCommitError: errors.New("tx error")}
		accountUUID, _ := uuid.NewV4()
		password := "password"
		dataCenters := []string{"eu-central-1"}
		hashedPassword, _ := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
		accountAuth := models.AccountAuth{Email: null.StringFrom("test@gmail.com"), UUID: accountUUID, Password: null.StringFrom(string(hashedPassword))}
		accountRepository.GetAuthUUIDResult = accountAuth
		accountRepository.ExistsByEmailResult = false
		accountRepository.GetAccountDataCentersResult = dataCenters
		queue := config.SQSQueue{Name: "", AccountID: "", IsFifo: false}
		queues := []config.SQSQueue{queue}
		dataCenterRegionSyncSqsQueues := config.DataCenterRegionSyncSqsQueues{DataCenterRegion: dataCenters[0], Queues: queues}
		dataCenterSyncSqsQueues := []config.DataCenterRegionSyncSqsQueues{dataCenterRegionSyncSqsQueues}
		config.Parameters.DataCenterQueues.DataCenterSyncSqsQueues = dataCenterSyncSqsQueues

		accountService := NewAccountServiceImpl(&accountRepository, &dbManager, &accountConfirmationRepository, auditService,
			&amazonSQSClient, &prometheusRegister, &authCompliance, &accountAttributesRepository,
			&oauthRefreshTokenRepository, &dataCenterNotifierService, messagingService)
		ctx := context.TODO()

		err := accountService.UpdateEmail(ctx, accountUUID, accountUUID, "test@gmail.com", null.StringFrom(password), BotDetectionData{})
		assert.Error(t, err)
		assert.Equal(t, err.Error(), "db: tx error")
		assert.True(t, authCompliance.IsValidSignupEmailInvoked)
		assert.True(t, accountRepository.GetAuthUUIDInvoked)
		assert.True(t, accountRepository.UpdateEmailInvoked)
		assert.False(t, auditLog.CreateInvoked)
		assert.True(t, amazonSQSClient.SendMessageInvoked)
	})

	t.Run("sending EMAIL_UPDATED_NOTIFICATION message fails", func(t *testing.T) {
		initTest()
		accountUUID, _ := uuid.NewV4()
		password := "password"
		dataCenters := []string{"eu-central-1"}
		hashedPassword, _ := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
		accountAuth := models.AccountAuth{Email: null.StringFrom("test@gmail.com"), UUID: accountUUID, Password: null.StringFrom(string(hashedPassword))}
		accountRepository.GetAuthUUIDResult = accountAuth
		accountRepository.ExistsByEmailResult = false
		accountRepository.GetAccountDataCentersResult = dataCenters
		queue := config.SQSQueue{Name: "", AccountID: "", IsFifo: false}
		queues := []config.SQSQueue{queue}
		dataCenterRegionSyncSqsQueues := config.DataCenterRegionSyncSqsQueues{DataCenterRegion: dataCenters[0], Queues: queues}
		dataCenterSyncSqsQueues := []config.DataCenterRegionSyncSqsQueues{dataCenterRegionSyncSqsQueues}
		config.Parameters.DataCenterQueues.DataCenterSyncSqsQueues = dataCenterSyncSqsQueues
		amazonSQSClient.SendMessageErrors = []error{nil, errors.New("sqs error")}
		ctx := context.TODO()

		err := accountService.UpdateEmail(ctx, accountUUID, accountUUID, "test@gmail.com", null.StringFrom(password), BotDetectionData{})
		assert.Error(t, err)
		assert.True(t, authCompliance.IsValidSignupEmailInvoked)
		assert.True(t, accountRepository.GetAuthUUIDInvoked)
		assert.True(t, accountRepository.UpdateEmailInvoked)
		assert.False(t, auditLog.CreateInvoked)
		assert.True(t, amazonSQSClient.SendMessageInvoked)
	})

	t.Run("successfully update the email without providing the password of a user who has no attached email yet", func(t *testing.T) {
		initTest()
		accountUUID, _ := uuid.NewV4()
		password := "password"
		dataCenters := []string{"eu-central-1"}
		hashedPassword, _ := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
		accountAuth := models.AccountAuth{UUID: accountUUID, Password: null.StringFrom(string(hashedPassword))}
		accountRepository.GetAuthUUIDResult = accountAuth
		accountRepository.ExistsByEmailResult = false
		accountRepository.GetAccountDataCentersResult = dataCenters
		queue := config.SQSQueue{Name: "", AccountID: "", IsFifo: false}
		queues := []config.SQSQueue{queue}
		dataCenterRegionSyncSqsQueues := config.DataCenterRegionSyncSqsQueues{DataCenterRegion: dataCenters[0], Queues: queues}
		dataCenterSyncSqsQueues := []config.DataCenterRegionSyncSqsQueues{dataCenterRegionSyncSqsQueues}
		config.Parameters.DataCenterQueues.DataCenterSyncSqsQueues = dataCenterSyncSqsQueues
		ctx := context.TODO()

		err := accountService.UpdateEmail(ctx, accountUUID, accountUUID, "test@gmail.com", null.String{}, BotDetectionData{})
		assert.NoError(t, err)
		assert.True(t, authCompliance.IsValidSignupEmailInvoked)
		assert.True(t, accountRepository.GetAuthUUIDInvoked)
		assert.True(t, accountRepository.UpdateEmailInvoked)
		assert.False(t, auditLog.CreateInvoked)
		assert.True(t, amazonSQSClient.SendMessageInvoked)
	})

	t.Run("success", func(t *testing.T) {
		initTest()
		accountUUID, _ := uuid.NewV4()
		password := "password"
		dataCenters := []string{"eu-central-1"}
		hashedPassword, _ := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
		accountAuth := models.AccountAuth{Email: null.StringFrom("test@gmail.com"), UUID: accountUUID, Password: null.StringFrom(string(hashedPassword))}
		accountRepository.GetAuthUUIDResult = accountAuth
		accountRepository.ExistsByEmailResult = false
		accountRepository.GetAccountDataCentersResult = dataCenters
		queue := config.SQSQueue{Name: "", AccountID: "", IsFifo: false}
		queues := []config.SQSQueue{queue}
		dataCenterRegionSyncSqsQueues := config.DataCenterRegionSyncSqsQueues{DataCenterRegion: dataCenters[0], Queues: queues}
		dataCenterSyncSqsQueues := []config.DataCenterRegionSyncSqsQueues{dataCenterRegionSyncSqsQueues}
		config.Parameters.DataCenterQueues.DataCenterSyncSqsQueues = dataCenterSyncSqsQueues
		ctx := context.TODO()

		err := accountService.UpdateEmail(ctx, accountUUID, accountUUID, "test@gmail.com", null.StringFrom(password), BotDetectionData{})
		assert.NoError(t, err)
		assert.True(t, authCompliance.IsValidSignupEmailInvoked)
		assert.True(t, accountRepository.GetAuthUUIDInvoked)
		assert.True(t, accountRepository.UpdateEmailInvoked)
		assert.False(t, auditLog.CreateInvoked)
		assert.True(t, amazonSQSClient.SendMessageInvoked)
	})
}

func TestUnit_AccountServiceImpl_UpdateUsername(t *testing.T) {

	t.Run("new username is too short", func(t *testing.T) {
		initTest()
		ctx := context.TODO()

		smallUsername, err := utils.RandomString(USERNAME_MIN_LENGTH - 1)
		assert.NoError(t, err)

		err = accountService.UpdateUsername(ctx, uuid.UUID{}, uuid.UUID{}, smallUsername, BotDetectionData{})
		assert.Error(t, err)
		badRequestErr := apierrors.FormValidationError{}
		assert.Equal(t, err.Error(), badRequestErr.Error())
		assert.False(t, accountRepository.UpdateUsernameInvoked)
		assert.False(t, auditLog.CreateInvoked)
		assert.False(t, amazonSQSClient.SendMessageInvoked)
	})

	t.Run("new username contains invalid characters", func(t *testing.T) {
		initTest()
		ctx := context.TODO()

		err := accountService.UpdateUsername(ctx, uuid.UUID{}, uuid.UUID{}, "testAZ%&$", BotDetectionData{})
		assert.Error(t, err)
		badRequestErr := apierrors.FormValidationError{}
		assert.Equal(t, err.Error(), badRequestErr.Error())
		assert.False(t, accountRepository.UpdateUsernameInvoked)
		assert.False(t, auditLog.CreateInvoked)
		assert.False(t, amazonSQSClient.SendMessageInvoked)
	})

	t.Run("no username account found", func(t *testing.T) {
		initTest()
		accountRepository.GetAuthUUIDError = sql.ErrNoRows
		ctx := context.TODO()

		err := accountService.UpdateUsername(ctx, uuid.UUID{}, uuid.UUID{}, "test", BotDetectionData{})
		assert.Error(t, err)
		notFoundError := apierrors.NotFoundError{}
		assert.Equal(t, err.Error(), notFoundError.Error())
		assert.True(t, accountRepository.GetAuthUUIDInvoked)
		assert.False(t, accountRepository.UpdateUsernameInvoked)
		assert.False(t, auditLog.CreateInvoked)
		assert.False(t, amazonSQSClient.SendMessageInvoked)
	})

	t.Run("unauthorized update", func(t *testing.T) {
		initTest()
		accountUUID, _ := uuid.NewV4()
		authenticatedAccountUUID, _ := uuid.NewV4()
		ctx := context.TODO()

		err := accountService.UpdateUsername(ctx, authenticatedAccountUUID, accountUUID, "test@gmail.com", BotDetectionData{})
		assert.Error(t, err)
		forbiddenError := apierrors.ForbiddenError{}
		assert.Equal(t, err.Error(), forbiddenError.Error())
		assert.True(t, accountRepository.GetAuthUUIDInvoked)
		assert.False(t, accountRepository.UpdateUsernameInvoked)
		assert.False(t, auditLog.CreateInvoked)
		assert.False(t, amazonSQSClient.SendMessageInvoked)
	})

	t.Run("new username in use", func(t *testing.T) {
		initTest()
		accountUUID, _ := uuid.NewV4()
		accountAuth := models.AccountAuth{UUID: accountUUID}
		accountRepository.GetAuthUUIDResult = accountAuth
		accountRepository.ExistsByUsernameResult = true
		ctx := context.TODO()

		err := accountService.UpdateUsername(ctx, accountUUID, accountUUID, "test", BotDetectionData{})
		assert.Error(t, err)
		invalidCredentialsError := apierrors.UsernameInUseError{}
		assert.Equal(t, err.Error(), invalidCredentialsError.Error())
		assert.True(t, accountRepository.GetAuthUUIDInvoked)
		assert.False(t, accountRepository.UpdateUsernameInvoked)
		assert.False(t, auditLog.CreateInvoked)
		assert.False(t, amazonSQSClient.SendMessageInvoked)
	})

	t.Run("cannot persist username change", func(t *testing.T) {
		initTest()
		accountUUID, _ := uuid.NewV4()
		accountAuth := models.AccountAuth{Email: null.StringFrom("test@gmail.com"), UUID: accountUUID}
		accountRepository.UpdateUsernameError = errors.New("db: db")
		accountRepository.GetAuthUUIDResult = accountAuth
		accountRepository.ExistsByUsernameResult = false
		ctx := context.TODO()

		err := accountService.UpdateUsername(ctx, accountUUID, accountUUID, "test123", BotDetectionData{})
		assert.Error(t, err)
		assert.Equal(t, err.Error(), "db: db: db")
		assert.True(t, accountRepository.GetAuthUUIDInvoked)
		assert.True(t, accountRepository.UpdateUsernameInvoked)
		assert.False(t, auditLog.CreateInvoked)
		assert.False(t, amazonSQSClient.SendMessageInvoked)
	})

	t.Run("cannot create audit log", func(t *testing.T) {
		initTest()
		accountUUID, _ := uuid.NewV4()
		accountAuth := models.AccountAuth{Email: null.StringFrom("test@gmail.com"), UUID: accountUUID}
		accountRepository.GetAuthUUIDResult = accountAuth
		accountRepository.ExistsByUsernameResult = false
		auditLog.CreateWithTransactionError = errors.New("error")
		ctx := context.TODO()

		err := accountService.UpdateUsername(ctx, accountUUID, accountUUID, "test123", BotDetectionData{})
		assert.Error(t, err)
		assert.Equal(t, err.Error(), "db: db: error")
		assert.True(t, accountRepository.GetAuthUUIDInvoked)
		assert.True(t, accountRepository.UpdateUsernameInvoked)
		assert.False(t, auditLog.CreateInvoked)
		assert.False(t, amazonSQSClient.SendMessageInvoked)
	})

	t.Run("cannot sync profile with data centers", func(t *testing.T) {
		initTest()
		accountUUID, _ := uuid.NewV4()
		accountAuth := models.AccountAuth{Email: null.StringFrom("test@gmail.com"), UUID: accountUUID}
		accountRepository.GetAuthUUIDResult = accountAuth
		accountRepository.ExistsByUsernameResult = false
		dataCenterNotifierService.NotifyDataCentersForProfileUpdatesError = errors.New("error")
		ctx := context.TODO()

		err := accountService.UpdateUsername(ctx, accountUUID, accountUUID, "test123", BotDetectionData{})
		assert.Error(t, err)
		assert.True(t, accountRepository.GetAuthUUIDInvoked)
		assert.True(t, accountRepository.UpdateUsernameInvoked)
		assert.False(t, auditLog.CreateInvoked)
	})

	t.Run("db transaction fails", func(t *testing.T) {
		initTest()
		dbManager = &database.DBManagerMock{TxCommitError: errors.New("tx error")}
		accountUUID, _ := uuid.NewV4()
		dataCenters := []string{"eu-central-1"}
		accountAuth := models.AccountAuth{Email: null.StringFrom("test@gmail.com"), UUID: accountUUID}
		accountRepository.GetAuthUUIDResult = accountAuth
		accountRepository.ExistsByUsernameResult = false
		accountRepository.GetAccountDataCentersResult = dataCenters
		queue := config.SQSQueue{Name: "", AccountID: "", IsFifo: false}
		queues := []config.SQSQueue{queue}
		dataCenterRegionSyncSqsQueues := config.DataCenterRegionSyncSqsQueues{DataCenterRegion: dataCenters[0], Queues: queues}
		dataCenterSyncSqsQueues := []config.DataCenterRegionSyncSqsQueues{dataCenterRegionSyncSqsQueues}
		config.Parameters.DataCenterQueues.DataCenterSyncSqsQueues = dataCenterSyncSqsQueues

		accountService := NewAccountServiceImpl(&accountRepository, &dbManager, &accountConfirmationRepository, auditService,
			&amazonSQSClient, &prometheusRegister, &authCompliance, &accountAttributesRepository,
			&oauthRefreshTokenRepository, &dataCenterNotifierService, messagingService)
		ctx := context.TODO()

		err := accountService.UpdateUsername(ctx, accountUUID, accountUUID, "test123", BotDetectionData{})
		assert.Error(t, err)
		assert.Equal(t, err.Error(), "db: tx error")
		assert.True(t, accountRepository.GetAuthUUIDInvoked)
		assert.True(t, accountRepository.UpdateUsernameInvoked)
		assert.False(t, auditLog.CreateInvoked)
	})

	t.Run("success", func(t *testing.T) {
		initTest()
		accountUUID, _ := uuid.NewV4()
		dataCenters := []string{"eu-central-1"}
		accountAuth := models.AccountAuth{Email: null.StringFrom("test@gmail.com"), UUID: accountUUID}
		accountRepository.GetAuthUUIDResult = accountAuth
		accountRepository.ExistsByUsernameResult = false
		accountRepository.GetAccountDataCentersResult = dataCenters
		queue := config.SQSQueue{Name: "", AccountID: "", IsFifo: false}
		queues := []config.SQSQueue{queue}
		dataCenterRegionSyncSqsQueues := config.DataCenterRegionSyncSqsQueues{DataCenterRegion: dataCenters[0], Queues: queues}
		dataCenterSyncSqsQueues := []config.DataCenterRegionSyncSqsQueues{dataCenterRegionSyncSqsQueues}
		config.Parameters.DataCenterQueues.DataCenterSyncSqsQueues = dataCenterSyncSqsQueues
		ctx := context.TODO()

		err := accountService.UpdateUsername(ctx, accountUUID, accountUUID, "test123", BotDetectionData{})
		assert.NoError(t, err)
		assert.True(t, accountRepository.GetAuthUUIDInvoked)
		assert.True(t, accountRepository.UpdateUsernameInvoked)
		assert.True(t, auditLog.CreateWithTransactionInvoked)
	})
}

func TestUnit_AccountServiceImpl_UpdatePassword(t *testing.T) {
	t.Run("no password account found", func(t *testing.T) {
		initTest()
		accountRepository.GetAuthUUIDError = sql.ErrNoRows
		ctx := context.TODO()

		err := accountService.UpdatePassword(ctx, uuid.UUID{}, uuid.UUID{}, "pass123", "password456", BotDetectionData{})
		assert.Error(t, err)
		notFoundError := apierrors.NotFoundError{}
		assert.Equal(t, err.Error(), notFoundError.Error())
		assert.True(t, accountRepository.GetAuthUUIDInvoked)
		assert.False(t, accountRepository.UpdatePasswordInvoked)
		assert.False(t, auditLog.CreateWithTransactionInvoked)
		assert.False(t, dataCenterNotifierService.NotifyDataCentersForProfileUpdatesInvoked)
	})

	t.Run("unauthorized update", func(t *testing.T) {
		initTest()
		accountUUID, _ := uuid.NewV4()
		authenticatedAccountUUID, _ := uuid.NewV4()
		accountAuth := models.AccountAuth{UUID: accountUUID}
		accountRepository.GetAuthUUIDResult = accountAuth
		ctx := context.TODO()

		err := accountService.UpdatePassword(ctx, authenticatedAccountUUID, accountUUID, "pass123", "pass456", BotDetectionData{})
		assert.Error(t, err)
		forbiddenError := apierrors.ForbiddenError{}
		assert.Equal(t, err.Error(), forbiddenError.Error())
		assert.True(t, accountRepository.GetAuthUUIDInvoked)
		assert.False(t, accountRepository.UpdatePasswordInvoked)
		assert.False(t, auditLog.CreateWithTransactionInvoked)
		assert.False(t, dataCenterNotifierService.NotifyDataCentersForProfileUpdatesInvoked)
	})

	t.Run("brute force detected", func(t *testing.T) {
		initTest()
		auditService := AuditServiceImpl{&auditLog, &RateLimitServiceMock{LimitReached: true}}
		accountService = NewAccountServiceImpl(&accountRepository, &dbManager, &accountConfirmationRepository, &auditService,
			&amazonSQSClient, &prometheusRegister, &authCompliance, &accountAttributesRepository,
			&oauthRefreshTokenRepository, &dataCenterNotifierService, messagingService)
		authenticatedAccountUUID, _ := uuid.NewV4()
		accountAuth := models.AccountAuth{UUID: authenticatedAccountUUID}
		accountRepository.GetAuthUUIDResult = accountAuth
		ctx := context.TODO()

		err := accountService.UpdatePassword(ctx, authenticatedAccountUUID, authenticatedAccountUUID, "pass123", "pass456", BotDetectionData{})
		assert.Error(t, err)
		forbiddenError := apierrors.TooManyRequestsError{}
		assert.Equal(t, err.Error(), forbiddenError.Error())
		assert.True(t, accountRepository.GetAuthUUIDInvoked)
		assert.False(t, accountRepository.UpdatePasswordInvoked)
		assert.True(t, auditLog.CreateInvoked)
		assert.False(t, auditLog.CreateWithTransactionInvoked)
		assert.False(t, dataCenterNotifierService.NotifyDataCentersForProfileUpdatesInvoked)
	})

	t.Run("brute force check fails", func(t *testing.T) {
		initTest()
		authenticatedAccountUUID, _ := uuid.NewV4()
		accountAuth := models.AccountAuth{UUID: authenticatedAccountUUID}
		accountRepository.GetAuthUUIDResult = accountAuth
		auditLog.CountTypeForLastHourError = errors.New("error")
		ctx := context.TODO()

		err := accountService.UpdatePassword(ctx, authenticatedAccountUUID, authenticatedAccountUUID, "pass123", "pass456", BotDetectionData{})
		assert.Error(t, err)
		assert.True(t, accountRepository.GetAuthUUIDInvoked)
		assert.False(t, accountRepository.UpdatePasswordInvoked)
		assert.False(t, auditLog.CreateWithTransactionInvoked)
		assert.False(t, dataCenterNotifierService.NotifyDataCentersForProfileUpdatesInvoked)
	})

	t.Run("invalid old password", func(t *testing.T) {
		initTest()
		accountUUID, _ := uuid.NewV4()
		oldPassword := "oldpassword"
		hashedPassword, _ := bcrypt.GenerateFromPassword([]byte(oldPassword), bcrypt.DefaultCost)
		accountAuth := models.AccountAuth{UUID: accountUUID, Password: null.StringFrom(string(hashedPassword))}
		accountRepository.GetAuthUUIDResult = accountAuth
		ctx := context.TODO()

		err := accountService.UpdatePassword(ctx, accountUUID, accountUUID, "oldPassword12345", "newpassword12345", BotDetectionData{})
		assert.Error(t, err)
		invalidCredentialsError := apierrors.InvalidCredentialsError{}
		assert.Equal(t, err.Error(), invalidCredentialsError.Error())
		assert.True(t, accountRepository.GetAuthUUIDInvoked)
		assert.False(t, accountRepository.UpdatePasswordInvoked)
		assert.True(t, auditLog.CreateInvoked)
		assert.False(t, auditLog.CreateWithTransactionInvoked)
		assert.False(t, dataCenterNotifierService.NotifyDataCentersForProfileUpdatesInvoked)
	})

	t.Run("new password same as old password", func(t *testing.T) {
		initTest()
		accountUUID, _ := uuid.NewV4()
		oldPassword := "oldpassword12345"
		hashedPassword, _ := bcrypt.GenerateFromPassword([]byte(oldPassword), bcrypt.DefaultCost)
		accountAuth := models.AccountAuth{UUID: accountUUID, Password: null.StringFrom(string(hashedPassword))}
		accountRepository.GetAuthUUIDResult = accountAuth
		ctx := context.TODO()

		err := accountService.UpdatePassword(ctx, accountUUID, accountUUID, oldPassword, oldPassword, BotDetectionData{})
		assert.NoError(t, err)
		assert.True(t, accountRepository.GetAuthUUIDInvoked)
		assert.False(t, accountRepository.UpdatePasswordInvoked)
		assert.False(t, auditLog.CreateWithTransactionInvoked)
		assert.False(t, dataCenterNotifierService.NotifyDataCentersForProfileUpdatesInvoked)
	})

	t.Run("cannot persist password change", func(t *testing.T) {
		initTest()
		accountUUID, _ := uuid.NewV4()
		oldPassword := "oldpassword12345"
		hashedPassword, _ := bcrypt.GenerateFromPassword([]byte(oldPassword), bcrypt.DefaultCost)
		accountAuth := models.AccountAuth{UUID: accountUUID, Password: null.StringFrom(string(hashedPassword))}
		accountRepository.UpdatePasswordError = errors.New("db")
		accountRepository.GetAuthUUIDResult = accountAuth
		ctx := context.TODO()

		err := accountService.UpdatePassword(ctx, accountUUID, accountUUID, oldPassword, "password98765", BotDetectionData{})
		assert.Error(t, err)
		assert.Equal(t, err.Error(), "db: db")
		assert.True(t, accountRepository.GetAuthUUIDInvoked)
		assert.True(t, accountRepository.UpdatePasswordInvoked)
		assert.False(t, auditLog.CreateWithTransactionInvoked)
		assert.False(t, dataCenterNotifierService.NotifyDataCentersForProfileUpdatesInvoked)
	})

	t.Run("db transaction fails", func(t *testing.T) {
		initTest()
		var dbManager database.DBManager = &database.DBManagerMock{TxCommitError: errors.New("tx error")}
		accountUUID, _ := uuid.NewV4()
		oldPassword := "oldpassword12345"
		hashedPassword, _ := bcrypt.GenerateFromPassword([]byte(oldPassword), bcrypt.DefaultCost)
		accountAuth := models.AccountAuth{UUID: accountUUID, Password: null.StringFrom(string(hashedPassword))}
		accountRepository.GetAuthUUIDResult = accountAuth
		accountService := NewAccountServiceImpl(&accountRepository, &dbManager, &accountConfirmationRepository, auditService,
			&amazonSQSClient, &prometheusRegister, &authCompliance, &accountAttributesRepository,
			&oauthRefreshTokenRepository, &dataCenterNotifierService, messagingService)
		ctx := context.TODO()

		err := accountService.UpdatePassword(ctx, accountUUID, accountUUID, oldPassword, "password98765", BotDetectionData{})
		assert.Error(t, err)
		assert.Equal(t, err.Error(), "db: tx error")
		assert.True(t, accountRepository.GetAuthUUIDInvoked)
		assert.True(t, accountRepository.UpdatePasswordInvoked)
		assert.False(t, auditLog.CreateInvoked)
		assert.True(t, auditLog.CreateWithTransactionInvoked)
	})

	t.Run("success", func(t *testing.T) {
		initTest()
		accountUUID, _ := uuid.NewV4()
		oldPassword := "oldpassword12345"
		hashedPassword, _ := bcrypt.GenerateFromPassword([]byte(oldPassword), bcrypt.DefaultCost)
		accountAuth := models.AccountAuth{UUID: accountUUID, Password: null.StringFrom(string(hashedPassword))}
		accountRepository.GetAuthUUIDResult = accountAuth
		ctx := context.TODO()

		err := accountService.UpdatePassword(ctx, accountUUID, accountUUID, oldPassword, "password98765", BotDetectionData{})
		assert.NoError(t, err)
		assert.True(t, accountRepository.GetAuthUUIDInvoked)
		assert.True(t, accountRepository.UpdatePasswordInvoked)
		assert.False(t, auditLog.CreateInvoked)
		assert.True(t, auditLog.CreateWithTransactionInvoked)
	})
}

func TestUnit_AccountServiceImpl_ResendConfirmation(t *testing.T) {
	t.Run("no resend confirmation account found", func(t *testing.T) {
		initTest()
		accountRepository.GetAuthUUIDError = sql.ErrNoRows
		ctx := context.TODO()

		err := accountService.ResendConfirmation(ctx, uuid.UUID{}, uuid.UUID{})
		assert.Error(t, err)
		notFoundError := apierrors.NotFoundError{}
		assert.Equal(t, err.Error(), notFoundError.Error())
		assert.True(t, accountRepository.GetAuthUUIDInvoked)
		assert.False(t, accountConfirmationRepository.GetByEmailAndAccountUUIDInvoked)
		assert.False(t, amazonSQSClient.SendMessageInvoked)
	})

	t.Run("unauthorized invocation", func(t *testing.T) {
		initTest()
		accountUUID, _ := uuid.NewV4()
		authenticatedAccountUUID, _ := uuid.NewV4()
		accountAuth := models.AccountAuth{UUID: accountUUID}
		accountRepository.GetAuthUUIDResult = accountAuth
		ctx := context.TODO()

		err := accountService.ResendConfirmation(ctx, authenticatedAccountUUID, accountUUID)
		assert.Error(t, err)
		forbiddenError := apierrors.ForbiddenError{}
		assert.Equal(t, err.Error(), forbiddenError.Error())
		assert.True(t, accountRepository.GetAuthUUIDInvoked)
		assert.False(t, accountConfirmationRepository.GetByEmailAndAccountUUIDInvoked)
		assert.False(t, amazonSQSClient.SendMessageInvoked)
	})

	t.Run("confirmation not found", func(t *testing.T) {
		initTest()
		accountUUID, _ := uuid.NewV4()
		accountAuth := models.AccountAuth{UUID: accountUUID}
		accountRepository.GetAuthUUIDResult = accountAuth
		accountConfirmationRepository.GetByEmailAndAccountUUIDError = sql.ErrNoRows
		ctx := context.TODO()

		err := accountService.ResendConfirmation(ctx, accountUUID, accountUUID)
		assert.Error(t, err)
		notFoundError := apierrors.NotFoundError{}
		assert.Equal(t, err.Error(), notFoundError.Error())
		assert.True(t, accountRepository.GetAuthUUIDInvoked)
		assert.True(t, accountConfirmationRepository.GetByEmailAndAccountUUIDInvoked)
		assert.False(t, amazonSQSClient.SendMessageInvoked)
	})

	t.Run("resending confirmation fails", func(t *testing.T) {
		initTest()
		accountUUID, _ := uuid.NewV4()
		accountAuth := models.AccountAuth{UUID: accountUUID}
		accountRepository.GetAuthUUIDResult = accountAuth
		accountConfirmationRepository.GetByEmailAndAccountUUIDResult = models.AccountConfirmation{}
		amazonSQSClient.SendMessageErrors = []error{errors.New("sqs error")}
		ctx := context.TODO()

		err := accountService.ResendConfirmation(ctx, accountUUID, accountUUID)
		assert.Error(t, err)
		assert.True(t, accountRepository.GetAuthUUIDInvoked)
		assert.True(t, accountConfirmationRepository.GetByEmailAndAccountUUIDInvoked)
		assert.True(t, amazonSQSClient.SendMessageInvoked)
	})

	t.Run("success", func(t *testing.T) {
		initTest()
		accountUUID, _ := uuid.NewV4()
		accountAuth := models.AccountAuth{UUID: accountUUID}
		accountRepository.GetAuthUUIDResult = accountAuth
		accountConfirmationRepository.GetByEmailAndAccountUUIDResult = models.AccountConfirmation{}
		ctx := context.TODO()

		err := accountService.ResendConfirmation(ctx, accountUUID, accountUUID)
		assert.NoError(t, err)
		assert.True(t, accountRepository.GetAuthUUIDInvoked)
		assert.True(t, accountConfirmationRepository.GetByEmailAndAccountUUIDInvoked)
		assert.True(t, amazonSQSClient.SendMessageInvoked)
	})
}

func TestUnit_AccountServiceImpl_ConfirmEmail(t *testing.T) {
	t.Run("confirmation not found", func(t *testing.T) {
		initTest()
		accountUUID, _ := uuid.NewV4()
		accountAuth := models.AccountAuth{UUID: accountUUID}
		accountRepository.GetAuthUUIDResult = accountAuth
		accountConfirmationRepository.GetByTokenError = sql.ErrNoRows
		ctx := context.TODO()

		confirmationToken := "token123"
		err := accountService.ConfirmEmail(ctx, confirmationToken, BotDetectionData{})
		assert.Error(t, err)
		notFoundError := apierrors.NotFoundError{}
		assert.Equal(t, err.Error(), notFoundError.Error())
		assert.True(t, accountConfirmationRepository.GetByTokenInvoked)
		assert.False(t, accountRepository.GetAccountByUUIDInvoked)
		assert.False(t, accountRepository.SetActiveInvoked)
		assert.False(t, accountConfirmationRepository.DeleteInvoked)
		assert.False(t, auditLog.CreateWithTransactionInvoked)
		assert.False(t, dataCenterNotifierService.NotifyDataCentersForProfileUpdatesInvoked)
	})

	t.Run("no confirm email account found", func(t *testing.T) {
		initTest()
		accountRepository.GetAccountByUUIDError = sql.ErrNoRows
		ctx := context.TODO()
		confirmationToken := "token123"

		err := accountService.ConfirmEmail(ctx, confirmationToken, BotDetectionData{})
		assert.Error(t, err)
		notFoundError := apierrors.NotFoundError{}
		assert.Equal(t, err.Error(), notFoundError.Error())
		assert.True(t, accountConfirmationRepository.GetByTokenInvoked)
		assert.True(t, accountRepository.GetAccountByUUIDInvoked)
		assert.False(t, accountRepository.SetActiveInvoked)
		assert.False(t, accountConfirmationRepository.DeleteInvoked)
		assert.False(t, auditLog.CreateWithTransactionInvoked)
		assert.False(t, dataCenterNotifierService.NotifyDataCentersForProfileUpdatesInvoked)
	})

	t.Run("confirmation emails miss match", func(t *testing.T) {
		initTest()
		accountRepository.GetAccountByUUIDResult = models.Account{Email: null.StringFrom("test1@gmail.com")}
		accountConfirmationRepository.GetByTokenResult = models.AccountConfirmation{Email: "test2@gmail.com"}
		ctx := context.TODO()
		confirmationToken := "token123"

		err := accountService.ConfirmEmail(ctx, confirmationToken, BotDetectionData{})
		assert.Error(t, err)
		assert.True(t, accountConfirmationRepository.GetByTokenInvoked)
		assert.True(t, accountRepository.GetAccountByUUIDInvoked)
		assert.False(t, accountRepository.SetActiveInvoked)
		assert.False(t, accountConfirmationRepository.DeleteInvoked)
		assert.False(t, auditLog.CreateWithTransactionInvoked)
		assert.False(t, dataCenterNotifierService.NotifyDataCentersForProfileUpdatesInvoked)
	})

	t.Run("cannot start db transaction", func(t *testing.T) {
		initTest()
		var dbManager database.DBManager = database.DBManagerMock{TxError: errors.New("db")}
		ctx := context.TODO()
		confirmationToken := "token123"

		accountService := NewAccountServiceImpl(&accountRepository, &dbManager, &accountConfirmationRepository, auditService,
			&amazonSQSClient, &prometheusRegister, &authCompliance, &accountAttributesRepository,
			&oauthRefreshTokenRepository, &dataCenterNotifierService, messagingService)
		err := accountService.ConfirmEmail(ctx, confirmationToken, BotDetectionData{})
		assert.Error(t, err)
		assert.True(t, accountConfirmationRepository.GetByTokenInvoked)
		assert.True(t, accountRepository.GetAccountByUUIDInvoked)
		assert.False(t, accountRepository.SetActiveInvoked)
		assert.False(t, accountConfirmationRepository.DeleteInvoked)
		assert.False(t, auditLog.CreateWithTransactionInvoked)
		assert.False(t, dataCenterNotifierService.NotifyDataCentersForProfileUpdatesInvoked)
	})

	t.Run("set active account fails", func(t *testing.T) {
		initTest()
		ctx := context.TODO()
		confirmationToken := "token123"
		accountRepository.SetActiveError = errors.New("db error")

		err := accountService.ConfirmEmail(ctx, confirmationToken, BotDetectionData{})
		assert.Error(t, err)
		assert.True(t, accountConfirmationRepository.GetByTokenInvoked)
		assert.True(t, accountRepository.GetAccountByUUIDInvoked)
		assert.True(t, accountRepository.SetActiveInvoked)
		assert.False(t, accountConfirmationRepository.DeleteInvoked)
		assert.False(t, auditLog.CreateWithTransactionInvoked)
		assert.False(t, dataCenterNotifierService.NotifyDataCentersForProfileUpdatesInvoked)
	})

	t.Run("delete of the confirmation token fails", func(t *testing.T) {
		initTest()
		ctx := context.TODO()
		confirmationToken := "token123"
		accountConfirmationRepository.DeleteError = errors.New("db error")

		err := accountService.ConfirmEmail(ctx, confirmationToken, BotDetectionData{})
		assert.Error(t, err)
		assert.True(t, accountConfirmationRepository.GetByTokenInvoked)
		assert.True(t, accountRepository.GetAccountByUUIDInvoked)
		assert.True(t, accountRepository.SetActiveInvoked)
		assert.True(t, accountConfirmationRepository.DeleteInvoked)
		assert.False(t, auditLog.CreateWithTransactionInvoked)
		assert.False(t, dataCenterNotifierService.NotifyDataCentersForProfileUpdatesInvoked)
	})

	t.Run("audit log creation fails", func(t *testing.T) {
		initTest()
		ctx := context.TODO()
		confirmationToken := "token123"
		auditLog.CreateWithTransactionError = errors.New("db error")

		err := accountService.ConfirmEmail(ctx, confirmationToken, BotDetectionData{})
		assert.Error(t, err)
		assert.True(t, accountConfirmationRepository.GetByTokenInvoked)
		assert.True(t, accountRepository.GetAccountByUUIDInvoked)
		assert.True(t, accountRepository.SetActiveInvoked)
		assert.True(t, accountConfirmationRepository.DeleteInvoked)
		assert.True(t, auditLog.CreateWithTransactionInvoked)
		assert.False(t, dataCenterNotifierService.NotifyDataCentersForProfileUpdatesInvoked)
	})

	t.Run("notifiying of data center fails", func(t *testing.T) {
		initTest()
		ctx := context.TODO()
		confirmationToken := "token123"
		dataCenterNotifierService.NotifyDataCentersForProfileUpdatesError = errors.New("db error")

		err := accountService.ConfirmEmail(ctx, confirmationToken, BotDetectionData{})
		assert.Error(t, err)
		assert.True(t, accountConfirmationRepository.GetByTokenInvoked)
		assert.True(t, accountRepository.GetAccountByUUIDInvoked)
		assert.True(t, accountRepository.SetActiveInvoked)
		assert.True(t, accountConfirmationRepository.DeleteInvoked)
		assert.True(t, auditLog.CreateWithTransactionInvoked)
		assert.True(t, dataCenterNotifierService.NotifyDataCentersForProfileUpdatesInvoked)
	})

	t.Run("db transaction cannot be committed", func(t *testing.T) {
		initTest()
		var dbManager database.DBManager = &database.DBManagerMock{TxCommitError: errors.New("db")}
		confirmationToken := "token123"
		accountService := NewAccountServiceImpl(&accountRepository, &dbManager, &accountConfirmationRepository, auditService,
			&amazonSQSClient, &prometheusRegister, &authCompliance, &accountAttributesRepository,
			&oauthRefreshTokenRepository, &dataCenterNotifierService, messagingService)
		ctx := context.TODO()

		err := accountService.ConfirmEmail(ctx, confirmationToken, BotDetectionData{})
		assert.Error(t, err)
		assert.True(t, accountConfirmationRepository.GetByTokenInvoked)
		assert.True(t, accountRepository.GetAccountByUUIDInvoked)
		assert.True(t, accountRepository.SetActiveInvoked)
		assert.True(t, accountConfirmationRepository.DeleteInvoked)
		assert.True(t, auditLog.CreateWithTransactionInvoked)
		assert.True(t, dataCenterNotifierService.NotifyDataCentersForProfileUpdatesInvoked)
	})

	t.Run("db transaction cannot be committed", func(t *testing.T) {
		initTest()
		confirmationToken := "token123"
		ctx := context.TODO()

		assert.NoError(t, accountService.ConfirmEmail(ctx, confirmationToken, BotDetectionData{}))
		assert.True(t, accountConfirmationRepository.GetByTokenInvoked)
		assert.True(t, accountRepository.GetAccountByUUIDInvoked)
		assert.True(t, accountRepository.SetActiveInvoked)
		assert.True(t, accountConfirmationRepository.DeleteInvoked)
		assert.True(t, auditLog.CreateWithTransactionInvoked)
		assert.True(t, dataCenterNotifierService.NotifyDataCentersForProfileUpdatesInvoked)
	})
}

func TestUnit_AccountServiceImpl_TryDelete(t *testing.T) {
	t.Run("account not found", func(t *testing.T) {
		initTest()
		accountRepository.GetAuthUUIDError = sql.ErrNoRows
		ctx := context.TODO()

		authenticatedAccountUUID, _ := uuid.NewV4()
		accountUUID, _ := uuid.NewV4()
		err := accountService.TryDelete(ctx, authenticatedAccountUUID, accountUUID, utils.RoleAccess{}, RequestIPData{})
		assert.Error(t, err)
		notFoundError := apierrors.NotFoundError{}
		assert.Equal(t, err.Error(), notFoundError.Error())
		assert.True(t, accountRepository.GetAuthUUIDInvoked)
		assert.False(t, accountRepository.DeleteInvoked)
		assert.False(t, auditLog.CreateWithTransactionInvoked)
		assert.False(t, dataCenterNotifierService.NotifyDataCentersForProfileUpdatesInvoked)
		assert.False(t, oauthRefreshTokenRepository.DeleteByAccountUUIDInvoked)
		assert.False(t, accountConfirmationRepository.DeleteByAccountUUIDInvoked)
	})

	t.Run("non admin account trying to delete another account", func(t *testing.T) {
		initTest()
		ctx := context.TODO()

		authenticatedAccountUUID, _ := uuid.NewV4()
		accountUUID, _ := uuid.NewV4()
		err := accountService.TryDelete(ctx, authenticatedAccountUUID, accountUUID, utils.RoleAccess{}, RequestIPData{})
		assert.Error(t, err)
		notFoundError := apierrors.ForbiddenError{}
		assert.Equal(t, err.Error(), notFoundError.Error())
		assert.True(t, accountRepository.GetAuthUUIDInvoked)
		assert.False(t, accountRepository.DeleteInvoked)
		assert.False(t, auditLog.CreateWithTransactionInvoked)
		assert.False(t, dataCenterNotifierService.NotifyDataCentersForProfileUpdatesInvoked)
		assert.False(t, oauthRefreshTokenRepository.DeleteByAccountUUIDInvoked)
		assert.False(t, accountConfirmationRepository.DeleteByAccountUUIDInvoked)
	})

	t.Run("trying to delete company account", func(t *testing.T) {
		initTest()
		ctx := context.TODO()
		accountRepository.GetAuthUUIDResult = models.AccountAuth{Email: null.StringFrom("test@knowunity.com")}
		accountUUID, _ := uuid.NewV4()
		err := accountService.TryDelete(ctx, accountUUID, accountUUID, utils.RoleAccess{AccountDeleteAccess: true}, RequestIPData{})
		assert.Error(t, err)
		notFoundError := apierrors.ContactCustomerSupportError{}
		assert.Equal(t, err.Error(), notFoundError.Error())
		assert.True(t, accountRepository.GetAuthUUIDInvoked)
		assert.False(t, accountRepository.DeleteInvoked)
		assert.False(t, auditLog.CreateWithTransactionInvoked)
		assert.False(t, dataCenterNotifierService.NotifyDataCentersForProfileUpdatesInvoked)
		assert.False(t, oauthRefreshTokenRepository.DeleteByAccountUUIDInvoked)
		assert.False(t, accountConfirmationRepository.DeleteByAccountUUIDInvoked)
	})

	t.Run("success", func(t *testing.T) {
		initTest()
		ctx := context.TODO()
		accountRepository.GetAuthUUIDResult = models.AccountAuth{Email: null.StringFrom("test@gmail.com")}
		accountUUID, _ := uuid.NewV4()

		err := accountService.TryDelete(ctx, accountUUID, accountUUID, utils.RoleAccess{AccountDeleteAccess: true}, RequestIPData{})
		assert.NoError(t, err)
		assert.True(t, accountRepository.GetAuthUUIDInvoked)
		assert.Equal(t, cloudscommon.MessagingClientMockLastQueueURL, "")
		assert.Equal(t, cloudscommon.MessagingClientMockLastType, "ACCOUNT_DELETION_REQUESTED")
		assert.Equal(t, cloudscommon.MessagingClientMockLastBody, "{\"accountUuid\":\""+accountUUID.String()+"\",\"employeeAccountUuid\":\""+accountUUID.String()+"\",\"ipAddress\":\"\",\"ipCountryCode\":null}")
		assert.Equal(t, cloudscommon.MessagingClientMockLastDelaySeconds, int64(0))
		assert.Equal(t, cloudscommon.MessagingClientMockBatch, []cloudscommon.MessagingMessageMock{})
	})
}

func TestUnit_AccountServiceImpl_Delete(t *testing.T) {
	t.Run("cannot start db transaction", func(t *testing.T) {
		initTest()
		var dbManager database.DBManager = database.DBManagerMock{TxError: errors.New("db")}
		ctx := context.TODO()
		accountUUID, _ := uuid.NewV4()

		accountService := NewAccountServiceImpl(&accountRepository, &dbManager, &accountConfirmationRepository, auditService,
			&amazonSQSClient, &prometheusRegister, &authCompliance, &accountAttributesRepository,
			&oauthRefreshTokenRepository, &dataCenterNotifierService, messagingService)
		err := accountService.Delete(ctx, accountUUID, uuid.NullUUID{UUID: accountUUID}, RequestIPData{})
		assert.Error(t, err)
		assert.False(t, accountRepository.DeleteInvoked)
		assert.False(t, auditLog.CreateWithTransactionInvoked)
		assert.False(t, dataCenterNotifierService.NotifyDataCentersForProfileUpdatesInvoked)
		assert.False(t, oauthRefreshTokenRepository.DeleteByAccountUUIDInvoked)
		assert.False(t, accountConfirmationRepository.DeleteByAccountUUIDInvoked)
	})

	t.Run("cannot notify data centers", func(t *testing.T) {
		initTest()
		ctx := context.TODO()
		dataCenterNotifierService.NotifyDataCentersForProfileUpdatesError = errors.New("error")
		accountUUID, _ := uuid.NewV4()

		err := accountService.Delete(ctx, accountUUID, uuid.NullUUID{UUID: accountUUID}, RequestIPData{})
		assert.Error(t, err)
		assert.True(t, dataCenterNotifierService.NotifyDataCentersForProfileUpdatesInvoked)
		assert.True(t, accountRepository.DeleteInvoked)
		assert.True(t, auditLog.CreateWithTransactionInvoked)
		assert.True(t, oauthRefreshTokenRepository.DeleteByAccountUUIDInvoked)
		assert.True(t, accountConfirmationRepository.DeleteByAccountUUIDInvoked)
	})

	t.Run("delete fails", func(t *testing.T) {
		initTest()
		ctx := context.TODO()
		accountRepository.DeleteError = errors.New("error")
		accountUUID, _ := uuid.NewV4()

		err := accountService.Delete(ctx, accountUUID, uuid.NullUUID{UUID: accountUUID}, RequestIPData{})
		assert.Error(t, err)
		assert.False(t, dataCenterNotifierService.NotifyDataCentersForProfileUpdatesInvoked)
		assert.True(t, accountRepository.DeleteInvoked)
		assert.False(t, auditLog.CreateWithTransactionInvoked)
		assert.True(t, oauthRefreshTokenRepository.DeleteByAccountUUIDInvoked)
		assert.True(t, accountConfirmationRepository.DeleteByAccountUUIDInvoked)
	})

	t.Run("audit log fails", func(t *testing.T) {
		initTest()
		ctx := context.TODO()
		auditLog.CreateWithTransactionError = errors.New("error")
		accountUUID, _ := uuid.NewV4()

		err := accountService.Delete(ctx, accountUUID, uuid.NullUUID{UUID: accountUUID}, RequestIPData{})
		assert.Error(t, err)
		assert.False(t, dataCenterNotifierService.NotifyDataCentersForProfileUpdatesInvoked)
		assert.True(t, accountRepository.DeleteInvoked)
		assert.True(t, auditLog.CreateWithTransactionInvoked)
		assert.True(t, oauthRefreshTokenRepository.DeleteByAccountUUIDInvoked)
		assert.True(t, accountConfirmationRepository.DeleteByAccountUUIDInvoked)
	})

	t.Run("db transaction cannot be committed", func(t *testing.T) {
		initTest()
		var dbManager database.DBManager = &database.DBManagerMock{TxCommitError: errors.New("db")}
		accountUUID, _ := uuid.NewV4()
		accountService := NewAccountServiceImpl(&accountRepository, &dbManager, &accountConfirmationRepository, auditService,
			&amazonSQSClient, &prometheusRegister, &authCompliance, &accountAttributesRepository,
			&oauthRefreshTokenRepository, &dataCenterNotifierService, messagingService)
		ctx := context.TODO()

		err := accountService.Delete(ctx, accountUUID, uuid.NullUUID{UUID: accountUUID}, RequestIPData{})
		assert.Error(t, err)
		assert.False(t, dataCenterNotifierService.NotifyDataCentersForProfileUpdatesInvoked)
		assert.True(t, accountRepository.DeleteInvoked)
		assert.True(t, auditLog.CreateWithTransactionInvoked)
		assert.True(t, oauthRefreshTokenRepository.DeleteByAccountUUIDInvoked)
		assert.True(t, accountConfirmationRepository.DeleteByAccountUUIDInvoked)
	})

	t.Run("success with token deletion errors", func(t *testing.T) {
		initTest()
		ctx := context.TODO()
		oauthRefreshTokenRepository.DeleteByAccountUUIDError = errors.New("error")
		accountConfirmationRepository.DeleteByAccountUUIDError = errors.New("error")
		accountUUID, _ := uuid.NewV4()

		err := accountService.Delete(ctx, accountUUID, uuid.NullUUID{UUID: accountUUID}, RequestIPData{})
		assert.Error(t, err)
		assert.False(t, dataCenterNotifierService.NotifyDataCentersForProfileUpdatesInvoked)
		assert.False(t, accountRepository.DeleteInvoked)
		assert.False(t, auditLog.CreateWithTransactionInvoked)
		assert.True(t, oauthRefreshTokenRepository.DeleteByAccountUUIDInvoked)
		assert.False(t, accountConfirmationRepository.DeleteByAccountUUIDInvoked)
	})

	t.Run("success without token deletion errors", func(t *testing.T) {
		initTest()
		ctx := context.TODO()
		accountUUID, _ := uuid.NewV4()

		err := accountService.Delete(ctx, accountUUID, uuid.NullUUID{UUID: accountUUID}, RequestIPData{})
		assert.NoError(t, err)
		assert.True(t, dataCenterNotifierService.NotifyDataCentersForProfileUpdatesInvoked)
		assert.True(t, accountRepository.DeleteInvoked)
		assert.True(t, auditLog.CreateWithTransactionInvoked)
		assert.True(t, oauthRefreshTokenRepository.DeleteByAccountUUIDInvoked)
		assert.True(t, accountConfirmationRepository.DeleteByAccountUUIDInvoked)
	})
}

func TestUnit_AccountServiceImpl_AnonymizeDeletedAccounts(t *testing.T) {
	t.Run("cannot fetch accounts to anonymize", func(t *testing.T) {
		initTest()
		accountRepository.GetAccountsForAnonymizationOlderThanError = errors.New("db")
		ctx := context.TODO()

		err := accountService.AnonymizeDeletedAccounts(ctx)
		assert.Error(t, err)
		assert.Equal(t, err.Error(), "db: db")
		assert.False(t, accountRepository.AnonymizeAccountInvoked)
	})

	t.Run("no accounts to anonymize", func(t *testing.T) {
		initTest()
		ctx := context.TODO()

		err := accountService.AnonymizeDeletedAccounts(ctx)
		assert.NoError(t, err)
		assert.False(t, accountRepository.AnonymizeAccountInvoked)
	})

	t.Run("ACCOUNT_ANONYMIZED event cannot be sent", func(t *testing.T) {
		initTest()
		accountUUID1, _ := uuid.NewV4()
		accounts := append([]uuid.UUID{}, accountUUID1)
		dataCenters := append([]string{}, "eu-central-1")
		queue := config.SQSQueue{Name: "", AccountID: "", IsFifo: false}
		queues := []config.SQSQueue{queue}
		amazonSQSClient.SendMessageErrors = []error{errors.New("error")}
		dataCenterRegionSyncSqsQueues := config.DataCenterRegionSyncSqsQueues{DataCenterRegion: dataCenters[0], Queues: queues}
		dataCenterSyncSqsQueues := []config.DataCenterRegionSyncSqsQueues{dataCenterRegionSyncSqsQueues}
		config.Parameters.DataCenterQueues.DataCenterSyncSqsQueues = dataCenterSyncSqsQueues
		accountRepository.GetAccountsForAnonymizationOlderThanResult = accounts
		accountRepository.GetAccountDataCentersResult = dataCenters
		dataCenterNotifierService.NotifyDataCentersForProfileUpdatesError = errors.New("error")

		ctx := context.TODO()

		err := accountService.AnonymizeDeletedAccounts(ctx)
		assert.NoError(t, err)
		assert.False(t, accountRepository.AnonymizeAccountInvoked)
	})

	t.Run("cannot start db transaction", func(t *testing.T) {
		var dbManager database.DBManager = database.DBManagerMock{TxError: errors.New("db")}
		accountUUID1, _ := uuid.NewV4()
		accounts := append([]uuid.UUID{}, accountUUID1)
		dataCenters := append([]string{}, "eu-central-1")
		queue := config.SQSQueue{Name: "", AccountID: "", IsFifo: false}
		queues := []config.SQSQueue{queue}
		dataCenterRegionSyncSqsQueues := config.DataCenterRegionSyncSqsQueues{DataCenterRegion: dataCenters[0], Queues: queues}
		dataCenterSyncSqsQueues := []config.DataCenterRegionSyncSqsQueues{dataCenterRegionSyncSqsQueues}
		config.Parameters.DataCenterQueues.DataCenterSyncSqsQueues = dataCenterSyncSqsQueues
		accountRepository.GetAccountsForAnonymizationOlderThanResult = accounts
		accountRepository.GetAccountDataCentersResult = dataCenters
		dataCenterNotifierServiceMock := DataCenterNotifierServiceMock{}

		accountService := NewAccountServiceImpl(&accountRepository, &dbManager, &accountConfirmationRepository, auditService,
			&amazonSQSClient, &prometheusRegister, &authCompliance, &accountAttributesRepository,
			&oauthRefreshTokenRepository, &dataCenterNotifierServiceMock, messagingService)
		ctx := context.TODO()

		err := accountService.AnonymizeDeletedAccounts(ctx)
		assert.NoError(t, err)
		assert.False(t, accountRepository.AnonymizeAccountInvoked)
	})

	t.Run("anonymization update fails", func(t *testing.T) {
		initTest()
		accountUUID1, _ := uuid.NewV4()
		accountUUID2, _ := uuid.NewV4()
		accounts := append([]uuid.UUID{}, accountUUID1, accountUUID2)
		dataCenters := append([]string{}, "eu-central-1")
		queue := config.SQSQueue{Name: "", AccountID: "", IsFifo: false}
		queues := []config.SQSQueue{queue}
		dataCenterRegionSyncSqsQueues := config.DataCenterRegionSyncSqsQueues{DataCenterRegion: dataCenters[0], Queues: queues}
		dataCenterSyncSqsQueues := []config.DataCenterRegionSyncSqsQueues{dataCenterRegionSyncSqsQueues}
		config.Parameters.DataCenterQueues.DataCenterSyncSqsQueues = dataCenterSyncSqsQueues
		accountRepository.GetAccountsForAnonymizationOlderThanResult = accounts
		accountRepository.GetAccountDataCentersResult = dataCenters
		accountRepository.AnonymizeAccountError = errors.New("db")
		ctx := context.TODO()

		err := accountService.AnonymizeDeletedAccounts(ctx)
		assert.NoError(t, err)
		assert.Equal(t, len(accounts), accountRepository.AnonymizeAccountInvocations)
	})

	t.Run("db transaction cannot be committed", func(t *testing.T) {
		initTest()
		var dbManager database.DBManager = &database.DBManagerMock{TxCommitError: errors.New("db")}
		accountUUID1, _ := uuid.NewV4()
		accountUUID2, _ := uuid.NewV4()
		accounts := append([]uuid.UUID{}, accountUUID1, accountUUID2)
		dataCenters := append([]string{}, "eu-central-1")
		queue := config.SQSQueue{Name: "", AccountID: "", IsFifo: false}
		queues := []config.SQSQueue{queue}
		dataCenterRegionSyncSqsQueues := config.DataCenterRegionSyncSqsQueues{DataCenterRegion: dataCenters[0], Queues: queues}
		dataCenterSyncSqsQueues := []config.DataCenterRegionSyncSqsQueues{dataCenterRegionSyncSqsQueues}
		config.Parameters.DataCenterQueues.DataCenterSyncSqsQueues = dataCenterSyncSqsQueues
		accountRepository.GetAccountsForAnonymizationOlderThanResult = accounts
		accountRepository.GetAccountDataCentersResult = dataCenters
		accountService := NewAccountServiceImpl(&accountRepository, &dbManager, &accountConfirmationRepository, auditService,
			&amazonSQSClient, &prometheusRegister, &authCompliance, &accountAttributesRepository,
			&oauthRefreshTokenRepository, &dataCenterNotifierService, messagingService)
		ctx := context.TODO()

		err := accountService.AnonymizeDeletedAccounts(ctx)
		assert.NoError(t, err)
		assert.Equal(t, len(accounts), accountRepository.AnonymizeAccountInvocations)
	})

	t.Run("success", func(t *testing.T) {
		initTest()
		accountUUID1, _ := uuid.NewV4()
		accountUUID2, _ := uuid.NewV4()
		accounts := append([]uuid.UUID{}, accountUUID1, accountUUID2)
		dataCenters := append([]string{}, "eu-central-1")
		queue := config.SQSQueue{Name: "", AccountID: "", IsFifo: false}
		queues := []config.SQSQueue{queue}
		dataCenterRegionSyncSqsQueues := config.DataCenterRegionSyncSqsQueues{DataCenterRegion: dataCenters[0], Queues: queues}
		dataCenterSyncSqsQueues := []config.DataCenterRegionSyncSqsQueues{dataCenterRegionSyncSqsQueues}
		config.Parameters.DataCenterQueues.DataCenterSyncSqsQueues = dataCenterSyncSqsQueues
		accountRepository.GetAccountsForAnonymizationOlderThanResult = accounts
		accountRepository.GetAccountDataCentersResult = dataCenters
		ctx := context.TODO()

		err := accountService.AnonymizeDeletedAccounts(ctx)
		assert.NoError(t, err)
		assert.Equal(t, len(accounts), accountRepository.AnonymizeAccountInvocations)
	})
}
*/
