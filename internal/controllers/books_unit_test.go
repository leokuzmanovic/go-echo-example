package controllers

/*
import (
	"global-auth-service/internal/apierrors"
	"global-auth-service/internal/constants"
	"global-auth-service/internal/models"
	"global-auth-service/internal/services"
	"global-auth-service/internal/utils"
	"global-auth-service/internal/views"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gofrs/uuid"
	"github.com/labstack/echo/v4"
	"github.com/stretchr/testify/assert"
	"gitlab.com/knowunity/go-common/pkg/errors"
)

func TestUnit_AuthController_updateUsername(t *testing.T) {
	var body views.AccountUsernameUpdateRequest
	_ = ParseJSON(strings.NewReader(AccountUsernameUpdateRequestJSON), &body)

	t.Run("update username controller fails - cannot parse account uuid", func(t *testing.T) {
		// Setup
		e := echo.New()
		req := httptest.NewRequest(http.MethodPatch, constants.ENDPOINT_ACCOUNT_USERNAME, nil)
		rec := httptest.NewRecorder()
		c := e.NewContext(req, rec)
		accountService := &services.AccountServiceMock{}
		h := AccountController{
			&models.AccountRepositoryMock{},
			accountService,
			&services.AccountRoleServiceMock{},
		}

		// Assertions
		err := h.updateUsername(c, &body)
		assert.False(t, accountService.UpdateEmailCalled)
		badRequestError := &apierrors.BadRequestError{}
		assert.ErrorAs(t, err, &badRequestError)
	})

	t.Run("update username service fails - controller returns error", func(t *testing.T) {
		// Setup
		e := echo.New()
		accountUUID, _ := uuid.NewV4()
		req := httptest.NewRequest(http.MethodPatch, constants.ENDPOINT_ACCOUNT_USERNAME, nil)
		rec := httptest.NewRecorder()
		c := e.NewContext(req, rec)
		authenticatedAccountUUID, _ := uuid.NewV4()
		c.Set(utils.KeyAccountUUID, authenticatedAccountUUID)
		c.SetParamNames("accountUUID")
		c.SetParamValues(accountUUID.String())
		accountService := &services.AccountServiceMock{UpdateUsernameError: &apierrors.InternalServerError{}}
		h := AccountController{
			&models.AccountRepositoryMock{},
			accountService,
			&services.AccountRoleServiceMock{},
		}

		// Assertions
		err := h.updateUsername(c, &body)
		verifyUpdateUsernameArguments(t, accountService.ArgumentsSpyMap, body, accountUUID, authenticatedAccountUUID)
		assert.True(t, errors.Is(err, &apierrors.InternalServerError{}))
	})

	t.Run("update username successful", func(t *testing.T) {
		// Setup
		e := echo.New()
		accountUUID, _ := uuid.NewV4()
		req := httptest.NewRequest(http.MethodPatch, constants.ENDPOINT_ACCOUNT_USERNAME, nil)
		rec := httptest.NewRecorder()
		c := e.NewContext(req, rec)
		authenticatedAccountUUID, _ := uuid.NewV4()
		c.Set(utils.KeyAccountUUID, authenticatedAccountUUID)
		c.SetParamNames("accountUUID")
		c.SetParamValues(accountUUID.String())
		accountService := &services.AccountServiceMock{}
		h := AccountController{
			&models.AccountRepositoryMock{},
			accountService,
			&services.AccountRoleServiceMock{},
		}

		// Assertions
		if assert.NoError(t, h.updateUsername(c, &body)) {
			assert.Equal(t, http.StatusOK, rec.Code)
			verifyUpdateUsernameArguments(t, accountService.ArgumentsSpyMap, body, accountUUID, authenticatedAccountUUID)
		}
	})
}

func TestUnit_AuthController_updateEmail(t *testing.T) {
	var body views.AccountEmailUpdateRequest
	_ = ParseJSON(strings.NewReader(AccountEmailUpdateRequestJSON), &body)

	t.Run("update email controller fails - cannot parse account uuid", func(t *testing.T) {
		// Setup
		e := echo.New()
		req := httptest.NewRequest(http.MethodPatch, constants.ENDPOINT_ACCOUNT_EMAIL, nil)
		rec := httptest.NewRecorder()
		c := e.NewContext(req, rec)
		accountService := &services.AccountServiceMock{}
		h := AccountController{
			&models.AccountRepositoryMock{},
			accountService,
			&services.AccountRoleServiceMock{},
		}

		// Assertions
		err := h.updateEmail(c, &body)
		assert.False(t, accountService.UpdateEmailCalled)
		badRequestError := &apierrors.BadRequestError{}
		assert.ErrorAs(t, err, &badRequestError)
	})

	t.Run("update email service fails - controller returns error", func(t *testing.T) {
		// Setup
		e := echo.New()
		accountUUID, _ := uuid.NewV4()
		req := httptest.NewRequest(http.MethodPatch, constants.ENDPOINT_ACCOUNT_EMAIL, nil)
		rec := httptest.NewRecorder()
		c := e.NewContext(req, rec)
		authenticatedAccountUUID, _ := uuid.NewV4()
		c.Set(utils.KeyAccountUUID, authenticatedAccountUUID)
		c.SetParamNames("accountUUID")
		c.SetParamValues(accountUUID.String())
		accountService := &services.AccountServiceMock{UpdateEmailError: &apierrors.InternalServerError{}}
		h := AccountController{
			&models.AccountRepositoryMock{},
			accountService,
			&services.AccountRoleServiceMock{},
		}

		// Assertions
		err := h.updateEmail(c, &body)
		verifyUpdateEmailArguments(t, accountService.ArgumentsSpyMap, body, accountUUID, authenticatedAccountUUID)
		assert.True(t, errors.Is(err, &apierrors.InternalServerError{}))
	})

	t.Run("update email successful", func(t *testing.T) {
		// Setup
		e := echo.New()
		accountUUID, _ := uuid.NewV4()
		req := httptest.NewRequest(http.MethodPatch, constants.ENDPOINT_ACCOUNT_EMAIL, nil)
		rec := httptest.NewRecorder()
		c := e.NewContext(req, rec)
		authenticatedAccountUUID, _ := uuid.NewV4()
		c.Set(utils.KeyAccountUUID, authenticatedAccountUUID)
		c.SetParamNames("accountUUID")
		c.SetParamValues(accountUUID.String())
		accountService := &services.AccountServiceMock{}
		h := AccountController{
			&models.AccountRepositoryMock{},
			accountService,
			&services.AccountRoleServiceMock{},
		}

		// Assertions
		if assert.NoError(t, h.updateEmail(c, &body)) {
			assert.Equal(t, http.StatusOK, rec.Code)
			verifyUpdateEmailArguments(t, accountService.ArgumentsSpyMap, body, accountUUID, authenticatedAccountUUID)
		}
	})
}

func TestUnit_AuthController_updatePassword(t *testing.T) {
	var body views.AccountPasswordUpdateRequest
	_ = ParseJSON(strings.NewReader(AccountPasswordUpdateRequestJSON), &body)

	t.Run("update password controller fails - cannot parse account uuid", func(t *testing.T) {
		// Setup
		e := echo.New()
		req := httptest.NewRequest(http.MethodPatch, constants.ENDPOINT_ACCOUNT_PASSWORD, nil)
		rec := httptest.NewRecorder()
		c := e.NewContext(req, rec)
		accountService := &services.AccountServiceMock{}
		h := AccountController{
			&models.AccountRepositoryMock{},
			accountService,
			&services.AccountRoleServiceMock{},
		}

		// Assertions
		err := h.updatePassword(c, &body)
		assert.False(t, accountService.UpdatePasswordCalled)
		assert.NotNil(t, err)
		//todo: fix this: assert.True(t, errors.Is(err, &apierrors.BadRequestError{}))
	})

	t.Run("update email service fails - controller returns error", func(t *testing.T) {
		// Setup
		e := echo.New()
		accountUUID, _ := uuid.NewV4()
		req := httptest.NewRequest(http.MethodPatch, constants.ENDPOINT_ACCOUNT_PASSWORD, nil)
		rec := httptest.NewRecorder()
		c := e.NewContext(req, rec)
		authenticatedAccountUUID, _ := uuid.NewV4()
		c.Set(utils.KeyAccountUUID, authenticatedAccountUUID)
		c.SetParamNames("accountUUID")
		c.SetParamValues(accountUUID.String())
		accountService := &services.AccountServiceMock{UpdatePasswordError: &apierrors.InternalServerError{}}
		h := AccountController{
			&models.AccountRepositoryMock{},
			accountService,
			&services.AccountRoleServiceMock{},
		}

		// Assertions
		err := h.updatePassword(c, &body)
		verifyUpdatePasswordArguments(t, accountService.ArgumentsSpyMap, body, accountUUID, authenticatedAccountUUID)
		assert.True(t, errors.Is(err, &apierrors.InternalServerError{}))
	})

	t.Run("update password successful", func(t *testing.T) {
		// Setup
		e := echo.New()
		accountUUID, _ := uuid.NewV4()
		req := httptest.NewRequest(http.MethodPatch, constants.ENDPOINT_ACCOUNT_PASSWORD, nil)
		rec := httptest.NewRecorder()
		c := e.NewContext(req, rec)
		authenticatedAccountUUID, _ := uuid.NewV4()
		c.Set(utils.KeyAccountUUID, authenticatedAccountUUID)
		c.SetParamNames("accountUUID")
		c.SetParamValues(accountUUID.String())
		accountService := &services.AccountServiceMock{}
		h := AccountController{
			&models.AccountRepositoryMock{},
			accountService,
			&services.AccountRoleServiceMock{},
		}

		// Assertions
		if assert.NoError(t, h.updatePassword(c, &body)) {
			assert.Equal(t, http.StatusOK, rec.Code)
			verifyUpdatePasswordArguments(t, accountService.ArgumentsSpyMap, body, accountUUID, authenticatedAccountUUID)
		}
	})
}

func TestUnit_AuthController_resendConfirmation(t *testing.T) {
	t.Run("resent confirmation controller fails - cannot parse account uuid", func(t *testing.T) {
		// Setup
		e := echo.New()
		req := httptest.NewRequest(http.MethodPost, constants.ENDPOINT_ACCOUNT_RESENDCONFIRMATION, nil)
		rec := httptest.NewRecorder()
		c := e.NewContext(req, rec)
		authenticatedAccountUUID, _ := uuid.NewV4()
		c.Set(utils.KeyAccountUUID, authenticatedAccountUUID)
		accountService := &services.AccountServiceMock{}
		h := AccountController{
			&models.AccountRepositoryMock{},
			accountService,
			&services.AccountRoleServiceMock{},
		}

		// Assertions
		err := h.resendConfirmation(c)
		assert.False(t, accountService.ResendConfirmationCalled)
		assert.NotNil(t, err)
		//todo: fix this: assert.True(t, errors.Is(err, &apierrors.BadRequestError{}))
	})

	t.Run("resent confirmation service fails - controller returns error", func(t *testing.T) {
		// Setup
		e := echo.New()
		accountUUID, _ := uuid.NewV4()
		req := httptest.NewRequest(http.MethodPost, constants.ENDPOINT_ACCOUNT_RESENDCONFIRMATION, nil)
		rec := httptest.NewRecorder()
		c := e.NewContext(req, rec)
		authenticatedAccountUUID, _ := uuid.NewV4()
		c.Set(utils.KeyAccountUUID, authenticatedAccountUUID)
		c.SetParamNames("accountUUID")
		c.SetParamValues(accountUUID.String())
		accountService := &services.AccountServiceMock{ResendConfirmationError: &apierrors.InternalServerError{}}
		h := AccountController{
			&models.AccountRepositoryMock{},
			accountService,
			&services.AccountRoleServiceMock{},
		}

		// Assertions
		err := h.resendConfirmation(c)
		assert.Equal(t, accountService.ArgumentsSpyMap["accountUUID"], accountUUID)
		assert.Equal(t, accountService.ArgumentsSpyMap["authenticatedAccountUUID"], authenticatedAccountUUID)
		assert.True(t, errors.Is(err, &apierrors.InternalServerError{}))
	})

	t.Run("resent confirmation successful", func(t *testing.T) {
		// Setup
		e := echo.New()
		accountUUID, _ := uuid.NewV4()
		req := httptest.NewRequest(http.MethodPost, constants.ENDPOINT_ACCOUNT_RESENDCONFIRMATION, nil)
		rec := httptest.NewRecorder()
		c := e.NewContext(req, rec)
		authenticatedAccountUUID, _ := uuid.NewV4()
		c.Set(utils.KeyAccountUUID, authenticatedAccountUUID)
		c.SetParamNames("accountUUID")
		c.SetParamValues(accountUUID.String())
		accountService := &services.AccountServiceMock{}
		h := AccountController{
			&models.AccountRepositoryMock{},
			accountService,
			&services.AccountRoleServiceMock{},
		}

		// Assertions
		err := h.resendConfirmation(c)
		assert.Equal(t, accountService.ArgumentsSpyMap["accountUUID"], accountUUID)
		assert.Equal(t, accountService.ArgumentsSpyMap["authenticatedAccountUUID"], authenticatedAccountUUID)
		assert.Nil(t, err)

		if assert.NoError(t, h.resendConfirmation(c)) {
			assert.Equal(t, http.StatusOK, rec.Code)
			assert.Equal(t, accountService.ArgumentsSpyMap["accountUUID"], accountUUID)
			assert.Equal(t, accountService.ArgumentsSpyMap["authenticatedAccountUUID"], authenticatedAccountUUID)
		}
	})
}

func TestUnit_AuthController_confirmEmail(t *testing.T) {
	var body views.AccountEmailConfirmRequest
	_ = ParseJSON(strings.NewReader(AccountEmailConfirmRequestJSON), &body)

	t.Run("confirm email service fails - controller returns error", func(t *testing.T) {
		// Setup
		e := echo.New()
		req := httptest.NewRequest(http.MethodPost, constants.ENDPOINT_ACCOUNT_CONFIRMATION, nil)
		rec := httptest.NewRecorder()
		c := e.NewContext(req, rec)
		accountService := &services.AccountServiceMock{ConfirmEmailError: &apierrors.InternalServerError{}}
		h := AccountController{
			&models.AccountRepositoryMock{},
			accountService,
			&services.AccountRoleServiceMock{},
		}

		// Assertions
		err := h.confirmEmail(c, &body)
		assert.Equal(t, accountService.ArgumentsSpyMap["confirmationToken"], body.ConformationToken)
		assert.True(t, errors.Is(err, &apierrors.InternalServerError{}))
	})

	t.Run("resent confirmation successful", func(t *testing.T) {
		// Setup
		e := echo.New()
		req := httptest.NewRequest(http.MethodPost, constants.ENDPOINT_ACCOUNT_CONFIRMATION, nil)
		rec := httptest.NewRecorder()
		c := e.NewContext(req, rec)
		accountService := &services.AccountServiceMock{}
		h := AccountController{
			&models.AccountRepositoryMock{},
			accountService,
			&services.AccountRoleServiceMock{},
		}

		// Assertions
		if assert.NoError(t, h.confirmEmail(c, &body)) {
			assert.Equal(t, http.StatusOK, rec.Code)
			assert.Equal(t, accountService.ArgumentsSpyMap["confirmationToken"], body.ConformationToken)
		}
	})
}

func TestUnit_AuthController_updateRoles(t *testing.T) {
	var body views.AccountRoleUpdateRequest
	_ = ParseJSON(strings.NewReader(UserRoleUpdateRequestJSON), &body)

	t.Run("update roles controller fails - cannot parse account uuid", func(t *testing.T) {
		// Setup
		e := echo.New()
		req := httptest.NewRequest(http.MethodPatch, constants.ENDPOINT_ACCOUNT_ROLES, nil)
		rec := httptest.NewRecorder()
		c := e.NewContext(req, rec)
		accountRoleService := &services.AccountRoleServiceMock{}
		h := AccountController{
			&models.AccountRepositoryMock{},
			&services.AccountServiceMock{},
			accountRoleService,
		}

		// Assertions
		err := h.updateRoles(c, &body)
		assert.False(t, accountRoleService.UpdateRolesCalled)
		assert.NotNil(t, err)
		//todo: fix this: assert.True(t, errors.Is(err, &apierrors.BadRequestError{}))
	})

	t.Run("update roles service fails - controller returns error", func(t *testing.T) {
		// Setup
		e := echo.New()
		accountUUID, _ := uuid.NewV4()
		req := httptest.NewRequest(http.MethodPatch, constants.ENDPOINT_ACCOUNT_ROLES, nil)
		rec := httptest.NewRecorder()
		c := e.NewContext(req, rec)
		authenticatedAccountUUID, _ := uuid.NewV4()
		c.Set(utils.KeyAccountUUID, authenticatedAccountUUID)
		c.SetParamNames("accountUUID")
		c.SetParamValues(accountUUID.String())
		accountRoleService := &services.AccountRoleServiceMock{UpdateRolesError: &apierrors.InternalServerError{}}
		h := AccountController{
			&models.AccountRepositoryMock{},
			&services.AccountServiceMock{},
			accountRoleService,
		}

		// Assertions
		err := h.updateRoles(c, &body)
		verifyUpdateRolesArguments(t, accountRoleService.ArgumentsSpyMap, body, accountUUID, authenticatedAccountUUID)
		assert.True(t, errors.Is(err, &apierrors.InternalServerError{}))
	})

	t.Run("update roles successful", func(t *testing.T) {
		// Setup
		e := echo.New()
		accountUUID, _ := uuid.NewV4()
		req := httptest.NewRequest(http.MethodPatch, constants.ENDPOINT_ACCOUNT_ROLES, nil)
		rec := httptest.NewRecorder()
		c := e.NewContext(req, rec)
		authenticatedAccountUUID, _ := uuid.NewV4()
		c.Set(utils.KeyAccountUUID, authenticatedAccountUUID)
		c.SetParamNames("accountUUID")
		c.SetParamValues(accountUUID.String())
		accountRoleService := &services.AccountRoleServiceMock{}
		h := AccountController{
			&models.AccountRepositoryMock{},
			&services.AccountServiceMock{},
			accountRoleService,
		}

		// Assertions
		if assert.NoError(t, h.updateRoles(c, &body)) {
			assert.Equal(t, http.StatusOK, rec.Code)
			verifyUpdateRolesArguments(t, accountRoleService.ArgumentsSpyMap, body, accountUUID, authenticatedAccountUUID)
		}
	})
}

func TestUnit_AuthController_listRoles(t *testing.T) {
	t.Run("list roles controller fails - cannot parse account uuid", func(t *testing.T) {
		// Setup
		e := echo.New()
		req := httptest.NewRequest(http.MethodGet, constants.ENDPOINT_ACCOUNT_ROLES, nil)
		rec := httptest.NewRecorder()
		c := e.NewContext(req, rec)
		accountRoleService := &services.AccountRoleServiceMock{}
		h := AccountController{
			&models.AccountRepositoryMock{},
			&services.AccountServiceMock{},
			accountRoleService,
		}

		// Assertions
		err := h.listRoles(c)
		assert.False(t, accountRoleService.ListRolesCalled)
		assert.NotNil(t, err)
		//todo: fix this: assert.True(t, errors.Is(err, &apierrors.BadRequestError{}))
	})

	t.Run("list roles service fails - controller returns error", func(t *testing.T) {
		// Setup
		e := echo.New()
		accountUUID, _ := uuid.NewV4()
		req := httptest.NewRequest(http.MethodGet, constants.ENDPOINT_ACCOUNT_ROLES, nil)
		rec := httptest.NewRecorder()
		c := e.NewContext(req, rec)
		c.SetParamNames("accountUUID")
		c.SetParamValues(accountUUID.String())
		accountRoleService := &services.AccountRoleServiceMock{ListRolesError: &apierrors.InternalServerError{}}
		h := AccountController{
			&models.AccountRepositoryMock{},
			&services.AccountServiceMock{},
			accountRoleService,
		}

		// Assertions
		err := h.listRoles(c)
		verifyListRolesArguments(t, accountRoleService.ArgumentsSpyMap, accountUUID)
		assert.True(t, errors.Is(err, &apierrors.InternalServerError{}))
	})

	t.Run("list roles successful", func(t *testing.T) {
		// Setup
		e := echo.New()
		accountUUID, _ := uuid.NewV4()
		req := httptest.NewRequest(http.MethodGet, constants.ENDPOINT_ACCOUNT_ROLES, nil)
		rec := httptest.NewRecorder()
		c := e.NewContext(req, rec)
		c.SetParamNames("accountUUID")
		c.SetParamValues(accountUUID.String())
		listRolesContent := []string{"some role"}
		accountRoleService := &services.AccountRoleServiceMock{ListRolesContent: listRolesContent}
		h := AccountController{
			&models.AccountRepositoryMock{},
			&services.AccountServiceMock{},
			accountRoleService,
		}

		// Assertions
		if assert.NoError(t, h.listRoles(c)) {
			assert.Equal(t, http.StatusOK, rec.Code)
			verifyListRolesArguments(t, accountRoleService.ArgumentsSpyMap, accountUUID)
		}
	})
}

func TestUnit_AuthController_delete(t *testing.T) {
	t.Run("delete account controller fails - cannot parse account uuid", func(t *testing.T) {
		// Setup
		e := echo.New()
		req := httptest.NewRequest(http.MethodDelete, constants.ENDPOINT_ACCOUNT, nil)
		rec := httptest.NewRecorder()
		c := e.NewContext(req, rec)
		accountService := &services.AccountServiceMock{}
		h := AccountController{
			&models.AccountRepositoryMock{},
			accountService,
			&services.AccountRoleServiceMock{},
		}

		// Assertions
		err := h.delete(c)
		assert.False(t, accountService.DeleteCalled)
		assert.NotNil(t, err)
		//todo: fix this: assert.True(t, errors.Is(err, &apierrors.BadRequestError{}))
	})

	t.Run("delete account service fails - controller returns error", func(t *testing.T) {
		// Setup
		e := echo.New()
		accountUUID, _ := uuid.NewV4()
		req := httptest.NewRequest(http.MethodDelete, constants.ENDPOINT_ACCOUNT, nil)
		rec := httptest.NewRecorder()
		c := e.NewContext(req, rec)
		authenticatedAccountUUID, _ := uuid.NewV4()
		c.Set(utils.KeyAccountUUID, authenticatedAccountUUID)
		c.SetParamNames("accountUUID")
		c.SetParamValues(accountUUID.String())
		accountService := &services.AccountServiceMock{TryDeleteError: &apierrors.InternalServerError{}}
		h := AccountController{
			&models.AccountRepositoryMock{},
			accountService,
			&services.AccountRoleServiceMock{},
		}

		// Assertions
		err := h.delete(c)
		verifyDeleteArguments(t, accountService.ArgumentsSpyMap, accountUUID, authenticatedAccountUUID)
		assert.True(t, errors.Is(err, &apierrors.InternalServerError{}))
	})

	t.Run("delete account successful", func(t *testing.T) {
		// Setup
		e := echo.New()
		accountUUID, _ := uuid.NewV4()
		req := httptest.NewRequest(http.MethodDelete, constants.ENDPOINT_ACCOUNT, nil)
		rec := httptest.NewRecorder()
		c := e.NewContext(req, rec)
		authenticatedAccountUUID, _ := uuid.NewV4()
		c.Set(utils.KeyAccountUUID, authenticatedAccountUUID)
		c.SetParamNames("accountUUID")
		c.SetParamValues(accountUUID.String())
		accountService := &services.AccountServiceMock{}
		h := AccountController{
			&models.AccountRepositoryMock{},
			accountService,
			&services.AccountRoleServiceMock{},
		}

		// Assertions
		if assert.NoError(t, h.delete(c)) {
			assert.Equal(t, http.StatusOK, rec.Code)
			verifyDeleteArguments(t, accountService.ArgumentsSpyMap, accountUUID, authenticatedAccountUUID)
		}
	})
}

func verifyUpdatePasswordArguments(t *testing.T, spyMap map[string]interface{}, body views.AccountPasswordUpdateRequest, accountUUID, authenticatedAccountUUID uuid.UUID) {
	assert.Equal(t, spyMap["newPassword"], body.NewPassword)
	assert.Equal(t, spyMap["oldPassword"], body.OldPassword)
	assert.Equal(t, spyMap["accountUUID"], accountUUID)
	assert.Equal(t, spyMap["authenticatedAccountUUID"], authenticatedAccountUUID)
}

func verifyUpdateEmailArguments(t *testing.T, spyMap map[string]interface{}, body views.AccountEmailUpdateRequest, accountUUID, authenticatedAccountUUID uuid.UUID) {
	assert.Equal(t, spyMap["newEmailRaw"], body.NewEmail)
	assert.Equal(t, spyMap["password"], body.Password)
	assert.Equal(t, spyMap["accountUUID"], accountUUID)
	assert.Equal(t, spyMap["authenticatedAccountUUID"], authenticatedAccountUUID)
}

func verifyUpdateUsernameArguments(t *testing.T, spyMap map[string]interface{}, body views.AccountUsernameUpdateRequest, accountUUID, authenticatedAccountUUID uuid.UUID) {
	assert.Equal(t, spyMap["newUsername"], body.NewUsername)
	assert.Equal(t, spyMap["accountUUID"], accountUUID)
	assert.Equal(t, spyMap["authenticatedAccountUUID"], authenticatedAccountUUID)
}

func verifyUpdateRolesArguments(t *testing.T, spyMap map[string]interface{}, body views.AccountRoleUpdateRequest, accountUUID uuid.UUID, authenticatedAccountUUID uuid.UUID) {
	assert.Equal(t, spyMap["accountUUID"], accountUUID)
	assert.Equal(t, spyMap["authenticatedAccountUUID"], authenticatedAccountUUID)
	if roleAccess, converted := spyMap["roleAccess"].(utils.RoleAccess); converted {
		assert.Equal(t, roleAccess.AdminOnlyAccess, false)
		assert.Equal(t, roleAccess.AccountDeleteAccess, false)
		assert.Equal(t, roleAccess.Type, utils.Role(""))
	}
	if accountRoles, converted := spyMap["accountRoles"].(models.AccountRoles); converted {
		assert.Equal(t, accountRoles.Product, body.Product)
		assert.Equal(t, accountRoles.Finance, body.Finance)
		assert.Equal(t, accountRoles.Expansion, body.Expansion)
		assert.Equal(t, accountRoles.Report, body.Report)
		assert.Equal(t, accountRoles.Content, body.Content)
		assert.Equal(t, accountRoles.CustomerSupport, body.CustomerSupport)
		assert.Equal(t, accountRoles.Sales, body.Sales)
		assert.Equal(t, accountRoles.Admin, body.Admin)
		assert.Equal(t, accountRoles.ExperimentationPlatform, body.ExperimentationPlatform)
	}
}

func verifyListRolesArguments(t *testing.T, spyMap map[string]interface{}, accountUUID uuid.UUID) {
	assert.Equal(t, spyMap["accountUUID"], accountUUID)
	if roleAccess, converted := spyMap["roleAccess"].(utils.RoleAccess); converted {
		assert.Equal(t, roleAccess.AdminOnlyAccess, false)
		assert.Equal(t, roleAccess.AccountDeleteAccess, false)
		assert.Equal(t, roleAccess.Type, utils.Role(""))
	}
}

func verifyDeleteArguments(t *testing.T, spyMap map[string]interface{}, accountUUID uuid.UUID, authenticatedAccountUUID uuid.UUID) {
	assert.Equal(t, spyMap["accountUUID"], accountUUID)
	assert.Equal(t, spyMap["authenticatedAccountUUID"], authenticatedAccountUUID)
	if roleAccess, converted := spyMap["roleAccess"].(utils.RoleAccess); converted {
		assert.Equal(t, roleAccess.AdminOnlyAccess, false)
		assert.Equal(t, roleAccess.AccountDeleteAccess, false)
		assert.Equal(t, roleAccess.Type, utils.Role(""))
	}
}
*/
