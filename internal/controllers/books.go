package controllers

import (
	"net/http"

	"github.com/leokuzmanovic/go-echo-example/api"
	"github.com/leokuzmanovic/go-echo-example/internal/constants"
	di "github.com/leokuzmanovic/go-echo-example/internal/dependencyinjection"
	errs "github.com/leokuzmanovic/go-echo-example/internal/errors"
	"github.com/leokuzmanovic/go-echo-example/internal/services"
	"github.com/pkg/errors"

	"github.com/labstack/echo/v4"
)

type BooksController struct {
	booksService services.BooksService
}

func wireBooks(e *echo.Echo) {
	controller := &BooksController{
		booksService: di.Get[services.BooksService](),
	}

	e.POST(api.ENDPOINT_BOOKS, withValidJsonBody(controller.createNew), getMiddlewareFunction(constants.TimeoutRegular))
	e.GET(api.ENDPOINT_BOOKS_BY_ID, controller.getById, getMiddlewareFunction(constants.TimeoutQuick))
	e.DELETE(api.ENDPOINT_BOOKS_BY_ID, controller.delete, getMiddlewareFunction(constants.TimeoutRegular))
}

/*
// @Summary Create new book
// @Tags books
// @Router /books [POST]
// @Param body body api.CreateBookRequest true "CreateBookRequest"
// @Success 201
// @Failure 400 {object} utils.ApiError "BadRequestError, FormValidationError, InvalidCredentialsError"
// @Failure 403 {object} utils.ApiError "ForbiddenError"
// @Failure 404 {object} utils.ApiError "NotFoundError"
*/
func (s *BooksController) createNew(ctx echo.Context, body *api.CreateBookRequest) error {
	book, err := s.booksService.CreateBook(ctx.Request().Context(), body.Title, body.Author)
	if err != nil {
		return errors.Wrap(err, "books")
	}

	response := api.BookResponse{
		Id:        book.Id,
		CreatedAt: book.CreatedAt.String(),
		Title:     book.Title,
		Author:    book.Author,
	}
	return errors.Wrap(ctx.JSON(http.StatusCreated, response), "json")
}

/*
// @Summary List account roles
// @Tags accountroleservice
// @Router /accounts/{accountUUID}/roles [GET]
// @Param accountUUID path string true "Account UUID"
// @Produce json
// @Success 200 {object} utils.Content "string"
// @Success 400 {object} utils.ApiError "BadRequestError"
// @Success 403 {object} utils.ApiError "ForbiddenError"
// @Success 404 {object} utils.ApiError "NotFoundError"
*/
func (s *BooksController) getById(ctx echo.Context) error {
	bookId := ctx.Param("bookId")
	if bookId == "" {
		return &errs.BadRequestError{}
	}

	book, err := s.booksService.GetBookById(ctx.Request().Context(), bookId)
	if err != nil {
		return errors.Wrap(err, "account")
	}

	response := api.BookResponse{
		Id:        book.Id,
		CreatedAt: book.CreatedAt.String(),
		Title:     book.Title,
		Author:    book.Author,
	}
	return errors.Wrap(ctx.JSON(http.StatusOK, response), "json")
}

/*
// @Summary Delete account
// @Tags account
// @Router /accounts/{accountUUID} [DELETE]
// @Param accountUUID path string true "Account UUID"
// @Success 200
// @Failure 400 {object} utils.ApiError "BadRequestError, ContactCustomerSupportError"
// @Failure 403 {object} utils.ApiError "ForbiddenError"
// @Failure 404 {object} utils.ApiError "NotFoundError"
*/
func (s *BooksController) delete(ctx echo.Context) error {
	bookId := ctx.Param("bookId")
	if bookId == "" {
		return errors.New("book id not set")
		//return &apierrors.BadRequestError{Message: "Unable to parse account uuid."}
	}

	err := s.booksService.DeleteBookById(ctx.Request().Context(), bookId)
	if err != nil {
		return errors.Wrap(err, "books")
	}

	return errors.Wrap(ctx.NoContent(http.StatusOK), "context")
}
