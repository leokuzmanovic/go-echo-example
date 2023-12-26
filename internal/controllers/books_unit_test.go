package controllers

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/labstack/echo/v4"
	"github.com/leokuzmanovic/go-echo-example/api"
	"github.com/leokuzmanovic/go-echo-example/internal/models"
	"github.com/leokuzmanovic/go-echo-example/internal/services/mocks"
	utils "github.com/leokuzmanovic/go-echo-example/internal/utils"
	"github.com/pkg/errors"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

func TestUnit_BooksController_CreateNew(t *testing.T) {
	var body api.CreateBookRequest
	_ = utils.ParseJSON(strings.NewReader(AuthLoginRequestJSON), &body)

	t.Run("service returns error", func(t *testing.T) {
		e := echo.New()
		request := httptest.NewRequest(http.MethodPost, api.ENDPOINT_BOOKS, nil)
		recorder := httptest.NewRecorder()
		ctx := e.NewContext(request, recorder)
		booksService := mocks.NewBooksService(t)
		booksService.On("CreateBook", mock.Anything, mock.Anything, mock.Anything).Return(&models.Book{}, errors.New("error"))

		booksController := BooksController{
			booksService,
		}
		err := booksController.createNew(ctx, &body)

		assert.Error(t, err)
		booksService.AssertCalled(t, "CreateBook", mock.Anything, body.Title, body.Author)
	})

	t.Run("successful book creation", func(t *testing.T) {
		e := echo.New()
		request := httptest.NewRequest(http.MethodPost, api.ENDPOINT_BOOKS, nil)
		recorder := httptest.NewRecorder()
		ctx := e.NewContext(request, recorder)
		booksService := mocks.NewBooksService(t)
		book := models.Book{
			Id:        "1",
			Title:     "title",
			Author:    "author",
			CreatedAt: time.Now(),
		}
		booksService.On("CreateBook", mock.Anything, mock.Anything, mock.Anything).Return(&book, nil)

		booksController := BooksController{
			booksService,
		}
		err := booksController.createNew(ctx, &body)

		assert.NoError(t, err)
		booksService.AssertCalled(t, "CreateBook", mock.Anything, body.Title, body.Author)

		assert.Equal(t, http.StatusCreated, recorder.Code)
		var response api.BookResponse
		err = json.Unmarshal(recorder.Body.Bytes(), &response)
		assert.NoError(t, err)
		assert.Equal(t, book.Author, response.Author)
		assert.Equal(t, book.Title, response.Title)
		assert.Equal(t, book.Id, response.Id)
		assert.Equal(t, book.CreatedAt.String(), response.CreatedAt)
	})
}

func TestUnit_BooksController_GetById(t *testing.T) {
	t.Run("service returns error", func(t *testing.T) {
		e := echo.New()
		bookId := "1"
		request := httptest.NewRequest(http.MethodGet, api.ENDPOINT_BOOKS_BY_ID, nil)
		recorder := httptest.NewRecorder()
		ctx := e.NewContext(request, recorder)
		ctx.SetParamNames("bookId")
		ctx.SetParamValues(bookId)

		booksService := mocks.NewBooksService(t)
		booksService.On("GetBookById", mock.Anything, mock.Anything).Return(&models.Book{}, errors.New("error"))

		booksController := BooksController{
			booksService,
		}
		err := booksController.getById(ctx)

		assert.Error(t, err)
		booksService.AssertCalled(t, "GetBookById", mock.Anything, bookId)
	})

	t.Run("bad book id param", func(t *testing.T) {
		e := echo.New()
		request := httptest.NewRequest(http.MethodGet, api.ENDPOINT_BOOKS_BY_ID, nil)
		recorder := httptest.NewRecorder()
		ctx := e.NewContext(request, recorder)
		ctx.SetParamNames("bookId")
		ctx.SetParamValues("")

		booksService := mocks.NewBooksService(t)
		booksController := BooksController{
			booksService,
		}
		err := booksController.getById(ctx)

		assert.Error(t, err)
		booksService.AssertNotCalled(t, "GetBookById", mock.Anything, mock.Anything)
	})

	t.Run("successful book retrieval", func(t *testing.T) {
		e := echo.New()
		request := httptest.NewRequest(http.MethodGet, api.ENDPOINT_BOOKS_BY_ID, nil)
		recorder := httptest.NewRecorder()
		bookId := "1"
		ctx := e.NewContext(request, recorder)
		ctx.SetParamNames("bookId")
		ctx.SetParamValues(bookId)
		booksService := mocks.NewBooksService(t)
		book := models.Book{
			Id:        "1",
			Title:     "title",
			Author:    "author",
			CreatedAt: time.Now(),
		}
		booksService.On("GetBookById", mock.Anything, mock.Anything).Return(&book, nil)

		booksController := BooksController{
			booksService,
		}
		err := booksController.getById(ctx)

		assert.NoError(t, err)
		booksService.AssertCalled(t, "GetBookById", mock.Anything, bookId)

		assert.Equal(t, http.StatusOK, recorder.Code)
		var response api.BookResponse
		err = json.Unmarshal(recorder.Body.Bytes(), &response)
		assert.NoError(t, err)
		assert.Equal(t, book.Author, response.Author)
		assert.Equal(t, book.Title, response.Title)
		assert.Equal(t, book.Id, response.Id)
		assert.Equal(t, book.CreatedAt.String(), response.CreatedAt)
	})
}

func TestUnit_BooksController_Delete(t *testing.T) {
	t.Run("service returns error", func(t *testing.T) {
		e := echo.New()
		bookId := "1"
		request := httptest.NewRequest(http.MethodDelete, api.ENDPOINT_BOOKS_BY_ID, nil)
		recorder := httptest.NewRecorder()
		ctx := e.NewContext(request, recorder)
		ctx.SetParamNames("bookId")
		ctx.SetParamValues(bookId)

		booksService := mocks.NewBooksService(t)
		booksService.On("DeleteBookById", mock.Anything, mock.Anything).Return(errors.New("error"))

		booksController := BooksController{
			booksService,
		}
		err := booksController.delete(ctx)

		assert.Error(t, err)
		booksService.AssertCalled(t, "DeleteBookById", mock.Anything, bookId)
	})

	t.Run("bad book id param", func(t *testing.T) {
		e := echo.New()
		request := httptest.NewRequest(http.MethodDelete, api.ENDPOINT_BOOKS_BY_ID, nil)
		recorder := httptest.NewRecorder()
		ctx := e.NewContext(request, recorder)
		ctx.SetParamNames("bookId")
		ctx.SetParamValues("")

		booksService := mocks.NewBooksService(t)
		booksController := BooksController{
			booksService,
		}
		err := booksController.delete(ctx)

		assert.Error(t, err)
		booksService.AssertNotCalled(t, "DeleteBookById", mock.Anything, mock.Anything)
	})

	t.Run("successful book retrieval", func(t *testing.T) {
		e := echo.New()
		request := httptest.NewRequest(http.MethodDelete, api.ENDPOINT_BOOKS_BY_ID, nil)
		recorder := httptest.NewRecorder()
		bookId := "1"
		ctx := e.NewContext(request, recorder)
		ctx.SetParamNames("bookId")
		ctx.SetParamValues(bookId)
		booksService := mocks.NewBooksService(t)
		booksService.On("DeleteBookById", mock.Anything, mock.Anything).Return(nil)

		booksController := BooksController{
			booksService,
		}
		err := booksController.delete(ctx)

		assert.NoError(t, err)
		booksService.AssertCalled(t, "DeleteBookById", mock.Anything, bookId)

		assert.Equal(t, http.StatusOK, recorder.Code)
	})
}
