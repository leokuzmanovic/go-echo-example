package controllers

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/leokuzmanovic/go-echo-example/api"
	utils "github.com/leokuzmanovic/go-echo-example/internal/utils"
	_ "github.com/lib/pq"
	"github.com/stretchr/testify/assert"
)

func TestIntegration_BooksController(t *testing.T) {
	e := prepare()
	defer shutdown(e)

	t.Run("create new", func(t *testing.T) {
		loginResponse := loginUser1(t)
		defer loginResponse.Body.Close()
		accessToken, _ := getTokensFromResponse(t, loginResponse)
		title := "title1"
		author := "author1"
		err, createNewBookResponse := createNewBook(t, title, author, accessToken)
		assert.NoError(t, err)
		defer createNewBookResponse.Body.Close()
		verifyBookResponse(t, createNewBookResponse, http.StatusCreated, author, title)
	})

	t.Run("get by id", func(t *testing.T) {
		loginResponse := loginUser1(t)
		defer loginResponse.Body.Close()
		accessToken, _ := getTokensFromResponse(t, loginResponse)

		title := "title2"
		author := "author2"
		err, createNewBookResponse := createNewBook(t, title, author, accessToken)
		assert.NoError(t, err)
		defer createNewBookResponse.Body.Close()
		bookResponse := getBookResponse(t, createNewBookResponse)

		req, err := http.NewRequest(http.MethodGet, "http://localhost"+testServerPort+strings.Replace(api.ENDPOINT_BOOKS_BY_ID, ":bookId", bookResponse.Id, 1), nil)
		assert.NoError(t, err)
		req.Header.Add("Content-Type", "application/json")
		req.Header.Add("Authorization", fmt.Sprintf("Bearer %s", accessToken))

		client := &http.Client{Timeout: time.Second * 3}
		getBookResponse, err := client.Do(req)
		assert.NoError(t, err)
		defer getBookResponse.Body.Close()
		verifyBookResponse(t, getBookResponse, http.StatusOK, author, title)
	})

	t.Run("delete", func(t *testing.T) {
		loginResponse := loginUser1(t)
		defer loginResponse.Body.Close()
		accessToken, _ := getTokensFromResponse(t, loginResponse)

		title := "title3"
		author := "author3"
		err, createNewBookResponse := createNewBook(t, title, author, accessToken)
		assert.NoError(t, err)
		defer createNewBookResponse.Body.Close()
		bookResponse := getBookResponse(t, createNewBookResponse)

		req, err := http.NewRequest(http.MethodDelete, "http://localhost"+testServerPort+strings.Replace(api.ENDPOINT_BOOKS_BY_ID, ":bookId", bookResponse.Id, 1), nil)
		assert.NoError(t, err)
		req.Header.Add("Content-Type", "application/json")
		req.Header.Add("Authorization", fmt.Sprintf("Bearer %s", accessToken))

		client := &http.Client{Timeout: time.Second * 3}
		deleteBookResponse, err := client.Do(req)
		assert.NoError(t, err)
		defer deleteBookResponse.Body.Close()
		assert.Equal(t, deleteBookResponse.StatusCode, http.StatusOK)
	})
}

func createNewBook(t *testing.T, title string, author string, accessToken string) (error, *http.Response) {
	requestBody := api.CreateBookRequest{
		Title:  title,
		Author: author,
	}
	requestBodyBytes, err := json.Marshal(requestBody)
	if err != nil {
		assert.NoError(t, err)
	}
	requestBodyString := string(requestBodyBytes)

	req, err := http.NewRequest(http.MethodPost, "http://localhost"+testServerPort+api.ENDPOINT_BOOKS, strings.NewReader(requestBodyString))
	assert.NoError(t, err)
	req.Header.Add("Content-Type", "application/json")
	req.Header.Add("Authorization", fmt.Sprintf("Bearer %s", accessToken))

	client := &http.Client{Timeout: time.Second * 3}
	createNewBookResponse, err := client.Do(req)
	return err, createNewBookResponse
}

func verifyBookResponse(t *testing.T, res *http.Response, expectedStatusCode int, author, title string) {
	assert.Equal(t, res.StatusCode, expectedStatusCode)
	bookResponse := getBookResponse(t, res)
	assert.Equal(t, bookResponse.Author, author)
	assert.Equal(t, bookResponse.Title, title)
	assert.NotEmpty(t, bookResponse.CreatedAt)
	assert.NotEmpty(t, bookResponse.Id)
}

func getBookResponse(t *testing.T, res *http.Response) api.BookResponse {
	responseBodyBytes, err := io.ReadAll(res.Body)
	assert.NoError(t, err)

	responseBodyString := string(responseBodyBytes)
	var bookResponse api.BookResponse
	err = utils.ParseJSON(strings.NewReader(responseBodyString), &bookResponse)
	assert.NoError(t, err)
	return bookResponse
}
