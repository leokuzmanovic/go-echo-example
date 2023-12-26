package controllers

import (
	"context"
	"encoding/json"
	"io"
	"log"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/labstack/echo/v4"
	"github.com/leokuzmanovic/go-echo-example/api"
	"github.com/leokuzmanovic/go-echo-example/internal/configuration"
	di "github.com/leokuzmanovic/go-echo-example/internal/dependencyinjection"
	"github.com/leokuzmanovic/go-echo-example/internal/models"
	"github.com/leokuzmanovic/go-echo-example/internal/services"
	utils "github.com/leokuzmanovic/go-echo-example/internal/utils"
	_ "github.com/lib/pq"
	"github.com/pkg/errors"
	"github.com/stretchr/testify/assert"
)

const (
	AuthLoginRequestJSON    = `{"username": "someusername", "password": "password"}`
	RefreshTokenRequestJSON = `{"refreshToken": "refresh.token"}`
	CreateBookRequestJSON   = `{"title": "some title", "author": "some author"}`
)

var testServerPort = ":1323"
var diWired = false

func prepare() *echo.Echo {
	e := echo.New()

	if !diWired { // right now, DI container is global, so we need to wire it only once
		config := &configuration.AppConfig{}
		di.Register(config)
		configuration.Wire()
		models.Wire()
		services.Wire()
		diWired = true
	}
	WireControllers(e)

	go func() {
		if err := e.Start(testServerPort); err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Fatal("test server down")
		}
	}()
	time.Sleep(2 * time.Second)
	// should be up and running by now
	return e
}

func shutdown(e *echo.Echo) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := e.Shutdown(ctx); err != nil {
		e.Logger.Fatal(err)
	}
}

func getTokensFromResponse(t *testing.T, res *http.Response) (string, string) {
	responseBodyBytes, _ := io.ReadAll(res.Body)
	responseBodyString := string(responseBodyBytes)
	var authResponse api.AuthResponse
	err := utils.ParseJSON(strings.NewReader(responseBodyString), &authResponse)
	assert.NoError(t, err)
	return authResponse.AccessToken, authResponse.RefreshToken
}

func loginUser1(t *testing.T) *http.Response {
	requestBody := api.AuthLoginRequest{
		Username: models.USER1_USERNAME,
		Password: models.USER1_PASSWORD,
	}
	requestBodyBytes, err := json.Marshal(requestBody)
	if err != nil {
		assert.NoError(t, err)
	}
	requestBodyString := string(requestBodyBytes)

	req, err := http.NewRequest(http.MethodPost, "http://localhost"+testServerPort+api.ENDPOINT_AUTH_LOGIN, strings.NewReader(requestBodyString))
	assert.NoError(t, err)
	req.Header.Add("Content-Type", "application/json")

	client := &http.Client{Timeout: time.Second * 5}
	res, err := client.Do(req)
	assert.NoError(t, err)

	return res
}

type NextInvoker struct {
	WasNextInvoked bool
	Next           func(ctx echo.Context) error
}

func NewNextInvoker() *NextInvoker {
	p := new(NextInvoker)
	p.WasNextInvoked = false
	var next = func(ctx echo.Context) error {
		p.WasNextInvoked = true
		return nil
	}
	p.Next = next

	return p
}
