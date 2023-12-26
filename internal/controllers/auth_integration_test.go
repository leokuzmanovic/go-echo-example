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

func TestIntegration_AuthController(t *testing.T) {
	e := prepare()
	defer shutdown(e)

	t.Run("login", func(t *testing.T) {
		loginResponse := loginUser1(t)
		defer loginResponse.Body.Close()
		verifyAuthResponse(t, loginResponse, http.StatusOK)
	})

	t.Run("logout", func(t *testing.T) {
		loginResponse := loginUser1(t)
		defer loginResponse.Body.Close()
		accessToken, refreshToken := getTokensFromResponse(t, loginResponse)

		requestBody := api.RefreshTokenRequest{
			RefreshToken: refreshToken,
		}
		requestBodyBytes, err := json.Marshal(requestBody)
		if err != nil {
			assert.NoError(t, err)
		}
		requestBodyString := string(requestBodyBytes)

		req, err := http.NewRequest(http.MethodPost, "http://localhost"+testServerPort+api.ENDPOINT_AUTH_LOGOUT, strings.NewReader(requestBodyString))
		assert.NoError(t, err)
		req.Header.Add("Content-Type", "application/json")
		req.Header.Add("Authorization", fmt.Sprintf("Bearer %s", accessToken))

		client := &http.Client{Timeout: time.Second * 5}
		logoutResponse, err := client.Do(req)
		assert.NoError(t, err)
		defer logoutResponse.Body.Close()
		assert.Equal(t, logoutResponse.StatusCode, http.StatusOK)
	})

	t.Run("refresh token", func(t *testing.T) {
		loginResponse := loginUser1(t)
		defer loginResponse.Body.Close()
		_, refreshToken := getTokensFromResponse(t, loginResponse)

		reqBody := api.RefreshTokenRequest{
			RefreshToken: refreshToken,
		}
		bodyByteArray, err := json.Marshal(reqBody)
		if err != nil {
			assert.NoError(t, err)
		}
		bodyString := string(bodyByteArray)

		req, err := http.NewRequest(http.MethodPost, "http://localhost"+testServerPort+api.ENDPOINT_AUTH_TOKEN, strings.NewReader(bodyString))
		assert.NoError(t, err)
		req.Header.Add("Content-Type", "application/json")

		client := &http.Client{Timeout: time.Second * 3}
		refreshTokenResponse, err := client.Do(req)
		assert.NoError(t, err)
		defer refreshTokenResponse.Body.Close()
		verifyAuthResponse(t, refreshTokenResponse, http.StatusOK)
	})
}

func verifyAuthResponse(t *testing.T, res *http.Response, expectedStatusCode int) {
	assert.Equal(t, res.StatusCode, expectedStatusCode)

	responseBodyBytes, err := io.ReadAll(res.Body)
	assert.NoError(t, err)

	responseBodyString := string(responseBodyBytes)
	var authResponse api.AuthResponse
	err = utils.ParseJSON(strings.NewReader(responseBodyString), &authResponse)
	assert.NoError(t, err)
	assert.NotEmpty(t, authResponse.AccessToken)
	assert.NotEmpty(t, authResponse.RefreshToken)
}
