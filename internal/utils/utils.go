package utils

import (
	"crypto/subtle"
	"strings"

	"github.com/labstack/echo/v4"
	"github.com/labstack/echo/v4/middleware"
)

/*
func ShortenString(value string, maxLength int) string {
	if len(value) <= maxLength {
		return value
	}
	return value[:maxLength-4] + " ..."
}
*/

func PrepareBasicAuthenticationMiddleware(username, password string) echo.MiddlewareFunc {
	middlewareFunc := middleware.BasicAuth(func(username, password string, c echo.Context) (bool, error) {
		usernameMatches := subtle.ConstantTimeCompare([]byte(username), []byte(username)) == 1
		passwordMatches := subtle.ConstantTimeCompare([]byte(password), []byte(password)) == 1
		return usernameMatches && passwordMatches, nil
	})
	return middlewareFunc
}

func SanitizeUri(uri string) string {
	sanitizedUri := strings.ToLower(uri)
	if len(sanitizedUri) > 1 {
		sanitizedUri = strings.TrimSuffix(sanitizedUri, "/")
	}

	return sanitizedUri
}

/*
// FormatEmailAddress lowercases email address and strips whitespace
func FormatEmailAddress(email string) string {
	email = strings.ReplaceAll(email, " ", "")
	return strings.ToLower(email)
}



func SleepRandom(durationFrom, durationTo int) int {
	if durationFrom > durationTo || durationFrom <= 0 || durationTo <= 0 {
		return 0
	}
	duration := 0
	if durationFrom == durationTo {
		duration = durationFrom
	} else {
		duration = mr.Intn(durationTo-durationFrom) + durationFrom
	}
	time.Sleep(time.Duration(duration) * time.Millisecond)
	return duration
}

// RandomString generates a random string of length n
func RandomString(n int) (string, error) {
	letters := "abcdefghijklmnopqrstuvwxyz"
	return random(n, letters)
}

func random(length int, letters string) (string, error) {
	ll := len(letters)
	b := make([]byte, length)
	_, err := rand.Read(b) // generates len(b) random bytes
	if err != nil {
		return "", errors.Wrap(err, "rand")
	}
	for i := 0; i < length; i++ {
		b[i] = letters[int(b[i])%ll]
	}
	return string(b), nil
}

func IsEmployeeEmail(email string) bool {
	return strings.HasSuffix(email, "@knowunity.com")
}

func GetUserIp(r *http.Request) string {
	cloudflareConnectingIP := r.Header.Get(constants.HeaderCloudflareConnectingIP)
	if cloudflareConnectingIP != "" {
		return cloudflareConnectingIP
	}

	ipAddresses := r.Header.Get(constants.HeaderXForwardedFor)
	if len(ipAddresses) > 0 {
		return strings.Split(ipAddresses, ",")[0]
	}
	return ""
}

// ContainsString checks whether slice contains string s
func ContainsString(slice []string, s string) bool {
	for _, e := range slice {
		if s == e {
			return true
		}
	}
	return false
}

func GetNullStringFromInterface(i interface{}) null.String {
	if i == nil {
		return null.String{}
	}
	str := fmt.Sprintf("%v", i)
	return null.StringFrom(str)
}

func GetNullIntFromInterface(i interface{}) null.Int {
	if i == nil {
		return null.Int{}
	}
	if val, converted := i.(int64); converted {
		return null.IntFrom(val)
	}
	return null.Int{}
}

func GetNullFloatFromInterface(i interface{}) null.Float {
	if i == nil {
		return null.Float{}
	}

	if val, converted := i.(float64); converted {
		return null.FloatFrom(val)
	}
	return null.Float{}
}

func GetSpyMap(accountProfile interface{}) (map[string]interface{}, error) {
	body, err := json.Marshal(accountProfile)
	if err != nil {
		return nil, errors.Wrap(err, "json")
	}
	var data map[string]interface{}
	err = json.Unmarshal(body, &data)
	if err != nil {
		return nil, errors.Wrap(err, "json")
	}
	return data, nil
}
*/
