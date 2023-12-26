package utils

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestUnit_Utils_sanitizeUri(t *testing.T) {
	t.Run("sanitization", func(t *testing.T) {
		uri1 := SanitizeUri("/SOME-Uri")
		uri2 := SanitizeUri("/SOMEOTHER-Uri/")
		uri3 := SanitizeUri("/")

		assert.Equal(t, uri1, "/some-uri")
		assert.Equal(t, uri2, "/someother-uri")
		assert.Equal(t, uri3, "/")
	})
}

func TestUnit_Utils_parseJson(t *testing.T) {
	t.Run("valid json", func(t *testing.T) {
		json := `{"name":"John", "age":30, "car":null}`
		var v map[string]interface{}
		err := ParseJSON(strings.NewReader(json), &v)
		assert.Nil(t, err)
		assert.Equal(t, v["name"], "John")
		assert.Equal(t, v["age"], float64(30))
		assert.Equal(t, v["car"], nil)
	})

	t.Run("invalid json", func(t *testing.T) {
		json := `{"name":"John", "age":30, "car":null`
		var v map[string]interface{}
		err := ParseJSON(strings.NewReader(json), &v)
		assert.NotNil(t, err)
	})
}
