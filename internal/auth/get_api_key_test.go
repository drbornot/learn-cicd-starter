package auth

import (
	"net/http"
	"testing"

	"github.com/stretchr/testify/require"
)

func Test_GetAPIKey(t *testing.T) {
	headers := http.Header{}

	t.Run("not provided", func(t *testing.T) {
		h, err := GetAPIKey(headers)
		require.ErrorIs(t, err, ErrNoAuthHeaderIncluded)
		require.Empty(t, h)
	})

	t.Run("not split header", func(t *testing.T) {
		headers.Set("Authorization", "ApiKey")
		h, err := GetAPIKey(headers)
		require.ErrorContains(t, err, "malformed authorization header")
		require.Empty(t, h)
	})

	t.Run("split but invalid header", func(t *testing.T) {
		headers.Set("Authorization", "Invalid some-key")
		h, err := GetAPIKey(headers)
		require.ErrorContains(t, err, "malformed authorization header")
		require.Empty(t, h)
	})

	t.Run("split header", func(t *testing.T) {
		headers.Set("Authorization", "ApiKey some-key")
		h, err := GetAPIKey(headers)
		require.NoError(t, err)
		require.Equal(t, "some-key", h)
	})
}
