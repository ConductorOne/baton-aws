package awspolicy

import (
	"net/url"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestDecodePolicyDocument(t *testing.T) {
	policy := `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Sid":"a+b c"}]}`

	t.Run("plain_json_with_plus_unchanged", func(t *testing.T) {
		decoded, err := DecodePolicyDocument(policy)
		require.NoError(t, err)
		require.Equal(t, policy, decoded)
	})

	t.Run("rfc3986_percent_encoded_plus", func(t *testing.T) {
		// PathEscape leaves '+' unescaped; force %2B so this path is actually exercised.
		encoded := strings.ReplaceAll(url.PathEscape(policy), "+", "%2B")
		require.Contains(t, encoded, "%2B")
		require.NotContains(t, encoded, "a+b")

		decoded, err := DecodePolicyDocument(encoded)
		require.NoError(t, err)
		require.Equal(t, policy, decoded)
		require.Contains(t, decoded, `"Sid":"a+b c"`)
	})

	t.Run("encoded_document_with_literal_plus", func(t *testing.T) {
		encoded := url.PathEscape(policy)
		require.Contains(t, encoded, "+")
		require.NotContains(t, encoded, "%2B")

		decoded, err := DecodePolicyDocument(encoded)
		require.NoError(t, err)
		require.Equal(t, policy, decoded)
		require.Contains(t, decoded, `"Sid":"a+b c"`)
		require.NotContains(t, decoded, `"Sid":"a b c"`)
	})

	t.Run("query_unescape_would_turn_plus_into_space", func(t *testing.T) {
		encoded := url.PathEscape(policy)
		wrong, err := url.QueryUnescape(encoded)
		require.NoError(t, err)
		require.NotEqual(t, policy, wrong)
		require.Contains(t, wrong, `"Sid":"a b c"`)
	})

	t.Run("invalid_percent_encoding", func(t *testing.T) {
		_, err := DecodePolicyDocument("%zz")
		require.Error(t, err)
	})
}
