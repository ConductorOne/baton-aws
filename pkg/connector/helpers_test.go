package connector

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestTrustPolicy_UnmarshalJSON(t *testing.T) {
	t.Run("should parse statement as array successfully", func(t *testing.T) {
		policyJSON := `{
			"Version": "2012-10-17",
			"Statement": [
				{
					"Effect": "Allow",
					"Principal": {"AWS": "arn:aws:iam::123456789012:user/test"},
					"Action": "sts:AssumeRole"
				}
			]
		}`

		var policy TrustPolicy
		err := json.Unmarshal([]byte(policyJSON), &policy)

		require.NoError(t, err)
		assert.Equal(t, "2012-10-17", policy.Version)
		assert.Len(t, policy.Statement, 1)
		assert.Equal(t, "Allow", policy.Statement[0].Effect)
	})

	t.Run("should parse statement as single object and convert to array", func(t *testing.T) {
		policyJSON := `{
			"Version": "2012-10-17",
			"Statement": {
				"Effect": "Allow",
				"Principal": {"AWS": "arn:aws:iam::123456789012:user/test"},
				"Action": "sts:AssumeRole"
			}
		}`

		var policy TrustPolicy
		err := json.Unmarshal([]byte(policyJSON), &policy)

		require.NoError(t, err)
		assert.Equal(t, "2012-10-17", policy.Version)
		assert.Len(t, policy.Statement, 1)
		assert.Equal(t, "Allow", policy.Statement[0].Effect)
	})

	t.Run("should parse multiple statements successfully", func(t *testing.T) {
		policyJSON := `{
			"Version": "2012-10-17",
			"Statement": [
				{
					"Effect": "Allow",
					"Principal": {"AWS": "arn:aws:iam::123456789012:user/test1"},
					"Action": "sts:AssumeRole"
				},
				{
					"Effect": "Deny",
					"Principal": {"AWS": "arn:aws:iam::123456789012:user/test2"},
					"Action": "sts:AssumeRole"
				}
			]
		}`

		var policy TrustPolicy
		err := json.Unmarshal([]byte(policyJSON), &policy)

		require.NoError(t, err)
		assert.Len(t, policy.Statement, 2)
	})

	t.Run("should return error for invalid JSON", func(t *testing.T) {
		invalidJSON := `{invalid json}`

		var policy TrustPolicy
		err := json.Unmarshal([]byte(invalidJSON), &policy)

		require.Error(t, err)
		// Error comes from json.Unmarshal, not our wrapper
		assert.Contains(t, err.Error(), "invalid character")
	})

	t.Run("should return error when statement is not object or array", func(t *testing.T) {
		invalidJSON := `{
			"Version": "2012-10-17",
			"Statement": "invalid-string"
		}`

		var policy TrustPolicy
		err := json.Unmarshal([]byte(invalidJSON), &policy)

		require.Error(t, err)
		assert.Contains(t, err.Error(), "statement must be object or array")
	})

	t.Run("should return error when statement is a number", func(t *testing.T) {
		invalidJSON := `{
			"Version": "2012-10-17",
			"Statement": 123
		}`

		var policy TrustPolicy
		err := json.Unmarshal([]byte(invalidJSON), &policy)

		require.Error(t, err)
		assert.Contains(t, err.Error(), "statement must be object or array")
	})

	t.Run("should return error when statement is a boolean", func(t *testing.T) {
		invalidJSON := `{
			"Version": "2012-10-17",
			"Statement": true
		}`

		var policy TrustPolicy
		err := json.Unmarshal([]byte(invalidJSON), &policy)

		require.Error(t, err)
		assert.Contains(t, err.Error(), "statement must be object or array")
	})

	t.Run("should parse empty statement array", func(t *testing.T) {
		policyJSON := `{
			"Version": "2012-10-17",
			"Statement": []
		}`

		var policy TrustPolicy
		err := json.Unmarshal([]byte(policyJSON), &policy)

		require.NoError(t, err)
		assert.Empty(t, policy.Statement)
	})
}

func TestAction_UnmarshalJSON(t *testing.T) {
	t.Run("should parse single action as string", func(t *testing.T) {
		actionJSON := `"sts:AssumeRole"`

		var action Action
		err := json.Unmarshal([]byte(actionJSON), &action)

		require.NoError(t, err)
		assert.Equal(t, []string{"sts:AssumeRole"}, []string(action))
	})

	t.Run("should parse action as array with one element", func(t *testing.T) {
		actionJSON := `["sts:AssumeRole"]`

		var action Action
		err := json.Unmarshal([]byte(actionJSON), &action)

		require.NoError(t, err)
		assert.Equal(t, []string{"sts:AssumeRole"}, []string(action))
	})

	t.Run("should parse action as array with multiple elements", func(t *testing.T) {
		actionJSON := `["sts:AssumeRole", "sts:TagSession"]`

		var action Action
		err := json.Unmarshal([]byte(actionJSON), &action)

		require.NoError(t, err)
		assert.Equal(t, []string{"sts:AssumeRole", "sts:TagSession"}, []string(action))
	})

	t.Run("should return error when action is a number", func(t *testing.T) {
		invalidJSON := `123`

		var action Action
		err := json.Unmarshal([]byte(invalidJSON), &action)

		require.Error(t, err)
		assert.Contains(t, err.Error(), "action must be string or array")
	})

	t.Run("should return error when action is an object", func(t *testing.T) {
		invalidJSON := `{"key": "value"}`

		var action Action
		err := json.Unmarshal([]byte(invalidJSON), &action)

		require.Error(t, err)
		assert.Contains(t, err.Error(), "action must be string or array")
	})

	t.Run("should return error when action is a boolean", func(t *testing.T) {
		invalidJSON := `true`

		var action Action
		err := json.Unmarshal([]byte(invalidJSON), &action)

		require.Error(t, err)
		assert.Contains(t, err.Error(), "action must be string or array")
	})

	t.Run("should parse empty array", func(t *testing.T) {
		actionJSON := `[]`

		var action Action
		err := json.Unmarshal([]byte(actionJSON), &action)

		require.NoError(t, err)
		assert.Empty(t, action)
	})

	t.Run("should parse empty string", func(t *testing.T) {
		actionJSON := `""`

		var action Action
		err := json.Unmarshal([]byte(actionJSON), &action)

		require.NoError(t, err)
		assert.Equal(t, []string{""}, []string(action))
	})
}

func TestPrincipal_UnmarshalJSON(t *testing.T) {
	t.Run("should parse AWS principal as single string", func(t *testing.T) {
		principalJSON := `{"AWS": "arn:aws:iam::123456789012:user/test"}`

		var principal Principal
		err := json.Unmarshal([]byte(principalJSON), &principal)

		require.NoError(t, err)
		assert.Equal(t, []string{"arn:aws:iam::123456789012:user/test"}, principal.AWS)
	})

	t.Run("should parse AWS principal as array", func(t *testing.T) {
		principalJSON := `{"AWS": ["arn:aws:iam::123456789012:user/test1", "arn:aws:iam::123456789012:user/test2"]}`

		var principal Principal
		err := json.Unmarshal([]byte(principalJSON), &principal)

		require.NoError(t, err)
		assert.Equal(t, []string{
			"arn:aws:iam::123456789012:user/test1",
			"arn:aws:iam::123456789012:user/test2",
		}, principal.AWS)
	})

	t.Run("should ignore principal when object has no AWS field", func(t *testing.T) {
		principalJSON := `{}`

		var principal Principal
		err := json.Unmarshal([]byte(principalJSON), &principal)

		require.NoError(t, err)
		assert.Nil(t, principal.AWS)
	})

	t.Run("should ignore wildcard principal", func(t *testing.T) {
		principalJSON := `"*"`

		var principal Principal
		err := json.Unmarshal([]byte(principalJSON), &principal)

		require.NoError(t, err)
		assert.Nil(t, principal.AWS)
	})

	t.Run("should ignore service principal without AWS field", func(t *testing.T) {
		principalJSON := `{"Service": "lambda.amazonaws.com"}`

		var principal Principal
		err := json.Unmarshal([]byte(principalJSON), &principal)

		require.NoError(t, err)
		assert.Nil(t, principal.AWS)
	})

	t.Run("should return error when principal is a number", func(t *testing.T) {
		invalidJSON := `123`

		var principal Principal
		err := json.Unmarshal([]byte(invalidJSON), &principal)

		require.Error(t, err)
		assert.Contains(t, err.Error(), "principal must be object or string")
	})

	t.Run("should return error when principal is a boolean", func(t *testing.T) {
		invalidJSON := `true`

		var principal Principal
		err := json.Unmarshal([]byte(invalidJSON), &principal)

		require.Error(t, err)
		assert.Contains(t, err.Error(), "principal must be object or string")
	})

	t.Run("should return error when AWS field is an object", func(t *testing.T) {
		invalidJSON := `{"AWS": {"nested": "value"}}`

		var principal Principal
		err := json.Unmarshal([]byte(invalidJSON), &principal)

		require.Error(t, err)
		assert.Contains(t, err.Error(), "AWS field must be string or array")
	})

	t.Run("should return error when principal is an array", func(t *testing.T) {
		invalidJSON := `["value1", "value2"]`

		var principal Principal
		err := json.Unmarshal([]byte(invalidJSON), &principal)

		require.Error(t, err)
		assert.Contains(t, err.Error(), "principal must be object or string")
	})

	t.Run("should parse empty AWS array", func(t *testing.T) {
		principalJSON := `{"AWS": []}`

		var principal Principal
		err := json.Unmarshal([]byte(principalJSON), &principal)

		require.NoError(t, err)
		assert.Empty(t, principal.AWS)
	})

	t.Run("should parse AWS array with empty string", func(t *testing.T) {
		principalJSON := `{"AWS": [""]}`

		var principal Principal
		err := json.Unmarshal([]byte(principalJSON), &principal)

		require.NoError(t, err)
		assert.Equal(t, []string{""}, principal.AWS)
	})

	t.Run("should parse single empty string in AWS field", func(t *testing.T) {
		principalJSON := `{"AWS": ""}`

		var principal Principal
		err := json.Unmarshal([]byte(principalJSON), &principal)

		require.NoError(t, err)
		assert.Equal(t, []string{""}, principal.AWS)
	})
}

func TestDetectPrincipalResource(t *testing.T) {
	t.Run("should detect IAM user ARN", func(t *testing.T) {
		principalARN := "arn:aws:iam::123456789012:user/test-user"

		resourceType, resourceID, ok := detectPrincipalResource(principalARN)

		require.True(t, ok)
		require.NotNil(t, resourceType)
		assert.Equal(t, resourceTypeIAMUser.Id, resourceType.Id)
		assert.Equal(t, "arn:aws:iam::123456789012:user/test-user", resourceID)
	})

	t.Run("should detect IAM role ARN", func(t *testing.T) {
		principalARN := "arn:aws:iam::123456789012:role/test-role"

		resourceType, resourceID, ok := detectPrincipalResource(principalARN)

		require.True(t, ok)
		require.NotNil(t, resourceType)
		assert.Equal(t, resourceTypeRole.Id, resourceType.Id)
		assert.Equal(t, "arn:aws:iam::123456789012:role/test-role", resourceID)
	})

	t.Run("should ignore account root ARN", func(t *testing.T) {
		principalARN := "arn:aws:iam::123456789012:root"

		_, _, ok := detectPrincipalResource(principalARN)

		assert.False(t, ok)
	})

	t.Run("should ignore service principal", func(t *testing.T) {
		principalARN := "ec2.amazonaws.com"

		_, _, ok := detectPrincipalResource(principalARN)

		assert.False(t, ok)
	})

	t.Run("should ignore wildcard", func(t *testing.T) {
		principalARN := "*"

		_, _, ok := detectPrincipalResource(principalARN)

		assert.False(t, ok)
	})

	t.Run("should ignore invalid ARN", func(t *testing.T) {
		principalARN := "not-an-arn"

		_, _, ok := detectPrincipalResource(principalARN)

		assert.False(t, ok)
	})

	t.Run("should ignore empty string", func(t *testing.T) {
		principalARN := ""

		_, _, ok := detectPrincipalResource(principalARN)

		assert.False(t, ok)
	})

	t.Run("should detect user with path", func(t *testing.T) {
		principalARN := "arn:aws:iam::123456789012:user/path/to/test-user"

		resourceType, resourceID, ok := detectPrincipalResource(principalARN)

		require.True(t, ok)
		require.NotNil(t, resourceType)
		assert.Equal(t, resourceTypeIAMUser.Id, resourceType.Id)
		assert.Equal(t, "arn:aws:iam::123456789012:user/path/to/test-user", resourceID)
	})

	t.Run("should detect role with path", func(t *testing.T) {
		principalARN := "arn:aws:iam::123456789012:role/path/to/test-role"

		resourceType, resourceID, ok := detectPrincipalResource(principalARN)

		require.True(t, ok)
		require.NotNil(t, resourceType)
		assert.Equal(t, resourceTypeRole.Id, resourceType.Id)
		assert.Equal(t, "arn:aws:iam::123456789012:role/path/to/test-role", resourceID)
	})
}

func TestExtractTrustPrincipals(t *testing.T) {
	t.Run("should extract single user principal", func(t *testing.T) {
		// URL-encoded: {"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"AWS":"arn:aws:iam::123456789012:user/test-user"},"Action":"sts:AssumeRole"}]}
		policyDocument := `%7B%22Version%22%3A%222012-10-17%22%2C%22Statement%22%3A%5B%7B%22Effect%22%3A%22Allow%22%2C%22Principal%22%3A%7B%22AWS%22%3A%22arn%3Aaws%3Aiam%3A%3A123456789012%3Auser%2Ftest-user%22%7D%2C%22Action%22%3A%22sts%3AAssumeRole%22%7D%5D%7D`

		principals, err := extractTrustPrincipals(policyDocument)

		require.NoError(t, err)
		assert.Equal(t, []string{"arn:aws:iam::123456789012:user/test-user"}, principals)
	})

	t.Run("should extract multiple principals", func(t *testing.T) {
		// URL-encoded: {"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"AWS":["arn:aws:iam::123456789012:user/test1","arn:aws:iam::123456789012:user/test2"]},"Action":"sts:AssumeRole"}]}
		policyDocument := `%7B%22Version%22%3A%222012-10-17%22%2C%22Statement%22%3A%5B%7B%22Effect%22%3A%22Allow%22%2C%22Principal%22%3A%7B%22AWS%22%3A%5B%22arn%3Aaws%3Aiam%3A%3A123456789012%3Auser%2Ftest1%22%2C%22arn%3Aaws%3Aiam%3A%3A123456789012%3Auser%2Ftest2%22%5D%7D%2C%22Action%22%3A%22sts%3AAssumeRole%22%7D%5D%7D`

		principals, err := extractTrustPrincipals(policyDocument)

		require.NoError(t, err)
		assert.Equal(t, []string{
			"arn:aws:iam::123456789012:user/test1",
			"arn:aws:iam::123456789012:user/test2",
		}, principals)
	})

	t.Run("should handle statement as single object", func(t *testing.T) {
		// URL-encoded: {"Version":"2012-10-17","Statement":{"Effect":"Allow","Principal":{"AWS":"arn:aws:iam::123456789012:user/test"},"Action":"sts:AssumeRole"}}
		policyDocument := `%7B%22Version%22%3A%222012-10-17%22%2C%22Statement%22%3A%7B%22Effect%22%3A%22Allow%22%2C%22Principal%22%3A%7B%22AWS%22%3A%22arn%3Aaws%3Aiam%3A%3A123456789012%3Auser%2Ftest%22%7D%2C%22Action%22%3A%22sts%3AAssumeRole%22%7D%7D`

		principals, err := extractTrustPrincipals(policyDocument)

		require.NoError(t, err)
		assert.Equal(t, []string{"arn:aws:iam::123456789012:user/test"}, principals)
	})

	t.Run("should handle action as string", func(t *testing.T) {
		// URL-encoded: {"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"AWS":"arn:aws:iam::123456789012:user/test"},"Action":"sts:AssumeRole"}]}
		policyDocument := `%7B%22Version%22%3A%222012-10-17%22%2C%22Statement%22%3A%5B%7B%22Effect%22%3A%22Allow%22%2C%22Principal%22%3A%7B%22AWS%22%3A%22arn%3Aaws%3Aiam%3A%3A123456789012%3Auser%2Ftest%22%7D%2C%22Action%22%3A%22sts%3AAssumeRole%22%7D%5D%7D`

		principals, err := extractTrustPrincipals(policyDocument)

		require.NoError(t, err)
		assert.Equal(t, []string{"arn:aws:iam::123456789012:user/test"}, principals)
	})

	t.Run("should filter out Deny statements", func(t *testing.T) {
		// URL-encoded with Deny and Allow statements
		policyDocument := `%7B%22Version%22%3A%222012-10-17%22%2C%22Statement%22%3A%5B%7B%22Effect%22%3A%22Deny%22%2C%22Principal%22%3A%7B%22AWS%22%3A%22arn%3Aaws%3Aiam%3A%3A123456789012%3Auser%2Fdenied%22%7D%2C%22Action%22%3A%22sts%3AAssumeRole%22%7D%2C%7B%22Effect%22%3A%22Allow%22%2C%22Principal%22%3A%7B%22AWS%22%3A%22arn%3Aaws%3Aiam%3A%3A123456789012%3Auser%2Fallowed%22%7D%2C%22Action%22%3A%22sts%3AAssumeRole%22%7D%5D%7D`

		principals, err := extractTrustPrincipals(policyDocument)

		require.NoError(t, err)
		assert.Equal(t, []string{"arn:aws:iam::123456789012:user/allowed"}, principals)
	})

	t.Run("should filter out non-AssumeRole actions", func(t *testing.T) {
		// URL-encoded with s3:GetObject and sts:AssumeRole
		policyDocument := `%7B%22Version%22%3A%222012-10-17%22%2C%22Statement%22%3A%5B%7B%22Effect%22%3A%22Allow%22%2C%22Principal%22%3A%7B%22AWS%22%3A%22arn%3Aaws%3Aiam%3A%3A123456789012%3Auser%2Ftest1%22%7D%2C%22Action%22%3A%22s3%3AGetObject%22%7D%2C%7B%22Effect%22%3A%22Allow%22%2C%22Principal%22%3A%7B%22AWS%22%3A%22arn%3Aaws%3Aiam%3A%3A123456789012%3Auser%2Ftest2%22%7D%2C%22Action%22%3A%22sts%3AAssumeRole%22%7D%5D%7D`

		principals, err := extractTrustPrincipals(policyDocument)

		require.NoError(t, err)
		assert.Equal(t, []string{"arn:aws:iam::123456789012:user/test2"}, principals)
	})

	t.Run("should extract role principals", func(t *testing.T) {
		// URL-encoded: {"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"AWS":"arn:aws:iam::123456789012:role/test-role"},"Action":"sts:AssumeRole"}]}
		policyDocument := `%7B%22Version%22%3A%222012-10-17%22%2C%22Statement%22%3A%5B%7B%22Effect%22%3A%22Allow%22%2C%22Principal%22%3A%7B%22AWS%22%3A%22arn%3Aaws%3Aiam%3A%3A123456789012%3Arole%2Ftest-role%22%7D%2C%22Action%22%3A%22sts%3AAssumeRole%22%7D%5D%7D`

		principals, err := extractTrustPrincipals(policyDocument)

		require.NoError(t, err)
		assert.Equal(t, []string{"arn:aws:iam::123456789012:role/test-role"}, principals)
	})

	t.Run("should include account root principals in results", func(t *testing.T) {
		// URL-encoded: {"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"AWS":"arn:aws:iam::123456789012:root"},"Action":"sts:AssumeRole"}]}
		// NOTE: extractTrustPrincipals returns ALL AWS principals, filtering happens later in detectPrincipalResource
		policyDocument := `%7B%22Version%22%3A%222012-10-17%22%2C%22Statement%22%3A%5B%7B%22Effect%22%3A%22Allow%22%2C%22Principal%22%3A%7B%22AWS%22%3A%22arn%3Aaws%3Aiam%3A%3A123456789012%3Aroot%22%7D%2C%22Action%22%3A%22sts%3AAssumeRole%22%7D%5D%7D`

		principals, err := extractTrustPrincipals(policyDocument)

		require.NoError(t, err)
		assert.Equal(t, []string{"arn:aws:iam::123456789012:root"}, principals)
	})

	t.Run("should return empty array for empty statement array", func(t *testing.T) {
		// URL-encoded: {"Version":"2012-10-17","Statement":[]}
		policyDocument := `%7B%22Version%22%3A%222012-10-17%22%2C%22Statement%22%3A%5B%5D%7D`

		principals, err := extractTrustPrincipals(policyDocument)

		require.NoError(t, err)
		assert.Empty(t, principals)
	})

	t.Run("should return error for invalid URL encoding", func(t *testing.T) {
		invalidPolicy := `%ZZ`

		_, err := extractTrustPrincipals(invalidPolicy)

		require.Error(t, err)
		assert.Contains(t, err.Error(), "failed to decode trust policy")
	})

	t.Run("should return error for invalid JSON after decoding", func(t *testing.T) {
		// URL-encoded: {invalid}
		invalidPolicy := `%7Binvalid%7D`

		_, err := extractTrustPrincipals(invalidPolicy)

		require.Error(t, err)
		assert.Contains(t, err.Error(), "failed to parse trust policy JSON")
	})

	t.Run("should ignore service principals in results", func(t *testing.T) {
		// URL-encoded: {"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"Service":"lambda.amazonaws.com"},"Action":"sts:AssumeRole"}]}
		// Service principals don't have AWS field, so AWS array is empty
		policyDocument := `%7B%22Version%22%3A%222012-10-17%22%2C%22Statement%22%3A%5B%7B%22Effect%22%3A%22Allow%22%2C%22Principal%22%3A%7B%22Service%22%3A%22lambda.amazonaws.com%22%7D%2C%22Action%22%3A%22sts%3AAssumeRole%22%7D%5D%7D`

		principals, err := extractTrustPrincipals(policyDocument)

		require.NoError(t, err)
		assert.Empty(t, principals)
	})

	t.Run("should filter out empty string principals", func(t *testing.T) {
		// URL-encoded: {"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"AWS":["arn:aws:iam::123456789012:user/test",""]},"Action":"sts:AssumeRole"}]}
		// Has one valid ARN and one empty string
		policyDocument := `%7B%22Version%22%3A%222012-10-17%22%2C%22Statement%22%3A%5B%7B%22Effect%22%3A%22Allow%22%2C%22Principal%22%3A%7B%22AWS%22%3A%5B%22arn%3Aaws%3Aiam%3A%3A123456789012%3Auser%2Ftest%22%2C%22%22%5D%7D%2C%22Action%22%3A%22sts%3AAssumeRole%22%7D%5D%7D`

		principals, err := extractTrustPrincipals(policyDocument)

		require.NoError(t, err)
		assert.Equal(t, []string{"arn:aws:iam::123456789012:user/test"}, principals)
	})
}
