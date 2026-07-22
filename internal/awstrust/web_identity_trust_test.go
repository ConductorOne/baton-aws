package awstrust

import (
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const (
	trustTestAccountID   = "123456789012"
	trustTestOtherAcctID = "210987654321"
	testIssuer           = "issuer.c1.example.com/aws-sts/v1"
	testProviderARN      = "arn:aws:iam::" + trustTestAccountID + ":oidc-provider/" + testIssuer
	testAudience         = "aws-sts"
	testSubject          = "tenant:tenant-123:binding:binding-456"
)

func TestEvaluateWebIdentityTrustGolden(t *testing.T) {
	exact := exactTrustStatement(testProviderARN, testAudience, testSubject, false, false)
	wildcardAudienceConditions := `"StringLike":{"` + testIssuer + `:aud":"aws-*"},` +
		`"StringEquals":{"` + testIssuer + `:sub":"` + testSubject + `"}`
	stringLikeSubjectConditions := `"StringEquals":{"` + testIssuer + `:aud":"` + testAudience + `"},` +
		`"StringLike":{"` + testIssuer + `:sub":"tenant:*"}`
	audienceOnlyConditions := `"StringEquals":{"` + testIssuer + `:aud":"` + testAudience + `"}`
	unknownSubjectConditions := `"StringEquals":{"` + testIssuer + `:aud":"` + testAudience + `"},` +
		`"FutureStringOperator":{"` + testIssuer + `:sub":"` + testSubject + `"}`
	unknownUnrelatedConditions := `"StringEquals":{"` + testIssuer + `:aud":"` + testAudience +
		`","` + testIssuer + `:sub":"` + testSubject + `"},"FutureOperator":{"other:key":"value"}`
	unrelatedProviderARN := "arn:aws:iam::" + trustTestAccountID + ":oidc-provider/unrelated.example.com"
	unrelated := statementWithConditions(unrelatedProviderARN, assumeRoleWithWebIdentityAction, "")
	deny := `{"Effect":"Deny","Principal":{"Federated":"` + testProviderARN +
		`"},"Action":"` + assumeRoleWithWebIdentityAction + `"}`
	tests := []struct {
		name     string
		expected ExpectedWebIdentityTrust
		observed ObservedWebIdentityTrust
	}{
		{
			name:     "plain_array_scalar_success",
			expected: validExpectedTrust(),
			observed: validObservedTrust(policyDocument(exact), 3600),
		},
		{
			name:     "encoded_object_list_success",
			expected: expectedWithTagSession(),
			observed: observedWithPolicy(url.QueryEscape(singleStatementPolicy(exactTrustStatement(testProviderARN, testAudience, testSubject, true, true)))),
		},
		{
			name:     "wildcard_audience",
			expected: validExpectedTrust(),
			observed: observedWithPolicy(policyDocument(statementWithConditions(
				testProviderARN,
				assumeRoleWithWebIdentityAction,
				wildcardAudienceConditions,
			))),
		},
		{
			name:     "stringlike_subject",
			expected: validExpectedTrust(),
			observed: observedWithPolicy(policyDocument(statementWithConditions(
				testProviderARN,
				assumeRoleWithWebIdentityAction,
				stringLikeSubjectConditions,
			))),
		},
		{
			name:     "wrong_binding",
			expected: validExpectedTrust(),
			observed: observedWithPolicy(policyDocument(exactTrustStatement(testProviderARN, "wrong-audience", "wrong-subject", false, false))),
		},
		{
			name:     "wrong_provider",
			expected: validExpectedTrust(),
			observed: observedWithProvider("arn:aws:iam::"+trustTestAccountID+":oidc-provider/other.example.com", "https://other.example.com"),
		},
		{
			name:     "wrong_account",
			expected: validExpectedTrust(),
			observed: observedWithRoleARN("arn:aws:iam::" + trustTestOtherAcctID + ":role/c1-vended-role"),
		},
		{
			name:     "missing_action",
			expected: validExpectedTrust(),
			observed: observedWithPolicy(policyDocument(exactTrustStatementWithAction(testProviderARN, "sts:AssumeRole", testAudience, testSubject))),
		},
		{
			name:     "matching_provider_statement_missing",
			expected: validExpectedTrust(),
			observed: observedWithPolicy(policyDocument(exactTrustStatement(
				unrelatedProviderARN,
				testAudience,
				testSubject,
				false,
				false,
			))),
		},
		{
			name:     "missing_audience",
			expected: validExpectedTrust(),
			observed: observedWithPolicy(policyDocument(statementWithConditions(testProviderARN, assumeRoleWithWebIdentityAction, `"StringEquals":{"`+testIssuer+`:sub":"`+testSubject+`"}`))),
		},
		{
			name:     "missing_subject",
			expected: validExpectedTrust(),
			observed: observedWithPolicy(policyDocument(statementWithConditions(testProviderARN, assumeRoleWithWebIdentityAction, `"StringEquals":{"`+testIssuer+`:aud":"`+testAudience+`"}`))),
		},
		{
			name:     "tag_session_required",
			expected: expectedWithTagSession(),
			observed: validObservedTrust(policyDocument(exact), 3600),
		},
		{
			name:     "broad_parallel_statement",
			expected: validExpectedTrust(),
			observed: observedWithPolicy(policyDocument(exact + `,` + statementWithConditions(
				testProviderARN,
				assumeRoleWithWebIdentityAction,
				audienceOnlyConditions,
			))),
		},
		{
			name:     "broad_parallel_wildcard_action",
			expected: validExpectedTrust(),
			observed: observedWithPolicy(policyDocument(exact + `,` + statementWithConditions(testProviderARN, "sts:*", ""))),
		},
		{
			name:     "unrelated_statements_ignored",
			expected: validExpectedTrust(),
			observed: observedWithPolicy(policyDocument(unrelated + `,` + exact + `,` + deny)),
		},
		{
			name:     "provider_client_id_mismatch",
			expected: validExpectedTrust(),
			observed: observedWithClientIDs([]string{"another-audience"}),
		},
		{
			name:     "duration_boundary_passes",
			expected: validExpectedTrust(),
			observed: validObservedTrust(policyDocument(exact), 3600),
		},
		{
			name:     "duration_too_short",
			expected: validExpectedTrust(),
			observed: validObservedTrust(policyDocument(exact), 3599),
		},
		{
			name: "malformed_expected_arn",
			expected: func() ExpectedWebIdentityTrust {
				value := validExpectedTrust()
				value.ProviderARN = "not-an-arn"
				return value
			}(),
			observed: validObservedTrust(policyDocument(exact), 3600),
		},
		{
			name:     "malformed_observed_arns",
			expected: validExpectedTrust(),
			observed: func() ObservedWebIdentityTrust {
				value := validObservedTrust(policyDocument(exact), 3600)
				value.ProviderARN = "bad-provider-arn"
				value.RoleARN = "bad-role-arn"
				return value
			}(),
		},
		{
			name: "malformed_expected_url",
			expected: func() ExpectedWebIdentityTrust {
				value := validExpectedTrust()
				value.ProviderURL = "http://issuer.c1.example.com"
				return value
			}(),
			observed: validObservedTrust(policyDocument(exact), 3600),
		},
		{
			name:     "malformed_observed_url",
			expected: validExpectedTrust(),
			observed: func() ObservedWebIdentityTrust {
				value := validObservedTrust(policyDocument(exact), 3600)
				value.ProviderURL = "https://issuer.c1.example.com:8443"
				return value
			}(),
		},
		{
			name:     "malformed_policy",
			expected: validExpectedTrust(),
			observed: observedWithPolicy(`{"Statement":`),
		},
		{
			name:     "malformed_condition_value",
			expected: validExpectedTrust(),
			observed: observedWithPolicy(policyDocument(statementWithConditions(
				testProviderARN,
				assumeRoleWithWebIdentityAction,
				`"StringEquals":{"`+testIssuer+`:aud":{"nested":"value"}}`,
			))),
		},
		{
			name:     "unknown_condition_operator_fails_closed",
			expected: validExpectedTrust(),
			observed: observedWithPolicy(policyDocument(statementWithConditions(
				testProviderARN,
				assumeRoleWithWebIdentityAction,
				unknownSubjectConditions,
			))),
		},
		{
			name:     "unknown_unrelated_operator_fails_closed",
			expected: validExpectedTrust(),
			observed: observedWithPolicy(policyDocument(statementWithConditions(
				testProviderARN,
				assumeRoleWithWebIdentityAction,
				unknownUnrelatedConditions,
			))),
		},
		{
			name: "invalid_expected_fields",
			expected: func() ExpectedWebIdentityTrust {
				value := validExpectedTrust()
				value.Audience = ""
				value.Subject = ""
				value.MaxSessionSeconds = 0
				return value
			}(),
			observed: validObservedTrust(policyDocument(exact), 3600),
		},
		{
			name:     "deterministic_mismatch_order",
			expected: validExpectedTrust(),
			observed: func() ObservedWebIdentityTrust {
				value := validObservedTrust(`not-json`, 1)
				value.RoleARN = "arn:aws:iam::" + trustTestOtherAcctID + ":role/c1-vended-role"
				value.ProviderURL = "https://wrong.example.com"
				value.ProviderClientIDs = []string{"wrong"}
				return value
			}(),
		},
		{
			name: "secret_like_values_are_not_returned",
			expected: func() ExpectedWebIdentityTrust {
				value := validExpectedTrust()
				value.Audience = "secret-audience-value"
				value.Subject = "token-like-subject-value"
				return value
			}(),
			observed: observedWithPolicy(policyDocument(exactTrustStatement(testProviderARN, "wrong", "wrong", false, false))),
		},
	}

	results := make(map[string][]TrustMismatchCode, len(tests))
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			first := EvaluateWebIdentityTrust(test.expected, test.observed)
			second := EvaluateWebIdentityTrust(test.expected, test.observed)
			require.Equal(t, first, second)
			codes := make([]TrustMismatchCode, 0, len(first))
			for _, mismatch := range first {
				codes = append(codes, mismatch.Code)
			}
			results[test.name] = codes

			if test.name == "secret_like_values_are_not_returned" {
				encoded, err := json.Marshal(first)
				require.NoError(t, err)
				assert.NotContains(t, string(encoded), test.expected.Audience)
				assert.NotContains(t, string(encoded), test.expected.Subject)
				assert.NotContains(t, string(encoded), test.observed.AssumeRolePolicyDocument)
			}
		})
	}

	expectedGoldenBytes, err := os.ReadFile("testdata/web_identity_trust.golden.json")
	require.NoError(t, err)
	var expectedGolden map[string][]TrustMismatchCode
	err = json.Unmarshal(expectedGoldenBytes, &expectedGolden)
	require.NoError(t, err)
	assert.Equal(t, expectedGolden, results)
}

func validExpectedTrust() ExpectedWebIdentityTrust {
	return ExpectedWebIdentityTrust{
		ProviderARN:       testProviderARN,
		ProviderURL:       "https://" + testIssuer,
		Audience:          testAudience,
		Subject:           testSubject,
		RequireTagSession: false,
		MaxSessionSeconds: 3600,
	}
}

func expectedWithTagSession() ExpectedWebIdentityTrust {
	value := validExpectedTrust()
	value.RequireTagSession = true
	return value
}

func validObservedTrust(policy string, duration int32) ObservedWebIdentityTrust {
	return ObservedWebIdentityTrust{
		RoleARN:                  "arn:aws:iam::" + trustTestAccountID + ":role/c1-vended-role",
		ProviderARN:              testProviderARN,
		ProviderURL:              testIssuer,
		ProviderClientIDs:        []string{"unrelated-client", testAudience},
		AssumeRolePolicyDocument: policy,
		RoleMaxSessionSeconds:    duration,
	}
}

func observedWithPolicy(policy string) ObservedWebIdentityTrust {
	return validObservedTrust(policy, 3600)
}

func observedWithProvider(providerARN string, providerURL string) ObservedWebIdentityTrust {
	value := observedWithPolicy(policyDocument(exactTrustStatement(testProviderARN, testAudience, testSubject, false, false)))
	value.ProviderARN = providerARN
	value.ProviderURL = providerURL
	return value
}

func observedWithRoleARN(roleARN string) ObservedWebIdentityTrust {
	value := observedWithPolicy(policyDocument(exactTrustStatement(testProviderARN, testAudience, testSubject, false, false)))
	value.RoleARN = roleARN
	return value
}

func observedWithClientIDs(clientIDs []string) ObservedWebIdentityTrust {
	value := observedWithPolicy(policyDocument(exactTrustStatement(testProviderARN, testAudience, testSubject, false, false)))
	value.ProviderClientIDs = clientIDs
	return value
}

func policyDocument(statements string) string {
	return `{"Version":"2012-10-17","Statement":[` + statements + `]}`
}

func singleStatementPolicy(statement string) string {
	return `{"Version":"2012-10-17","Statement":` + statement + `}`
}

func exactTrustStatement(providerARN string, audience string, subject string, listFields bool, tagSession bool) string {
	action := `"` + assumeRoleWithWebIdentityAction + `"`
	principal := `"` + providerARN + `"`
	audienceValue := `"` + audience + `"`
	subjectValue := `"` + subject + `"`
	if listFields {
		actions := []string{`"` + assumeRoleWithWebIdentityAction + `"`}
		if tagSession {
			actions = append(actions, `"`+tagSessionAction+`"`)
		}
		action = `[` + strings.Join(actions, ",") + `]`
		principal = `[` + principal + `]`
		audienceValue = `[` + audienceValue + `]`
		subjectValue = `[` + subjectValue + `]`
	}
	conditions := fmt.Sprintf(`"StringEquals":{"%s:aud":%s,"%s:sub":%s}`, testIssuer, audienceValue, testIssuer, subjectValue)
	return statementWithConditionsAndJSONAction(principal, action, conditions)
}

func exactTrustStatementWithAction(providerARN string, action string, audience string, subject string) string {
	conditions := fmt.Sprintf(`"StringEquals":{"%s:aud":"%s","%s:sub":"%s"}`, testIssuer, audience, testIssuer, subject)
	return statementWithConditions(providerARN, action, conditions)
}

func statementWithConditions(providerARN string, action string, conditions string) string {
	return statementWithConditionsAndJSONAction(`"`+providerARN+`"`, `"`+action+`"`, conditions)
}

func statementWithConditionsAndJSONAction(principalJSON string, actionJSON string, conditions string) string {
	conditionJSON := ""
	if conditions != "" {
		conditionJSON = `,"Condition":{` + conditions + `}`
	}
	return `{"Effect":"Allow","Principal":{"Federated":` + principalJSON + `},"Action":` + actionJSON + conditionJSON + `}`
}
