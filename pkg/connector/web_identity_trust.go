package connector

import (
	"encoding/json"
	"net/url"
	"path"
	"regexp"
	"slices"
	"sort"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws/arn"
)

const (
	assumeRoleWithWebIdentityAction = "sts:AssumeRoleWithWebIdentity"
	tagSessionAction                = "sts:TagSession"
)

var awsAccountIDPattern = regexp.MustCompile(`^[0-9]{12}$`)

// ExpectedWebIdentityTrust is the immutable expected shape of one C1 OIDC
// provider and role binding. Production callers must source these values from
// C1-owned configuration, never requester input.
type ExpectedWebIdentityTrust struct {
	ProviderARN       string
	ProviderURL       string
	Audience          string
	Subject           string
	RequireTagSession bool
	MaxSessionSeconds int32
}

// ObservedWebIdentityTrust contains only the AWS state needed for structural
// evaluation. Constructing it does not require or accept web identity tokens.
type ObservedWebIdentityTrust struct {
	RoleARN                  string
	ProviderARN              string
	ProviderURL              string
	ProviderClientIDs        []string
	AssumeRolePolicyDocument string
	RoleMaxSessionSeconds    int32
}

// TrustMismatchCode is a stable, non-secret reason an observed trust does not
// match the expected binding.
type TrustMismatchCode string

const (
	TrustMismatchExpectedProviderARNInvalid     TrustMismatchCode = "expected_provider_arn_invalid"
	TrustMismatchObservedProviderARNInvalid     TrustMismatchCode = "observed_provider_arn_invalid"
	TrustMismatchObservedRoleARNInvalid         TrustMismatchCode = "observed_role_arn_invalid"
	TrustMismatchExpectedProviderURLInvalid     TrustMismatchCode = "expected_provider_url_invalid"
	TrustMismatchObservedProviderURLInvalid     TrustMismatchCode = "observed_provider_url_invalid"
	TrustMismatchExpectedProviderBindingInvalid TrustMismatchCode = "expected_provider_binding_invalid"
	TrustMismatchObservedProviderBindingInvalid TrustMismatchCode = "observed_provider_binding_invalid"
	TrustMismatchExpectedAudienceInvalid        TrustMismatchCode = "expected_audience_invalid"
	TrustMismatchExpectedSubjectInvalid         TrustMismatchCode = "expected_subject_invalid"
	TrustMismatchExpectedSessionDurationInvalid TrustMismatchCode = "expected_session_duration_invalid"
	TrustMismatchProviderRolePartitionMismatch  TrustMismatchCode = "provider_role_partition_mismatch"
	TrustMismatchProviderRoleAccountMismatch    TrustMismatchCode = "provider_role_account_mismatch"
	TrustMismatchProviderARN                    TrustMismatchCode = "provider_arn_mismatch"
	TrustMismatchProviderURL                    TrustMismatchCode = "provider_url_mismatch"
	TrustMismatchProviderAudienceMissing        TrustMismatchCode = "provider_audience_missing"
	TrustMismatchPolicyDocumentInvalid          TrustMismatchCode = "policy_document_invalid"
	TrustMismatchProviderAllowStatementMissing  TrustMismatchCode = "provider_allow_statement_missing"
	TrustMismatchWebIdentityActionMissing       TrustMismatchCode = "web_identity_action_missing"
	TrustMismatchAudienceConditionMissing       TrustMismatchCode = "audience_condition_missing"
	TrustMismatchAudienceConditionMismatch      TrustMismatchCode = "audience_condition_mismatch"
	TrustMismatchAudienceConditionUnsafe        TrustMismatchCode = "audience_condition_unsafe"
	TrustMismatchSubjectConditionMissing        TrustMismatchCode = "subject_condition_missing"
	TrustMismatchSubjectConditionMismatch       TrustMismatchCode = "subject_condition_mismatch"
	TrustMismatchSubjectConditionUnsafe         TrustMismatchCode = "subject_condition_unsafe"
	TrustMismatchConditionOperatorUnsupported   TrustMismatchCode = "condition_operator_unsupported"
	TrustMismatchTagSessionActionMissing        TrustMismatchCode = "tag_session_action_missing"
	TrustMismatchRoleMaxSessionTooShort         TrustMismatchCode = "role_max_session_too_short"
	TrustMismatchBroadProviderStatement         TrustMismatchCode = "broad_provider_statement"
)

// TrustMismatch includes a stable code and optional safe structural context.
// Context never contains policy values, tokens, credentials, or policy text.
type TrustMismatch struct {
	Code    TrustMismatchCode `json:"code"`
	Context string            `json:"context,omitempty"`
}

// EvaluateWebIdentityTrust performs a pure, deterministic comparison of AWS
// IAM state against an expected C1 web identity trust binding.
func EvaluateWebIdentityTrust(expected ExpectedWebIdentityTrust, observed ObservedWebIdentityTrust) []TrustMismatch {
	mismatches := make([]TrustMismatch, 0)

	expectedProvider, expectedProviderOK := parseIAMARN(expected.ProviderARN, "oidc-provider/")
	if !expectedProviderOK {
		mismatches = appendMismatch(mismatches, TrustMismatchExpectedProviderARNInvalid, "expected_provider")
	}
	observedProvider, observedProviderOK := parseIAMARN(observed.ProviderARN, "oidc-provider/")
	if !observedProviderOK {
		mismatches = appendMismatch(mismatches, TrustMismatchObservedProviderARNInvalid, "observed_provider")
	}
	observedRole, observedRoleOK := parseIAMARN(observed.RoleARN, "role/")
	if !observedRoleOK {
		mismatches = appendMismatch(mismatches, TrustMismatchObservedRoleARNInvalid, "observed_role")
	}

	expectedURL, expectedURLOK := parseProviderURL(expected.ProviderURL)
	if !expectedURLOK {
		mismatches = appendMismatch(mismatches, TrustMismatchExpectedProviderURLInvalid, "expected_provider")
	}
	observedURL, observedURLOK := parseProviderURL(observed.ProviderURL)
	if !observedURLOK {
		mismatches = appendMismatch(mismatches, TrustMismatchObservedProviderURLInvalid, "observed_provider")
	}

	if expectedProviderOK && expectedURLOK && strings.TrimPrefix(expectedProvider.Resource, "oidc-provider/") != expectedURL.conditionPrefix {
		mismatches = appendMismatch(mismatches, TrustMismatchExpectedProviderBindingInvalid, "expected_provider")
	}
	if observedProviderOK && observedURLOK && strings.TrimPrefix(observedProvider.Resource, "oidc-provider/") != observedURL.conditionPrefix {
		mismatches = appendMismatch(mismatches, TrustMismatchObservedProviderBindingInvalid, "observed_provider")
	}
	if expected.Audience == "" {
		mismatches = appendMismatch(mismatches, TrustMismatchExpectedAudienceInvalid, "audience")
	}
	if expected.Subject == "" {
		mismatches = appendMismatch(mismatches, TrustMismatchExpectedSubjectInvalid, "subject")
	}
	if expected.MaxSessionSeconds <= 0 {
		mismatches = appendMismatch(mismatches, TrustMismatchExpectedSessionDurationInvalid, "max_session_seconds")
	}

	if observedProviderOK && observedRoleOK {
		if observedProvider.Partition != observedRole.Partition {
			mismatches = appendMismatch(mismatches, TrustMismatchProviderRolePartitionMismatch, "provider_role")
		}
		if observedProvider.AccountID != observedRole.AccountID {
			mismatches = appendMismatch(mismatches, TrustMismatchProviderRoleAccountMismatch, "provider_role")
		}
	}
	if expectedProviderOK && observedProviderOK && expected.ProviderARN != observed.ProviderARN {
		mismatches = appendMismatch(mismatches, TrustMismatchProviderARN, "provider")
	}
	if expectedURLOK && observedURLOK && expectedURL.canonical != observedURL.canonical {
		mismatches = appendMismatch(mismatches, TrustMismatchProviderURL, "provider")
	}
	if expected.Audience != "" && !slices.Contains(observed.ProviderClientIDs, expected.Audience) {
		mismatches = appendMismatch(mismatches, TrustMismatchProviderAudienceMissing, "audience")
	}

	policy, policyOK := parseTrustPolicyDocument(observed.AssumeRolePolicyDocument)
	if !policyOK {
		mismatches = appendMismatch(mismatches, TrustMismatchPolicyDocumentInvalid, "assume_role_policy")
	} else if expectedProviderOK && expectedURLOK && expected.Audience != "" && expected.Subject != "" {
		mismatches = append(mismatches, evaluateTrustPolicy(expected, expectedURL.conditionPrefix, policy)...)
	}

	if expected.MaxSessionSeconds > 0 && observed.RoleMaxSessionSeconds < expected.MaxSessionSeconds {
		mismatches = appendMismatch(mismatches, TrustMismatchRoleMaxSessionTooShort, "max_session_seconds")
	}

	return mismatches
}

type providerURL struct {
	canonical       string
	conditionPrefix string
}

func parseProviderURL(value string) (providerURL, bool) {
	if value == "" || strings.TrimSpace(value) != value {
		return providerURL{}, false
	}
	withScheme := value
	if !strings.Contains(value, "://") {
		// GetOpenIDConnectProvider returns the registered provider URL without
		// the https:// prefix in AWS's documented response example.
		// https://docs.aws.amazon.com/IAM/latest/APIReference/API_GetOpenIDConnectProvider.html
		withScheme = "https://" + value
	}
	parsed, err := url.Parse(withScheme)
	invalid := err != nil || parsed.Scheme != "https" || parsed.Host == "" || parsed.Hostname() == "" ||
		parsed.Port() != "" || parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" || parsed.Opaque != ""
	if invalid {
		return providerURL{}, false
	}
	canonical := strings.TrimSuffix(parsed.String(), "/")
	if canonical == "https:" {
		return providerURL{}, false
	}
	return providerURL{
		canonical:       canonical,
		conditionPrefix: strings.TrimPrefix(canonical, "https://"),
	}, true
}

func parseIAMARN(value string, resourcePrefix string) (arn.ARN, bool) {
	parsed, err := arn.Parse(value)
	if err != nil || parsed.Partition == "" || parsed.Service != "iam" || parsed.Region != "" || !awsAccountIDPattern.MatchString(parsed.AccountID) {
		return arn.ARN{}, false
	}
	if !strings.HasPrefix(parsed.Resource, resourcePrefix) || strings.TrimPrefix(parsed.Resource, resourcePrefix) == "" {
		return arn.ARN{}, false
	}
	return parsed, true
}

func parseTrustPolicyDocument(document string) (TrustPolicy, bool) {
	var policy TrustPolicy
	if err := json.Unmarshal([]byte(document), &policy); err == nil {
		return policy, true
	}
	decoded, err := url.QueryUnescape(document)
	if err != nil {
		return TrustPolicy{}, false
	}
	if err := json.Unmarshal([]byte(decoded), &policy); err != nil {
		return TrustPolicy{}, false
	}
	return policy, true
}

func evaluateTrustPolicy(expected ExpectedWebIdentityTrust, conditionPrefix string, policy TrustPolicy) []TrustMismatch {
	audienceKey := conditionPrefix + ":aud"
	subjectKey := conditionPrefix + ":sub"

	candidates := make([]Statement, 0)
	for _, statement := range policy.Statement {
		if statement.Effect == trustPolicyAllowEffect && slices.Contains(statement.Principal.Federated, expected.ProviderARN) {
			candidates = append(candidates, statement)
		}
	}
	if len(candidates) == 0 {
		return []TrustMismatch{{Code: TrustMismatchProviderAllowStatementMissing, Context: "provider"}}
	}

	actionCandidates := make([]Statement, 0, len(candidates))
	for _, statement := range candidates {
		if slices.Contains(statement.Action, assumeRoleWithWebIdentityAction) {
			actionCandidates = append(actionCandidates, statement)
		}
	}
	if len(actionCandidates) == 0 {
		return []TrustMismatch{{Code: TrustMismatchWebIdentityActionMissing, Context: "action"}}
	}

	best := statementMismatches(expected, audienceKey, subjectKey, actionCandidates[0])
	validIndex := -1
	if len(best) == 0 {
		validIndex = 0
	}
	for i := 1; i < len(actionCandidates); i++ {
		current := statementMismatches(expected, audienceKey, subjectKey, actionCandidates[i])
		if len(current) == 0 && validIndex == -1 {
			validIndex = i
		}
		if mismatchListLess(current, best) {
			best = current
		}
	}
	if validIndex == -1 {
		return best
	}

	for _, statement := range candidates {
		if actionAllowsWebIdentity(statement.Action) && broadlyTrustsProvider(statement, audienceKey, subjectKey, expected) {
			return []TrustMismatch{{Code: TrustMismatchBroadProviderStatement, Context: "provider"}}
		}
	}
	return nil
}

func statementMismatches(expected ExpectedWebIdentityTrust, audienceKey string, subjectKey string, statement Statement) []TrustMismatch {
	mismatches := make([]TrustMismatch, 0, 3)
	if operator := unsupportedUnrelatedConditionOperator(statement.Condition, audienceKey, subjectKey); operator != "" {
		mismatches = appendMismatch(mismatches, TrustMismatchConditionOperatorUnsupported, operator)
	}
	mismatches = appendConditionMismatch(mismatches, statement.Condition, audienceKey, expected.Audience, true)
	mismatches = appendConditionMismatch(mismatches, statement.Condition, subjectKey, expected.Subject, false)
	if expected.RequireTagSession && !slices.Contains(statement.Action, tagSessionAction) {
		mismatches = appendMismatch(mismatches, TrustMismatchTagSessionActionMissing, "action")
	}
	return mismatches
}

type conditionMatch int

const (
	conditionExact conditionMatch = iota
	conditionMissing
	conditionMismatch
	conditionUnsafe
)

func matchExactCondition(condition Condition, key string, expected string) conditionMatch {
	for operator, entries := range condition {
		if operator != "StringEquals" {
			if _, ok := entries[key]; !ok {
				continue
			}
			return conditionUnsafe
		}
	}
	values, found := condition["StringEquals"][key]
	if !found {
		return conditionMissing
	}
	if len(values) != 1 || strings.ContainsAny(values[0], "*?") {
		return conditionUnsafe
	}
	if values[0] != expected {
		return conditionMismatch
	}
	return conditionExact
}

func unsupportedUnrelatedConditionOperator(condition Condition, audienceKey string, subjectKey string) string {
	operators := make([]string, 0)
	for operator, entries := range condition {
		if operator == "StringEquals" || operator == "StringLike" {
			continue
		}
		if _, relevant := entries[audienceKey]; relevant {
			continue
		}
		if _, relevant := entries[subjectKey]; relevant {
			continue
		}
		operators = append(operators, operator)
	}
	if len(operators) == 0 {
		return ""
	}
	sort.Strings(operators)
	return operators[0]
}

func appendConditionMismatch(mismatches []TrustMismatch, condition Condition, key string, expected string, audience bool) []TrustMismatch {
	switch matchExactCondition(condition, key, expected) {
	case conditionExact:
		return mismatches
	case conditionMissing:
		if audience {
			return appendMismatch(mismatches, TrustMismatchAudienceConditionMissing, key)
		}
		return appendMismatch(mismatches, TrustMismatchSubjectConditionMissing, key)
	case conditionMismatch:
		if audience {
			return appendMismatch(mismatches, TrustMismatchAudienceConditionMismatch, key)
		}
		return appendMismatch(mismatches, TrustMismatchSubjectConditionMismatch, key)
	case conditionUnsafe:
		if audience {
			return appendMismatch(mismatches, TrustMismatchAudienceConditionUnsafe, key)
		}
		return appendMismatch(mismatches, TrustMismatchSubjectConditionUnsafe, key)
	default:
		return mismatches
	}
}

func broadlyTrustsProvider(statement Statement, audienceKey string, subjectKey string, expected ExpectedWebIdentityTrust) bool {
	return matchExactCondition(statement.Condition, audienceKey, expected.Audience) != conditionExact ||
		matchExactCondition(statement.Condition, subjectKey, expected.Subject) != conditionExact
}

func actionAllowsWebIdentity(actions Action) bool {
	for _, action := range actions {
		matched, err := path.Match(strings.ToLower(action), strings.ToLower(assumeRoleWithWebIdentityAction))
		if err == nil && matched {
			return true
		}
	}
	return false
}

func mismatchListLess(left []TrustMismatch, right []TrustMismatch) bool {
	if len(left) != len(right) {
		return len(left) < len(right)
	}
	for i := range left {
		if left[i].Code != right[i].Code {
			return left[i].Code < right[i].Code
		}
		if left[i].Context != right[i].Context {
			return left[i].Context < right[i].Context
		}
	}
	return false
}

func appendMismatch(mismatches []TrustMismatch, code TrustMismatchCode, context string) []TrustMismatch {
	return append(mismatches, TrustMismatch{Code: code, Context: context})
}
