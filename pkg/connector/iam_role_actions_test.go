package connector

import (
	"context"
	"testing"
	"time"

	awsSdk "github.com/aws/aws-sdk-go-v2/aws"
	awsmiddleware "github.com/aws/aws-sdk-go-v2/aws/middleware"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	iamTypes "github.com/aws/aws-sdk-go-v2/service/iam/types"
	smithymiddleware "github.com/aws/smithy-go/middleware"
	v2 "github.com/conductorone/baton-sdk/pb/c1/connector/v2"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/structpb"
)

// opStub returns a real *iam.Client whose operations are answered by fn (keyed by operation
// name) with no network access; calls records the operations invoked in order.
func opStub(calls *[]string, fn func(op string, in any) (any, error)) *iam.Client {
	return iam.New(iam.Options{
		Region: "us-east-1",
		APIOptions: []func(*smithymiddleware.Stack) error{
			func(stack *smithymiddleware.Stack) error {
				return stack.Finalize.Add(
					smithymiddleware.FinalizeMiddlewareFunc("opStub",
						func(ctx context.Context, _ smithymiddleware.FinalizeInput, _ smithymiddleware.FinalizeHandler) (smithymiddleware.FinalizeOutput, smithymiddleware.Metadata, error) {
							op := awsmiddleware.GetOperationName(ctx)
							*calls = append(*calls, op)
							out, err := fn(op, nil)
							if err == nil {
								if _, empty := out.(struct{}); empty {
									out = emptyIAMOutput(op)
								}
							}
							return smithymiddleware.FinalizeOutput{Result: out}, smithymiddleware.Metadata{}, err
						}),
					smithymiddleware.Before,
				)
			},
		},
	})
}

func roleArgs(t *testing.T, m map[string]any) *structpb.Struct {
	t.Helper()
	s, err := structpb.NewStruct(m)
	require.NoError(t, err)
	return s
}

const testTrust = `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"AWS":"arn:aws:iam::111111111111:root"},"Action":"sts:AssumeRole"}]}`

func TestParseCreateRoleArgs_Validation(t *testing.T) {
	now := time.Now()
	base := func() map[string]any {
		return map[string]any{"role_name": "eks-deployer", "trust_policy_json": testTrust}
	}
	with := func(k string, v any) map[string]any { m := base(); m[k] = v; return m }

	for name, m := range map[string]map[string]any{
		"bad name":         with("role_name", "bad name!"),
		"bad trust":        with("trust_policy_json", "{nope"),
		"bad path":         with("path", "noslash"),
		"short duration":   with("max_session_duration_seconds", 100),
		"reserved tag":     with("tags", map[string]any{"baton:managed-by": "x"}),
		"past expiry":      with("expires_at", now.Add(-time.Hour).Format(time.RFC3339)),
		"bad expiry":       with("expires_at", "tomorrow"),
		"bad policy arn":   with("managed_policy_arns", []any{"nope"}),
		"bad inline json":  with("inline_policies", map[string]any{"p": "{"}),
		"bad boundary arn": with("permissions_boundary_arn", "x"),
	} {
		_, err := parseCreateRoleArgs(roleArgs(t, m), now)
		require.Error(t, err, name)
		require.Equal(t, codes.InvalidArgument, status.Code(err), name)
	}

	req, err := parseCreateRoleArgs(roleArgs(t, with("expires_at", now.Add(time.Hour).Format(time.RFC3339))), now)
	require.NoError(t, err)
	require.Equal(t, defaultDynamicRolePath, req.path)
	require.EqualValues(t, 3600, req.maxSession)
	keys := map[string]bool{}
	for _, tg := range req.tags {
		keys[awsSdk.ToString(tg.Key)] = true
	}
	require.True(t, keys[managedRoleTagKey])
	require.True(t, keys[roleExpiresAtTagKey])
}

func TestCreateIAMRole_Success(t *testing.T) {
	var calls []string
	c := &AWS{iamClient: opStub(&calls, func(op string, _ any) (any, error) {
		switch op {
		case "CreateRole":
			return &iam.CreateRoleOutput{Role: &iamTypes.Role{Arn: awsSdk.String("arn:aws:iam::222222222222:role/c1/eks-deployer")}}, nil
		}
		return struct{}{}, nil
	})}
	resp, _, err := c.createIAMRole(context.Background(), roleArgs(t, map[string]any{
		"role_name":           "eks-deployer",
		"trust_policy_json":   testTrust,
		"managed_policy_arns": []any{"arn:aws:iam::aws:policy/AmazonEKSClusterPolicy"},
		"inline_policies":     map[string]any{"extra": `{"Version":"2012-10-17","Statement":[]}`},
	}))
	require.NoError(t, err)
	require.Equal(t, []string{"CreateRole", "AttachRolePolicy", "PutRolePolicy"}, calls)
	require.Equal(t, "arn:aws:iam::222222222222:role/c1/eks-deployer", resp.GetFields()["role_arn"].GetStringValue())
	require.True(t, resp.GetFields()["created"].GetBoolValue())
}

func TestCreateIAMRole_ExistingUnmanagedRoleRefused(t *testing.T) {
	var calls []string
	c := &AWS{iamClient: opStub(&calls, func(op string, _ any) (any, error) {
		switch op {
		case "CreateRole":
			return nil, &iamTypes.EntityAlreadyExistsException{}
		case "GetRole":
			return &iam.GetRoleOutput{Role: &iamTypes.Role{Arn: awsSdk.String("arn:aws:iam::2:role/x")}}, nil
		}
		return struct{}{}, nil
	})}
	_, _, err := c.createIAMRole(context.Background(), roleArgs(t, map[string]any{"role_name": "x", "trust_policy_json": testTrust}))
	require.Equal(t, codes.AlreadyExists, status.Code(err))
	require.NotContains(t, calls, "UpdateAssumeRolePolicy")
}

func TestCreateIAMRole_PolicyFailureRollsBackNewRole(t *testing.T) {
	var calls []string
	c := &AWS{iamClient: opStub(&calls, func(op string, _ any) (any, error) {
		switch op {
		case "CreateRole":
			return &iam.CreateRoleOutput{Role: &iamTypes.Role{Arn: awsSdk.String("arn:aws:iam::2:role/c1/x")}}, nil
		case "AttachRolePolicy":
			return nil, &iamTypes.LimitExceededException{}
		case "ListAttachedRolePolicies":
			return &iam.ListAttachedRolePoliciesOutput{}, nil
		case "ListRolePolicies":
			return &iam.ListRolePoliciesOutput{}, nil
		case "ListInstanceProfilesForRole":
			return &iam.ListInstanceProfilesForRoleOutput{}, nil
		}
		return struct{}{}, nil
	})}
	_, _, err := c.createIAMRole(context.Background(), roleArgs(t, map[string]any{
		"role_name": "x", "trust_policy_json": testTrust,
		"managed_policy_arns": []any{"arn:aws:iam::aws:policy/ReadOnlyAccess"},
	}))
	require.Equal(t, codes.ResourceExhausted, status.Code(err))
	require.Equal(t, "DeleteRole", calls[len(calls)-1])
}

func TestDeleteIAMRole(t *testing.T) {
	t.Run("missing role is already deleted", func(t *testing.T) {
		var calls []string
		c := &AWS{iamClient: opStub(&calls, func(string, any) (any, error) { return nil, &iamTypes.NoSuchEntityException{} })}
		resp, annos, err := c.deleteIAMRole(context.Background(), roleArgs(t, map[string]any{"role_name": "gone"}))
		require.NoError(t, err)
		require.True(t, annos.Contains(&v2.ResourceDoesNotExist{}))
		require.False(t, resp.GetFields()["deleted"].GetBoolValue())
	})
	t.Run("refuses role without managed tag", func(t *testing.T) {
		var calls []string
		c := &AWS{iamClient: opStub(&calls, func(op string, _ any) (any, error) {
			switch op {
			case "GetRole":
				return &iam.GetRoleOutput{Role: &iamTypes.Role{}}, nil
			case "ListRoleTags":
				return &iam.ListRoleTagsOutput{Tags: []iamTypes.Tag{{Key: awsSdk.String("team"), Value: awsSdk.String("a")}}}, nil
			}
			return struct{}{}, nil
		})}
		_, _, err := c.deleteIAMRole(context.Background(), roleArgs(t, map[string]any{"role_name": "prod-admin"}))
		require.Equal(t, codes.FailedPrecondition, status.Code(err))
		require.NotContains(t, calls, "DeleteRole")
	})
	t.Run("managed role is detached then deleted", func(t *testing.T) {
		var calls []string
		c := &AWS{iamClient: opStub(&calls, func(op string, _ any) (any, error) {
			switch op {
			case "GetRole":
				return &iam.GetRoleOutput{Role: &iamTypes.Role{}}, nil
			case "ListRoleTags":
				return &iam.ListRoleTagsOutput{Tags: []iamTypes.Tag{{Key: awsSdk.String(managedRoleTagKey), Value: awsSdk.String(managedRoleTagValue)}}}, nil
			case "ListAttachedRolePolicies":
				return &iam.ListAttachedRolePoliciesOutput{AttachedPolicies: []iamTypes.AttachedPolicy{{PolicyArn: awsSdk.String("arn:aws:iam::aws:policy/ReadOnlyAccess")}}}, nil
			case "ListRolePolicies":
				return &iam.ListRolePoliciesOutput{PolicyNames: []string{"extra"}}, nil
			case "ListInstanceProfilesForRole":
				return &iam.ListInstanceProfilesForRoleOutput{}, nil
			}
			return struct{}{}, nil
		})}
		resp, annos, err := c.deleteIAMRole(context.Background(), roleArgs(t, map[string]any{"role_name": "eks-deployer"}))
		require.NoError(t, err)
		require.Empty(t, annos)
		require.True(t, resp.GetFields()["deleted"].GetBoolValue())
		require.Equal(t, "DeleteRole", calls[len(calls)-1])
		require.Contains(t, calls, "DetachRolePolicy")
		require.Contains(t, calls, "DeleteRolePolicy")
	})
}

func TestIAMClientForAccount_InvalidID(t *testing.T) {
	_, err := (&AWS{}).iamClientForAccount(context.Background(), "abc")
	require.Equal(t, codes.InvalidArgument, status.Code(err))
}

// emptyIAMOutput returns the zero-value output type the SDK deserializer expects per operation.
func emptyIAMOutput(op string) any {
	switch op {
	case "AttachRolePolicy":
		return &iam.AttachRolePolicyOutput{}
	case "PutRolePolicy":
		return &iam.PutRolePolicyOutput{}
	case "DetachRolePolicy":
		return &iam.DetachRolePolicyOutput{}
	case "DeleteRolePolicy":
		return &iam.DeleteRolePolicyOutput{}
	case "DeleteRole":
		return &iam.DeleteRoleOutput{}
	case "UpdateAssumeRolePolicy":
		return &iam.UpdateAssumeRolePolicyOutput{}
	case "UpdateRole":
		return &iam.UpdateRoleOutput{}
	case "TagRole":
		return &iam.TagRoleOutput{}
	case "RemoveRoleFromInstanceProfile":
		return &iam.RemoveRoleFromInstanceProfileOutput{}
	}
	return struct{}{}
}
