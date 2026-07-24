package connector

import (
	"context"
	"testing"

	awsSdk "github.com/aws/aws-sdk-go-v2/aws"
	iamTypes "github.com/aws/aws-sdk-go-v2/service/iam/types"
	v2 "github.com/conductorone/baton-sdk/pb/c1/connector/v2"
	resourceSdk "github.com/conductorone/baton-sdk/pkg/types/resource"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestIamUserToResource_AttachesEmailAndProfile(t *testing.T) {
	user := &iamTypes.User{
		UserName: awsSdk.String("ci-iam-1"),
		Arn:      awsSdk.String("arn:aws:iam::123456789012:user/ci-iam-1"),
		Path:     awsSdk.String("/"),
		UserId:   awsSdk.String("AIDAEXAMPLE"),
	}

	resource, err := iamUserToResource(context.Background(), user, "ci-iam-1@example.com")
	require.NoError(t, err)
	require.NotNil(t, resource)

	trait, err := resourceSdk.GetUserTrait(resource)
	require.NoError(t, err)
	require.NotNil(t, trait, "user trait must be attached")

	emails := trait.GetEmails()
	require.NotEmpty(t, emails, "email trait must be present")
	assert.Equal(t, "ci-iam-1@example.com", emails[0].GetAddress())
	assert.True(t, emails[0].GetIsPrimary(), "passed-in email should be marked primary")

	profile := resource.GetProfile().AsMap()
	assert.Equal(t, "arn:aws:iam::123456789012:user/ci-iam-1", profile["aws_arn"])
	assert.Equal(t, "AIDAEXAMPLE", profile["aws_user_id"])
	assert.Equal(t, iamType, profile["aws_user_type"])
}

func TestIamUserToResource_NoEmailFallsBackToUsername(t *testing.T) {
	user := &iamTypes.User{
		UserName: awsSdk.String("user@example.com"),
		Arn:      awsSdk.String("arn:aws:iam::123456789012:user/user@example.com"),
		Path:     awsSdk.String("/"),
		UserId:   awsSdk.String("AIDAEXAMPLE2"),
	}

	resource, err := iamUserToResource(context.Background(), user, "")
	require.NoError(t, err)

	trait, err := resourceSdk.GetUserTrait(resource)
	require.NoError(t, err)

	emails := trait.GetEmails()
	require.Len(t, emails, 1, "username-as-email should be picked up by getUserEmails")
	assert.Equal(t, "user@example.com", emails[0].GetAddress())
	assert.True(t, emails[0].GetIsPrimary(), "fallback email should be primary when no explicit email passed")
}

func TestIamUserToResource_DedupesEmailFromUsername(t *testing.T) {
	user := &iamTypes.User{
		UserName: awsSdk.String("dup@example.com"),
		Arn:      awsSdk.String("arn:aws:iam::123456789012:user/dup@example.com"),
		Path:     awsSdk.String("/"),
		UserId:   awsSdk.String("AIDAEXAMPLE3"),
	}

	resource, err := iamUserToResource(context.Background(), user, "dup@example.com")
	require.NoError(t, err)

	trait, err := resourceSdk.GetUserTrait(resource)
	require.NoError(t, err)

	emails := trait.GetEmails()
	require.Len(t, emails, 1, "email passed in must not be duplicated by getUserEmails")
	assert.Equal(t, "dup@example.com", emails[0].GetAddress())
}

// Grants on iamUserResourceType exists only to emit cross-type iam_policy "attached"
// grants. When syncIAMPolicyGrants is false, it must short-circuit before ever touching
// the IAM client/factory: both are nil here, so if the gate were missing (pre-fix
// behavior) this would panic on a nil-pointer dereference rather than return cleanly.
func TestIamUserGrants_SkipsWhenIAMPolicyGrantsGateOff(t *testing.T) {
	o := &iamUserResourceType{
		resourceType:        resourceTypeIAMUser,
		iamClient:           nil,
		awsClientFactory:    nil,
		aws:                 nil,
		syncIAMPolicyGrants: false,
	}

	resource := &v2.Resource{
		Id: &v2.ResourceId{
			ResourceType: resourceTypeIAMUser.Id,
			Resource:     "arn:aws:iam::123456789012:user/ci-iam-1",
		},
	}

	grants, results, err := o.Grants(context.Background(), resource, resourceSdk.SyncOpAttrs{})
	require.NoError(t, err)
	assert.Empty(t, grants)
	assert.Nil(t, results)
}
