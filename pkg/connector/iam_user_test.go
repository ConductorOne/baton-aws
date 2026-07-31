package connector

import (
	"context"
	"testing"

	awsSdk "github.com/aws/aws-sdk-go-v2/aws"
	iamTypes "github.com/aws/aws-sdk-go-v2/service/iam/types"
	v2 "github.com/conductorone/baton-sdk/pb/c1/connector/v2"
	"github.com/conductorone/baton-sdk/pkg/annotations"
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

// ResourceType on iamUserResourceType is the gate for cross-type iam_policy "attached"
// grants: when iam_policy IS being synced, it must return the resource type unchanged
// (already carrying the static SkipEntitlements annotation). When iam_policy is NOT being
// synced, it must attach SkipEntitlementsAndGrants so the SDK skips this resource type's
// Grants() call entirely rather than emit grants referencing an unsynced resource type.
func TestIamUserResourceType_SkipsEntitlementsWhenSyncingIAMPolicy(t *testing.T) {
	o := &iamUserResourceType{
		resourceType:        resourceTypeIAMUser,
		syncIAMPolicyGrants: true,
	}

	rt := o.ResourceType(context.Background())
	require.NotNil(t, rt)

	annos := annotations.Annotations(rt.Annotations)
	assert.True(t, annos.Contains(&v2.SkipEntitlements{}))
	assert.False(t, annos.Contains(&v2.SkipEntitlementsAndGrants{}))
}

func TestIamUserResourceType_SkipsEntitlementsAndGrantsWhenNotSyncingIAMPolicy(t *testing.T) {
	o := &iamUserResourceType{
		resourceType:        resourceTypeIAMUser,
		syncIAMPolicyGrants: false,
	}

	rt := o.ResourceType(context.Background())
	require.NotNil(t, rt)

	annos := annotations.Annotations(rt.Annotations)
	assert.True(t, annos.Contains(&v2.SkipEntitlementsAndGrants{}))

	// The package-level var must not have been mutated by the clone-and-annotate path;
	// other builder instances across the test run share this same var.
	sharedAnnos := annotations.Annotations(resourceTypeIAMUser.Annotations)
	assert.False(t, sharedAnnos.Contains(&v2.SkipEntitlementsAndGrants{}))
}
