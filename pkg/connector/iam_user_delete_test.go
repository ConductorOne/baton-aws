package connector

import (
	"context"
	"errors"
	"testing"

	"github.com/aws/aws-sdk-go-v2/service/iam"
	iamTypes "github.com/aws/aws-sdk-go-v2/service/iam/types"
	smithymiddleware "github.com/aws/smithy-go/middleware"
	v2 "github.com/conductorone/baton-sdk/pb/c1/connector/v2"
	"github.com/stretchr/testify/require"
)

// iamUserResourceType.iamClient is the concrete *iam.Client, so instead of an
// interface seam we build a real client whose first (GetUser) call is
// short-circuited by an AWS SDK v2 Finalize middleware returning the desired
// error, without touching the network. The SDK wraps the returned error in a
// *smithy.OperationError, which errors.As unwraps, so the production
// errors.As(&iamTypes.NoSuchEntityException{}) branch is genuinely exercised.
//
// The ordinary-success IAM path (~19 sequential IAM calls after GetUser) is
// intentionally NOT tested here: the "ordinary success emits no marker"
// behavior is already covered by TestSSOUserDelete_OrdinarySuccess_NoMarker.
func iamClientReturning(err error) *iam.Client {
	return iam.New(iam.Options{
		Region: "us-east-1",
		APIOptions: []func(*smithymiddleware.Stack) error{
			func(stack *smithymiddleware.Stack) error {
				return stack.Finalize.Add(
					smithymiddleware.FinalizeMiddlewareFunc("stubErr",
						func(ctx context.Context, in smithymiddleware.FinalizeInput, next smithymiddleware.FinalizeHandler) (smithymiddleware.FinalizeOutput, smithymiddleware.Metadata, error) {
							return smithymiddleware.FinalizeOutput{}, smithymiddleware.Metadata{}, err
						}),
					smithymiddleware.Before,
				)
			},
		},
	})
}

func iamUserResourceID() *v2.ResourceId {
	// arn:aws:iam::123456789012:user/ci-iam-1 -> iamUserNameFromARN => "ci-iam-1"
	return &v2.ResourceId{
		ResourceType: resourceTypeIAMUser.Id,
		Resource:     "arn:aws:iam::123456789012:user/ci-iam-1",
	}
}

func TestIAMUserDelete_ConfirmedAbsence_ReturnsMarker(t *testing.T) {
	ctx := context.Background()
	o := &iamUserResourceType{
		resourceType: resourceTypeIAMUser,
		iamClient:    iamClientReturning(&iamTypes.NoSuchEntityException{}),
	}

	annos, err := o.Delete(ctx, iamUserResourceID(), nil)
	require.NoError(t, err)
	require.True(t, annos.Contains(&v2.ResourceDoesNotExist{}), "GetUser NoSuchEntity must emit the ResourceDoesNotExist marker")
}

func TestIAMUserDelete_OtherGetUserError_StaysError(t *testing.T) {
	ctx := context.Background()
	o := &iamUserResourceType{
		resourceType: resourceTypeIAMUser,
		iamClient:    iamClientReturning(errors.New("boom")),
	}

	annos, err := o.Delete(ctx, iamUserResourceID(), nil)
	require.Error(t, err)
	require.False(t, annos.Contains(&v2.ResourceDoesNotExist{}), "a non-NoSuchEntity GetUser error must NOT emit the marker")
}

func TestIAMUserDelete_WrongResourceType_Error(t *testing.T) {
	ctx := context.Background()
	o := &iamUserResourceType{
		resourceType: resourceTypeIAMUser,
		iamClient:    iamClientReturning(errors.New("should not be called")),
	}

	resourceID := &v2.ResourceId{
		ResourceType: resourceTypeSSOUser.Id,
		Resource:     "arn:aws:iam::123456789012:user/ci-iam-1",
	}

	annos, err := o.Delete(ctx, resourceID, nil)
	require.Error(t, err)
	require.False(t, annos.Contains(&v2.ResourceDoesNotExist{}))
}
