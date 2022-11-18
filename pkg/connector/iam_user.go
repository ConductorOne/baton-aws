package connector

import (
	"context"
	"fmt"
	"strings"

	awsSdk "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	iamTypes "github.com/aws/aws-sdk-go-v2/service/iam/types"
	v2 "github.com/conductorone/baton-sdk/pb/c1/connector/v2"
	"github.com/conductorone/baton-sdk/pkg/annotations"
	"github.com/conductorone/baton-sdk/pkg/pagination"
	"google.golang.org/protobuf/types/known/structpb"
)

type iamUserResourceType struct {
	resourceType *v2.ResourceType
	iamClient    *iam.Client
}

func (o *iamUserResourceType) ResourceType(_ context.Context) *v2.ResourceType {
	return o.resourceType
}

func (o *iamUserResourceType) List(ctx context.Context, _ *v2.ResourceId, pt *pagination.Token) ([]*v2.Resource, string, annotations.Annotations, error) {
	bag := &pagination.Bag{}
	err := bag.Unmarshal(pt.Token)

	if bag.Current() == nil {
		bag.Push(pagination.PageState{
			ResourceTypeID: resourceTypeIAMUser.Id,
		})
	}

	listUsersInput := &iam.ListUsersInput{}
	if bag.PageToken() != "" {
		listUsersInput.Marker = awsSdk.String(bag.PageToken())
	}

	resp, err := o.iamClient.ListUsers(ctx, listUsersInput)
	if err != nil {
		return nil, "", nil, fmt.Errorf("aws-connector: iam.ListUsers failed: %w", err)
	}

	rv := make([]*v2.Resource, 0, len(resp.Users))
	for _, user := range resp.Users {
		ur, err := iamUserResource(ctx, user)
		if err != nil {
			return nil, "", nil, err
		}
		rv = append(rv, ur)
	}

	hasNextPage := resp.IsTruncated && resp.Marker != nil
	if !hasNextPage {
		return rv, "", nil, nil
	}

	// TODO(lauren) update connector-sdk version and simplify this by just calling bag.NextToken
	err = bag.Next(awsSdk.ToString(resp.Marker))
	if err != nil {
		return nil, "", nil, err
	}

	nextPage, err := bag.Marshal()
	if err != nil {
		return nil, "", nil, fmt.Errorf("aws-connector: failed to marshal pagination bag: %w", err)
	}

	return rv, nextPage, nil, nil
}

func (o *iamUserResourceType) Entitlements(_ context.Context, _ *v2.Resource, _ *pagination.Token) ([]*v2.Entitlement, string, annotations.Annotations, error) {
	return nil, "", nil, nil
}

func (o *iamUserResourceType) Grants(_ context.Context, _ *v2.Resource, _ *pagination.Token) ([]*v2.Grant, string, annotations.Annotations, error) {
	return nil, "", nil, nil
}

func iamUserBuilder(iamClient *iam.Client) *iamUserResourceType {
	return &iamUserResourceType{
		resourceType: resourceTypeIAMUser,
		iamClient:    iamClient,
	}
}

// Create a new connector resource for an aws sso user.
func iamUserResource(ctx context.Context, user iamTypes.User) (*v2.Resource, error) {
	ut, err := iamUserTrait(ctx, user)
	if err != nil {
		return nil, err
	}

	var annos annotations.Annotations
	annos.Append(ut)

	// TODO(lauren) what to do here? do we always need external link url?
	/*if user.ProfileUrl != nil {
		annos.Append(&v2.ExternalLink{
			Url: awsSdk.ToString(user.ProfileUrl),
		})
	}*/

	if user.UserId != nil {
		// TODO(lauren) should this be user id? or arn? or can it be multiple things?
		annos.Append(&v2.V1Identifier{
			Id: awsSdk.ToString(user.UserId),
		})
	}

	return &v2.Resource{
		Id: fmtResourceId(resourceTypeIAMUser.Id, awsSdk.ToString(user.Arn)),
		// Id:          fmtResourceId(resourceTypeUser.Id, awsSdk.ToString(user.UserId)),
		DisplayName: awsSdk.ToString(user.UserName),
		Annotations: annos,
	}, nil
}

// Create and return a User trait for an aws sso user.
func iamUserTrait(ctx context.Context, user iamTypes.User) (*v2.UserTrait, error) {
	ret := &v2.UserTrait{
		Status: &v2.UserTrait_Status{
			Status: v2.UserTrait_Status_STATUS_ENABLED,
		},
	}

	attributes, err := structpb.NewStruct(map[string]interface{}{
		"aws_arn":       awsSdk.ToString(user.Arn),
		"aws_path":      awsSdk.ToString(user.Path),
		"aws_tags":      userTagsToMap(user),
		"aws_user_type": "iam",
	})
	if err != nil {
		return nil, fmt.Errorf("aws-connector: iam.ListUsers struct creation failed:: %w", err)
	}

	email := ""
	username := awsSdk.ToString(user.UserName)
	if strings.Contains(username, "@") {
		email = username
		ret.Emails = []*v2.UserTrait_Email{
			{
				Address:   email,
				IsPrimary: true,
			},
		}
	}

	ret.Profile = attributes
	return ret, nil
}

func userTagsToMap(u iamTypes.User) map[string]interface{} {
	rv := make(map[string]interface{})
	for _, tag := range u.Tags {
		rv[awsSdk.ToString(tag.Key)] = awsSdk.ToString(tag.Value)
	}
	return rv
}
