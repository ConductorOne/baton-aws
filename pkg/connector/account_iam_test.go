package connector

import (
	"context"
	"testing"

	awsSdk "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	"github.com/aws/aws-sdk-go-v2/service/organizations/types"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	v2 "github.com/conductorone/baton-sdk/pb/c1/connector/v2"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/proto"
)

func TestAccountIAMParseAssumeRole_SecretChildFollowsRegistration(t *testing.T) {
	const childAccountID = "222222222222"
	factory := &AWSClientFactory{
		iamClientMap: map[string]*iam.Client{childAccountID: {}},
	}
	identity := &sts.GetCallerIdentityOutput{Account: awsSdk.String("111111111111")}
	account := types.Account{Id: awsSdk.String(childAccountID)}

	for _, tc := range []struct {
		name        string
		syncSecrets bool
		wantSecret  bool
	}{
		{name: "secrets disabled", syncSecrets: false, wantSecret: false},
		{name: "secrets enabled", syncSecrets: true, wantSecret: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			builder := accountIAMBuilder(nil, factory, nil, tc.syncSecrets)
			children, err := builder.parseAssumeRole(context.Background(), identity, account)
			require.NoError(t, err)

			childIDs := childResourceTypeIDs(children)
			require.Contains(t, childIDs, resourceTypeIAMUser.Id)
			if tc.wantSecret {
				require.Contains(t, childIDs, resourceTypeSecret.Id)
			} else {
				require.NotContains(t, childIDs, resourceTypeSecret.Id)
			}
		})
	}
}

func TestResourceSyncers_SecretRegistrationMatchesAccountIAMDeclaration(t *testing.T) {
	for _, syncSecrets := range []bool{false, true} {
		t.Run(map[bool]string{false: "disabled", true: "enabled"}[syncSecrets], func(t *testing.T) {
			connector := &AWS{
				orgsEnabled:      true,
				syncSecrets:      syncSecrets,
				iamClient:        &iam.Client{},
				awsClientFactory: &AWSClientFactory{},
			}

			var accountBuilder *accountIAMResourceType
			secretRegistered := false
			for _, syncer := range connector.ResourceSyncers(context.Background()) {
				switch syncer.ResourceType(context.Background()).GetId() {
				case resourceTypeAccountIam.Id:
					var ok bool
					accountBuilder, ok = syncer.(*accountIAMResourceType)
					require.True(t, ok)
				case resourceTypeSecret.Id:
					secretRegistered = true
				}
			}

			require.NotNil(t, accountBuilder)
			require.Equal(t, syncSecrets, secretRegistered)
			require.Equal(t, secretRegistered, accountBuilder.syncSecrets)
		})
	}
}

func childResourceTypeIDs(children []proto.Message) []string {
	ids := make([]string, 0, len(children))
	for _, child := range children {
		annotation, ok := child.(*v2.ChildResourceType)
		if ok {
			ids = append(ids, annotation.ResourceTypeId)
		}
	}
	return ids
}
