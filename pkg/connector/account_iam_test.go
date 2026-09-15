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
)

func TestAccountIAMSecretChildFollowsRegistration(t *testing.T) {
	const childAccountID = "222222222222"
	factory := &AWSClientFactory{
		iamClientMap: map[string]*iam.Client{childAccountID: {}},
	}
	identity := &sts.GetCallerIdentityOutput{Account: awsSdk.String("111111111111")}
	account := types.Account{Id: awsSdk.String(childAccountID)}

	for _, tc := range []struct {
		name        string
		syncSecrets bool
	}{
		{name: "secrets disabled", syncSecrets: false},
		{name: "secrets enabled", syncSecrets: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			connector := &AWS{
				orgsEnabled:      true,
				syncSecrets:      tc.syncSecrets,
				iamClient:        &iam.Client{},
				awsClientFactory: factory,
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
			require.Equal(t, tc.syncSecrets, secretRegistered)

			children, err := accountBuilder.parseAssumeRole(context.Background(), identity, account)
			require.NoError(t, err)

			iamUserDeclared, secretDeclared := false, false
			for _, child := range children {
				if childResource, ok := child.(*v2.ChildResourceType); ok {
					iamUserDeclared = iamUserDeclared || childResource.GetResourceTypeId() == resourceTypeIAMUser.Id
					secretDeclared = secretDeclared || childResource.GetResourceTypeId() == resourceTypeSecret.Id
				}
			}
			require.True(t, iamUserDeclared)
			require.Equal(t, secretRegistered, secretDeclared)
		})
	}
}
