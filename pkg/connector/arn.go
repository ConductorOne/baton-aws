package connector

import (
	"fmt"
	"path"
	"regexp"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws/arn"
)

var (
	// per AWS docs for rolename: https://docs.aws.amazon.com/IAM/latest/APIReference/API_GetRole.html
	roleNameRE = regexp.MustCompile(`^role/([\W+=,.@-]{1,64})$`)
)

func IsValidRoleARN(input string) error {
	if input == "" {
		return fmt.Errorf("role arn is missing")
	}
	parsedArn, err := arn.Parse(input)
	if err != nil {
		return fmt.Errorf("aws-connector: invalid role ARN: %w", err)
	}
	if parsedArn.Partition != "aws" {
		return fmt.Errorf("aws-connector: invalid role ARN: only aws partition supported")
	}
	if parsedArn.Service != "iam" {
		return fmt.Errorf("aws-connector: invalid role ARN: invalid service: must be 'iam'")
	}
	if parsedArn.Region != "" {
		return fmt.Errorf("aws-connector: invalid role ARN: invalid region: must be empty")
	}
	if len(parsedArn.AccountID) != 12 {
		return fmt.Errorf("aws-connector: invalid role ARN: invalid account id: must be 12 characters long")
	}
	if !strings.HasPrefix(parsedArn.Resource, "role/") {
		return fmt.Errorf("aws-connector: invalid role ARN: invalid resource: must start with 'role/'")
	}
	if roleNameRE.MatchString(parsedArn.Resource) {
		return fmt.Errorf("aws-connector: invalid role ARN: invalid resource: must match regexp '%s'", roleNameRE.String())
	}
	return nil
}

func ResourceWithoutPath(resourceType string, input string) (string, error) {
	parsedArn, err := arn.Parse(input)
	if err != nil {
		return "", fmt.Errorf("invalid %s ARN: '%s': %w", resourceType, input, err)
	}
	if !strings.HasPrefix(parsedArn.Resource, resourceType+"/") {
		return "", fmt.Errorf("invalid %s ARN: missing resource prefix '%s'", resourceType, input)
	}
	_, last := path.Split(parsedArn.Resource)
	return last, nil
}

func AccountIdFromARN(input string) (string, error) {
	parsedArn, err := arn.Parse(input)
	if err != nil {
		return "", fmt.Errorf("invalid ARN: '%s': %w", input, err)
	}
	return parsedArn.AccountID, nil
}

func ssoUserToARN(region string, identityStoreId string, userId string) string {
	id := arn.ARN{
		Partition: "aws",
		Service:   "identitystore",
		Region:    region,
		AccountID: "",
		Resource:  identityStoreId + "/user/" + userId,
	}
	return id.String()
}

func ssoGroupToARN(region string, identityStoreId string, groupId string) string {
	id := arn.ARN{
		Partition: "aws",
		Service:   "identitystore",
		Region:    region,
		AccountID: "",
		Resource:  identityStoreId + "/group/" + groupId,
	}
	return id.String()
}
