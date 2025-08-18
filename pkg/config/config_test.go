package config

import (
	"context"
	"fmt"
	"testing"

	"github.com/conductorone/baton-aws/pkg/connector"
	"github.com/conductorone/baton-sdk/pkg/test"
	"github.com/conductorone/baton-sdk/pkg/ustrings"
	"github.com/spf13/viper"
)

const (
	exampleARN        = "arn:aws:iam::123456789012:role/David"
	exampleExternalID = "12345678901234567890123456789012"
	s3ARN             = "arn:aws:s3:::my_corporate_bucket/exampleobject.png"
)

// validateConfig is run after the configuration is loaded, and should return an error if it isn't valid.
func validateConfig(ctx context.Context, v *viper.Viper) error {
	if v.GetBool(UseAssumeField.FieldName) {
		err := ValidateExternalId(v.GetString(ExternalIdField.FieldName))
		if err != nil {
			return err
		}
		err = connector.IsValidRoleARN(v.GetString(RoleArnField.FieldName))
		if err != nil {
			return err
		}
	}
	return nil
}

func TestConfigs(t *testing.T) {
	ctx := context.Background()
	test.ExerciseTestCasesFromExpressions(
		t,
		Config,
		func(viper *viper.Viper) error { return validateConfig(ctx, viper) },
		ustrings.ParseFlags,
		[]test.TestCaseFromExpression{
			{
				"",
				true,
				"empty",
			},
			{
				"--use-assume",
				false,
				"externalID + ARN missing",
			},
			{
				fmt.Sprintf("--use-assume --external-id %s", exampleExternalID),
				false,
				"ARN missing",
			},
			{
				fmt.Sprintf("--use-assume --role-arn %s", exampleARN),
				false,
				"external ID missing",
			},
			{
				fmt.Sprintf("--use-assume --external-id 1 --role-arn %s", exampleARN),
				false,
				"externalID too short",
			},
			{

				fmt.Sprintf(
					"--use-assume --external-id %s --role-arn %s",
					exampleExternalID,
					s3ARN,
				),
				false,
				"ARN is not IAM",
			},
			{
				fmt.Sprintf(
					"--use-assume --external-id %s --role-arn %s",
					exampleExternalID,
					exampleARN,
				),
				true,
				"all",
			},
			{
				"--sync-secrets",
				true,
				"empty",
			},
		},
	)
}
