package config_test

import (
	"fmt"
	"testing"

	"github.com/conductorone/baton-aws/pkg/config"
	"github.com/conductorone/baton-aws/pkg/connector"
	"github.com/conductorone/baton-sdk/pkg/test"
	"github.com/conductorone/baton-sdk/pkg/ustrings"
	"github.com/spf13/viper"
)

const (
	exampleARN        = "arn:aws:iam::123456789012:role/David"
	exampleExternalID = "12345678901234567890123456789012"
	s3ARN             = "arn:aws:s3:::my_corporate_bucket/exampleobject.png"
	chinaARN          = "arn:aws-cn:iam::123456789012:role/David"
	govCloudARN       = "arn:aws-us-gov:iam::123456789012:role/David"
)

// validateConfig is run after the configuration is loaded, and should return an error if it
// isn't valid. It decodes into the generated config struct and calls the production
// connector.ValidateConfig rather than reimplementing it, so these cases cover whatever
// that function actually enforces.
func validateConfig(v *viper.Viper) error {
	var awsc config.Aws
	if err := v.Unmarshal(&awsc); err != nil {
		return err
	}
	return connector.ValidateConfig(&awsc)
}

func TestConfigs(t *testing.T) {
	test.ExerciseTestCasesFromExpressions(
		t,
		config.Config,
		validateConfig,
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
				"ARN missing",
			},
			{
				fmt.Sprintf("--use-assume --external-id %s", exampleExternalID),
				false,
				"ARN missing",
			},
			{
				fmt.Sprintf("--use-assume --role-arn %s", exampleARN),
				true,
				"single-hop assume: external-id not required",
			},
			{
				fmt.Sprintf("--use-assume --external-id 1 --role-arn %s", exampleARN),
				true,
				"single-hop assume: short external-id ignored",
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
				"single-hop assume: all valid",
			},
			{
				fmt.Sprintf(
					"--use-assume --role-arn %s --global-role-arn %s",
					exampleARN,
					exampleARN,
				),
				false,
				"two-hop assume: external-id missing",
			},
			{
				fmt.Sprintf(
					"--use-assume --external-id 1 --role-arn %s --global-role-arn %s",
					exampleARN,
					exampleARN,
				),
				false,
				"two-hop assume: external-id too short",
			},
			{
				fmt.Sprintf(
					"--use-assume --external-id %s --role-arn %s --global-role-arn %s",
					exampleExternalID,
					exampleARN,
					exampleARN,
				),
				true,
				"two-hop assume: all valid",
			},
			{
				"--sync-secrets",
				true,
				"empty",
			},
			// aws-cn partition. global-aws-sso-region is a SelectField, so the
			// China regions have to be in its allowed set or field.Validate rejects them
			// before the connector's own validation ever runs.
			{
				fmt.Sprintf(
					"--use-assume --role-arn %s --global-region cn-north-1",
					chinaARN,
				),
				true,
				"china: single-hop assume with china region",
			},
			{
				fmt.Sprintf(
					"--use-assume --role-arn %s --global-region cn-northwest-1"+
						" --global-aws-orgs-enabled --global-aws-sso-enabled --global-aws-sso-region cn-north-1",
					chinaARN,
				),
				true,
				"china: identity center in china region",
			},
			{
				"--global-aws-sso-region cn-northwest-1",
				true,
				"china: cn-northwest-1 is an allowed identity center region",
			},
			{
				"--global-aws-sso-region cn-nowhere-1",
				false,
				"china: unknown region is still rejected",
			},
			{
				fmt.Sprintf("--use-assume --role-arn %s", govCloudARN),
				false,
				"govcloud partition is not supported",
			},
			{
				fmt.Sprintf(
					"--use-assume --role-arn %s --global-region us-east-1",
					chinaARN,
				),
				false,
				"china: role arn and global region in different partitions",
			},
			{
				fmt.Sprintf(
					"--use-assume --role-arn %s --global-region cn-north-1"+
						" --global-aws-orgs-enabled --global-aws-sso-enabled --global-aws-sso-region us-east-1",
					chinaARN,
				),
				false,
				"china: identity center region in the wrong partition",
			},
			{
				fmt.Sprintf(
					"--use-assume --external-id %s --role-arn %s --global-role-arn %s --global-region cn-north-1",
					exampleExternalID,
					chinaARN,
					exampleARN,
				),
				false,
				"china: two-hop cannot cross partitions",
			},
		},
	)
}
