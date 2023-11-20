package main

import (
	"context"
	"fmt"

	"github.com/conductorone/baton-sdk/pkg/cli"
	"github.com/spf13/cobra"

	"github.com/conductorone/baton-aws/pkg/connector"
)

// config defines the external configuration required for the connector to run.
type config struct {
	cli.BaseConfig `mapstructure:",squash"` // Puts the base config options in the same place as the connector options

	ExternalID string `mapstructure:"external-id"`
	RoleARN    string `mapstructure:"role-arn"`

	GlobalBindingExternalID string `mapstructure:"global-binding-external-id"`
	GlobalRegion            string `mapstructure:"global-region"`
	GlobalRoleARN           string `mapstructure:"global-role-arn"`
	GlobalSecretAccessKey   string `mapstructure:"global-secret-access-key"`
	GlobalAccessKeyID       string `mapstructure:"global-access-key-id"`

	GlobalAwsSsoRegion   string `mapstructure:"global-aws-sso-region"`
	GlobalAwsSsoEnabled  bool   `mapstructure:"global-aws-sso-enabled"`
	GlobalAwsOrgsEnabled bool   `mapstructure:"global-aws-orgs-enabled"`

	UseAssumeRole bool `mapstructure:"use-assume-role"`
}

// validateConfig is run after the configuration is loaded, and should return an error if it isn't valid.
func validateConfig(ctx context.Context, cfg *config) error {
	if cfg.GlobalAwsSsoRegion == "" {
		cfg.GlobalAwsSsoRegion = "us-east-1"
	}

	if cfg.UseAssumeRole {
		if cfg.ExternalID == "" {
			return fmt.Errorf("external id is missing")
		} else if len(cfg.ExternalID) < 32 || len(cfg.ExternalID) > 65 {
			return fmt.Errorf("aws_external_id must be between 32 and 64 bytes")
		}
		err := connector.IsValidRoleARN(cfg.RoleARN)
		if err != nil {
			return err
		}
	}
	return nil
}

// cmdFlags sets the cmdFlags required for the connector.
func cmdFlags(cmd *cobra.Command) {
	cmd.PersistentFlags().String("external-id", "", "The external id for the aws account. ($BATON_EXTERNAL_ID)")
	cmd.PersistentFlags().String("role-arn", "", "The role arn for the aws account. ($BATON_ROLE_ARN)")
	cmd.PersistentFlags().String("global-aws-sso-region", "", "The region for the sso identities. ($BATON_GLOBAL_AWS_SSO_REGION)")
	cmd.PersistentFlags().Bool("global-aws-sso-enabled", false, "Enable support for AWS IAM Identity Center. ($BATON_GLOBAL_AWS_SSO_ENABLED)")
	cmd.PersistentFlags().Bool("global-aws-orgs-enabled", false, "Enable support for AWS Organizations. ($BATON_GLOBAL_AWS_ORGS_ENABLED)")
	cmd.PersistentFlags().String("global-binding-external-id", "", "The global external id for the aws account. ($BATON_GLOBAL_BINDING_EXTERNAL_ID)")
	cmd.PersistentFlags().String("global-region", "", "The region for the aws account. ($BATON_GLOBAL_REGION)")
	cmd.PersistentFlags().String("global-role-arn", "", "The role arn for the aws account. ($BATON_GLOBAL_ROLE_ARN)")
	cmd.PersistentFlags().String("global-secret-access-key", "", "The global-secret-access-key for the aws account. ($BATON_GLOBAL_SECRET_ACCESS_KEY)")
	cmd.PersistentFlags().String("global-access-key-id", "", "The global-access-key-id for the aws account. ($BATON_GLOBAL_ACCESS_KEY_ID)")
	cmd.PersistentFlags().Bool("use-assume-role", false, "Enable support for assume role. ($BATON_GLOBAL_USE_ASSUME_ROLE)")
}
