package main

import (
	"context"
	"fmt"

	"github.com/conductorone/baton-sdk/pkg/cli"
	"github.com/spf13/cobra"
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
}

// validateConfig is run after the configuration is loaded, and should return an error if it isn't valid.
func validateConfig(ctx context.Context, cfg *config) error {
	if cfg.ExternalID == "" {
		return fmt.Errorf("external id is missing")
	}

	if cfg.RoleARN == "" {
		return fmt.Errorf("role arn is missing")
	}

	if cfg.GlobalAwsSsoEnabled && cfg.GlobalAwsOrgsEnabled && cfg.GlobalAwsSsoRegion == "" {
		return fmt.Errorf("region is missing")
	}

	return nil
}

// cmdFlags sets the cmdFlags required for the connector.
func cmdFlags(cmd *cobra.Command) {
	cmd.PersistentFlags().String("external-id", "", "The external id for the aws account")
	cmd.PersistentFlags().String("role-arn", "", "The role arn for the aws account")
	cmd.PersistentFlags().String("global-aws-sso-region", "", "The region for the sso identities")
	cmd.PersistentFlags().Bool("global-aws-sso-enabled", false, "Enable support for AWS IAM Identity Center")
	cmd.PersistentFlags().Bool("global-aws-orgs-enabled", false, "Enable support for AWS Organizations")
	cmd.PersistentFlags().String("global-binding-external-id", "", "The global external id for the aws account")
	cmd.PersistentFlags().String("global-region", "", "The region for the aws account")
	cmd.PersistentFlags().String("global-role-arn", "", "The role arn for the aws account")
	cmd.PersistentFlags().String("global-secret-access-key", "", "The global-secret-access-key for the aws account")
	cmd.PersistentFlags().String("global-access-key-id", "", "The global-access-key-id for the aws account")
}
