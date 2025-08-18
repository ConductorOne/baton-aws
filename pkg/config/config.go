package config

import (
	"context"
	"fmt"

	"github.com/conductorone/baton-aws/pkg/connector"
	"github.com/conductorone/baton-sdk/pkg/field"
)

const (
	ExternalIDLengthMaximum = 65 // TODO(marcos): this might be a bug.
	ExternalIDLengthMinimum = 32
	RegionDefault           = "us-east-1"
)

var (
	ExternalIdField = field.StringField(
		"external-id",
		field.WithDisplayName("External ID"),
		field.WithDescription("The external id for the aws account"),
	)
	GlobalAccessKeyIdField = field.StringField(
		"global-access-key-id",
		field.WithDisplayName("Global Access Key"),
		field.WithDescription("The global-access-key-id for the aws account"),
	)
	GlobalAwsOrgsEnabledField = field.BoolField(
		"global-aws-orgs-enabled",
		field.WithDisplayName("Global AWS Orgs Enabled"),
		field.WithDescription("Enable support for AWS Organizations"),
	)
	GlobalAwsSsoEnabledField = field.BoolField(
		"global-aws-sso-enabled",
		field.WithDisplayName("Global AWS SSO Enabled"),
		field.WithDescription("Enable support for AWS IAM Identity Center"),
	)
	GlobalAwsSsoRegionField = field.StringField(
		"global-aws-sso-region",
		field.WithDisplayName("Global AWS SSO Region"),
		field.WithDescription("The region for the sso identities"),
		field.WithDefaultValue(RegionDefault),
	)
	GlobalBindingExternalIdField = field.StringField(
		"global-binding-external-id",
		field.WithDisplayName("Global Binding External ID"),
		field.WithDescription("The global external id for the aws account"),
	)
	GlobalRegionField = field.StringField(
		"global-region",
		field.WithDisplayName("Global Region"),
		field.WithDescription("The region for the aws account"),
	)
	GlobalRoleArnField = field.StringField(
		"global-role-arn",
		field.WithDisplayName("Global Role ARN"),
		field.WithDescription("The role arn for the aws account"),
	)
	GlobalSecretAccessKeyField = field.StringField(
		"global-secret-access-key",
		field.WithDisplayName("Global Secret Access Key"),
		field.WithDescription("The global-secret-access-key for the aws account"),
	)
	RoleArnField = field.StringField(
		"role-arn",
		field.WithDisplayName("Role ARN"),
		field.WithDescription("The role arn for the aws account"),
	)
	ScimEnabledField = field.BoolField(
		"scim-enabled",
		field.WithDisplayName("SCIM Enabled"),
		field.WithDescription("Enable support for pulling SSO User status from the AWS SCIM API"),
	)
	ScimEndpointField = field.StringField(
		"scim-endpoint",
		field.WithDisplayName("SCIM Endpoint"),
		field.WithDescription("The SCIMv2 endpoint for aws identity center"),
	)
	ScimTokenField = field.StringField(
		"scim-token",
		field.WithDisplayName("SCIM Token"),
		field.WithDescription("The SCIMv2 token for aws identity center"),
	)
	UseAssumeField = field.BoolField(
		"use-assume",
		field.WithDisplayName("Use Assume"),
		field.WithDescription("Enable support for assume role"),
	)
	SyncSecrets = field.BoolField(
		"sync-secrets",
		field.WithDisplayName("Sync Secrets"),
		field.WithDescription("Whether to sync secrets or not"),
	)

	IamAssumeRoleName = field.StringField(
		"iam-assume-role-name",
		field.WithDisplayName("IAM Assume Role Name"),
		field.WithDescription("Role name for the IAM role to assume when using the AWS connector"),
		field.WithDefaultValue("OrganizationAccountAccessRole"),
	)
)

func ValidateExternalId(input string) error {
	fieldLength := len(input)
	if fieldLength <= 0 {
		return fmt.Errorf("external id is missing")
	}

	if fieldLength < ExternalIDLengthMinimum || fieldLength > ExternalIDLengthMaximum {
		return fmt.Errorf("aws_external_id must be between 32 and 64 bytes")
	}
	return nil
}

// validateConfig is run after the configuration is loaded, and should return an error if it isn't valid.
func ValidateConfig(ctx context.Context, awsc *Aws) error {
	if awsc.GetBool(UseAssumeField.FieldName) {
		err := ValidateExternalId(awsc.GetString(ExternalIdField.FieldName))
		if err != nil {
			return err
		}
		err = connector.IsValidRoleARN(awsc.GetString(RoleArnField.FieldName))
		if err != nil {
			return err
		}
	}
	return nil
}

//go:generate go run ./gen
var Config = field.NewConfiguration(
	[]field.SchemaField{
		ExternalIdField,
		GlobalAccessKeyIdField,
		GlobalAwsOrgsEnabledField,
		GlobalAwsSsoEnabledField,
		GlobalAwsSsoRegionField,
		GlobalBindingExternalIdField,
		GlobalRegionField,
		GlobalRoleArnField,
		GlobalSecretAccessKeyField,
		RoleArnField,
		ScimEnabledField,
		ScimEndpointField,
		ScimTokenField,
		UseAssumeField,
		SyncSecrets,
		IamAssumeRoleName,
	},
	field.WithConstraints(
		field.FieldsDependentOn(
			[]field.SchemaField{
				UseAssumeField,
			},
			[]field.SchemaField{
				ExternalIdField,
				RoleArnField,
			},
		)),
	field.WithConnectorDisplayName("AWS"),
	field.WithHelpUrl("/docs/baton/aws-v2"),
	field.WithIconUrl("/static/app-icons/aws.svg"),
)
