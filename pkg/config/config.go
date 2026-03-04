package config

import (
	"github.com/conductorone/baton-sdk/pkg/field"
)

const (
	RegionDefault = "us-east-1"
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
		field.WithExportTarget(field.ExportTargetOps),
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
	GlobalAwsSsoRegionField = field.SelectField(
		"global-aws-sso-region",
		[]string{
			"us-east-2",
			"us-east-1",
			"us-west-1",
			"us-west-2",
			"af-south-1",
			"ap-east-1",
			"ap-southeast-3",
			"ap-south-1",
			"ap-northeast-3",
			"ap-northeast-2",
			"ap-southeast-1",
			"ap-southeast-2",
			"ap-northeast-1",
			"ca-central-1",
			"eu-central-1",
			"eu-west-1",
			"eu-west-2",
			"eu-south-1",
			"eu-west-3",
			"eu-north-1",
			"me-south-1",
			"me-central-1",
			"sa-east-1",
		},
		field.WithDisplayName("Global AWS SSO Region"),
		field.WithDescription("The region for the sso identities"),
		field.WithDefaultValue(RegionDefault),
	)
	GlobalBindingExternalIdField = field.StringField(
		"global-binding-external-id",
		field.WithDisplayName("Global Binding External ID"),
		field.WithDescription("The global external id for the aws account"),
		field.WithExportTarget(field.ExportTargetOps),
	)
	GlobalRegionField = field.StringField(
		"global-region",
		field.WithDisplayName("Global Region"),
		field.WithDescription("The region for the aws account"),
		field.WithExportTarget(field.ExportTargetOps),
	)
	GlobalRoleArnField = field.StringField(
		"global-role-arn",
		field.WithDisplayName("Global Role ARN"),
		field.WithDescription("The role arn for the aws account"),
		field.WithExportTarget(field.ExportTargetOps),
	)
	GlobalSecretAccessKeyField = field.StringField(
		"global-secret-access-key",
		field.WithDisplayName("Global Secret Access Key"),
		field.WithDescription("The global-secret-access-key for the aws account"),
		field.WithExportTarget(field.ExportTargetOps),
	)
	RoleArnField = field.StringField(
		"role-arn",
		field.WithDisplayName("Role ARN"),
		field.WithDescription("The role arn for the aws account"),
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
	SyncSSOUserLastLogin = field.BoolField(
		"sync-sso-user-last-login",
		field.WithDisplayName("Sync SSO User Last Login"),
		field.WithDescription("Enable fetching last login time for SSO users from CloudTrail (requires cloudtrail:LookupEvents permission)"),
		field.WithDefaultValue(false),
	)
)

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
		UseAssumeField,
		SyncSecrets,
		IamAssumeRoleName,
		SyncSSOUserLastLogin,
	},
	field.WithConstraints(
		field.FieldsDependentOn(
			[]field.SchemaField{
				UseAssumeField,
			},
			[]field.SchemaField{
				RoleArnField,
			},
		)),
	field.WithConnectorDisplayName("AWS"),
	field.WithHelpUrl("/docs/baton/aws-v2"),
	field.WithIconUrl("/static/app-icons/aws.svg"),
)
