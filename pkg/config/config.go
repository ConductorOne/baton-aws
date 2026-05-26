package config

import (
	"github.com/conductorone/baton-sdk/pkg/field"
)

const (
	RegionDefault = "us-east-1"
)

var (
	ExternalIdField = field.RandomField(
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
		field.WithDisplayName("Enable support for AWS Organizations"),
		field.WithDescription("Enable support for AWS Organizations"),
	)
	GlobalAwsSsoEnabledField = field.BoolField(
		"global-aws-sso-enabled",
		field.WithDisplayName("Enable support for AWS IAM Identity Center (successor to AWS Single Sign-On)"),
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
		field.WithDisplayName("Region for AWS IAM Identity Center (successor to AWS Single Sign-On)"),
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
		field.WithIsSecret(true),
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
		field.WithExportTarget(field.ExportTargetOps),
	)
	SyncSecrets = field.BoolField(
		"sync-secrets",
		field.WithDisplayName("Sync Secrets"),
		field.WithDescription("Whether to sync secrets or not"),
	)

	IamAssumeRoleName = field.StringField(
		"iam-assume-role-name",
		field.WithDisplayName("IAM assume role name (child IAM accounts)"),
		field.WithDescription("Role name for the IAM role to assume when using the AWS connector"),
		field.WithDefaultValue("OrganizationAccountAccessRole"),
	)
	SyncSSOUserLastLogin = field.BoolField(
		"sync-sso-user-last-login",
		field.WithDisplayName("Sync SSO User Last Login"),
		field.WithDescription("Enable fetching last login time for SSO users from CloudTrail (requires cloudtrail:LookupEvents permission)"),
		field.WithDefaultValue(false),
	)

	GlobalBonbonEnabledField = field.BoolField(
		"global-bonbon-enabled",
		field.WithDisplayName("Enable AWS Account Access (Bonbon)"),
		field.WithDescription("Enable support for the AWS Account Access (codename Bonbon) connector — private preview"),
		field.WithDefaultValue(false),
	)
	GlobalBonbonRegionField = field.SelectField(
		"global-bonbon-region",
		[]string{"us-east-1", "us-west-2"},
		field.WithDisplayName("Region for AWS Account Access (Bonbon)"),
		field.WithDescription("AWS region for the Account Access service. Private preview is available in us-east-1 (IAD) and us-west-2 (PDX) only"),
		field.WithDefaultValue(RegionDefault),
	)
	GlobalBonbonApplicationArnField = field.StringField(
		"global-bonbon-application-arn",
		field.WithDisplayName("Bonbon Application ARN"),
		field.WithDescription("Optional scope filter: only sync entitlements for this Bonbon Application. Leave empty to sync all applications in the account"),
	)
	GlobalBonbonBaseURLField = field.StringField(
		"global-bonbon-base-url",
		field.WithDescription("Override the Account Access endpoint URL (regression testing only)"),
		field.WithHidden(true),
		field.WithExportTarget(field.ExportTargetCLIOnly),
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
		GlobalBonbonEnabledField,
		GlobalBonbonRegionField,
		GlobalBonbonApplicationArnField,
		GlobalBonbonBaseURLField,
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
