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
	GlobalAwsCrossAccountIamEnabledField = field.BoolField(
		"global-aws-cross-account-iam-enabled",
		field.WithDisplayName("Also sync cross-account IAM when Identity Center is enabled"),
		field.WithDescription(
			"When both Organizations and Identity Center are enabled, also sync IAM "+
				"users, roles, and groups from every child account. Requires "+
				"sts:AssumeRole on OrganizationAccountAccessRole in each child account. "+
				"Has no effect when Identity Center is disabled (cross-account IAM "+
				"sync always runs in that mode).",
		),
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
			// aws-cn partition. Requires a self-hosted connector with China-partition
			// credentials or IRSA: sts:AssumeRole cannot cross partitions, so the
			// C1-hosted binding-account path cannot reach an aws-cn account.
			"cn-north-1",
			"cn-northwest-1",
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
	SyncAccessAnalyzerInsights = field.BoolField(
		"sync-access-analyzer-insights",
		field.WithDisplayName("Sync IAM Access Analyzer Insights"),
		field.WithDescription(
			"Sync active IAM Access Analyzer unused-access and external-access findings as security insights on "+
				"permission set assignments, IAM users, and IAM roles. Read-only; requires access-analyzer:ListAnalyzers, "+
				"access-analyzer:ListFindings, and access-analyzer:GetFinding. Disabled by default.",
		),
		field.WithDefaultValue(false),
	)
	AccessAnalyzerAccountID = field.StringField(
		"access-analyzer-account-id",
		field.WithDisplayName("IAM Access Analyzer Account ID"),
		field.WithDescription(
			"Account that owns the analyzers, such as the organization's Access Analyzer delegated administrator. "+
				"Leave empty to use the connector's account. A different account is reached by assuming the IAM assume role name in it.",
		),
	)
	AccessAnalyzerRegion = field.StringField(
		"access-analyzer-region",
		field.WithDisplayName("IAM Access Analyzer Region"),
		field.WithDescription("Region of the analyzers. Leave empty to use the Identity Center region when Identity Center is enabled, otherwise the connector's region or us-east-1."),
	)
	SyncIAMUserConsoleAccess = field.BoolField(
		"sync-iam-user-console-access",
		field.WithDisplayName("Sync IAM User Console Access"),
		field.WithDescription("Enable fetching IAM user console login profiles via iam:GetLoginProfile (one API call per user). Disabled by default."),
		field.WithDefaultValue(false),
	)
	SyncOnlyAttachedPolicies = field.BoolField(
		"sync-only-attached-policies",
		field.WithDisplayName("Sync Only Attached Policies"),
		field.WithDescription("Only sync IAM managed policies that are attached to at least one user, role, or group"),
		field.WithDefaultValue(false),
	)
	SyncResourceTags = field.BoolField(
		"sync-resource-tags",
		field.WithDisplayName("Sync Resource Tags"),
		field.WithDescription(
			"Sync AWS resource tags onto accounts, IAM users, and IAM roles as the aws_tags profile field. "+
				"Tags are not returned by the List APIs, so this costs at least one extra API call per resource.",
		),
		field.WithDefaultValue(false),
	)
	GlobalAwsAccountProvisioningTargetField = field.SelectField(
		"create-account-resource-type",
		[]string{"iam_user", "sso_user"},
		field.WithDisplayName("Account Provisioning Target"),
		field.WithDescription(
			"Which AWS user type C1 should create when provisioning accounts. "+
				"'iam_user' (default) creates IAM users; 'sso_user' creates AWS Identity Center (SSO) users "+
				"and requires the 'Enable support for AWS IAM Identity Center' setting. "+
				"Each connector instance creates one type of account. "+
				"Changing it requires updating the account provisioning mappings: Identity Center users also need given_name and family_name.",
		),
		field.WithDefaultValue("iam_user"),
	).ExportAs(field.ExportTargetGUI)
)

//go:generate go run ./gen
var Config = field.NewConfiguration(
	[]field.SchemaField{
		ExternalIdField,
		GlobalAccessKeyIdField,
		GlobalAwsOrgsEnabledField,
		GlobalAwsSsoEnabledField,
		GlobalAwsCrossAccountIamEnabledField,
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
		SyncAccessAnalyzerInsights,
		AccessAnalyzerAccountID,
		AccessAnalyzerRegion,
		SyncIAMUserConsoleAccess,
		SyncOnlyAttachedPolicies,
		SyncResourceTags,
		GlobalAwsAccountProvisioningTargetField,
	},
	field.WithConstraints(
		field.FieldsDependentOn(
			[]field.SchemaField{
				UseAssumeField,
			},
			[]field.SchemaField{
				RoleArnField,
			},
		),
		field.FieldsDependentOn(
			[]field.SchemaField{
				AccessAnalyzerAccountID,
				AccessAnalyzerRegion,
			},
			[]field.SchemaField{
				SyncAccessAnalyzerInsights,
			},
		),
		field.FieldsDependentOn(
			[]field.SchemaField{
				GlobalAwsCrossAccountIamEnabledField,
			},
			[]field.SchemaField{
				GlobalAwsOrgsEnabledField,
				GlobalAwsSsoEnabledField,
			},
		)),
	field.WithConnectorDisplayName("AWS"),
	field.WithHelpUrl("/docs/baton/aws-v2"),
	field.WithIconUrl("/static/app-icons/aws.svg"),
)
