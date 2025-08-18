package main

import (
	"context"
	"fmt"
	"os"

	cfg "github.com/conductorone/baton-aws/pkg/config"
	"github.com/conductorone/baton-sdk/pkg/config"
	"github.com/conductorone/baton-sdk/pkg/connectorbuilder"
	"github.com/conductorone/baton-sdk/pkg/field"
	"github.com/conductorone/baton-sdk/pkg/types"
	"github.com/grpc-ecosystem/go-grpc-middleware/logging/zap/ctxzap"
	"go.uber.org/zap"

	"github.com/conductorone/baton-aws/pkg/connector"
)

var version = "dev"

func main() {
	ctx := context.Background()

	_, cmd, err := config.DefineConfiguration(
		ctx,
		"baton-aws",
		getConnector,
		cfg.Config,
	)
	if err != nil {
		fmt.Fprintln(os.Stderr, err.Error())
		os.Exit(1)
	}

	cmd.Version = version

	err = cmd.Execute()
	if err != nil {
		fmt.Fprintln(os.Stderr, err.Error())
		os.Exit(1)
	}
}

func getConnector(ctx context.Context, awsc *cfg.Aws) (types.ConnectorServer, error) {
	l := ctxzap.Extract(ctx)

	err := field.Validate(cfg.Config, awsc)
	if err != nil {
		return nil, err
	}
	err = cfg.ValidateConfig(ctx, awsc)
	if err != nil {
		return nil, err
	}

	config := connector.Config{
		GlobalBindingExternalID: awsc.GetString(cfg.GlobalBindingExternalIdField.FieldName),
		GlobalRegion:            awsc.GetString(cfg.GlobalRegionField.FieldName),
		GlobalRoleARN:           awsc.GetString(cfg.GlobalRoleArnField.FieldName),
		GlobalSecretAccessKey:   awsc.GetString(cfg.GlobalSecretAccessKeyField.FieldName),
		GlobalAccessKeyID:       awsc.GetString(cfg.GlobalAccessKeyIdField.FieldName),
		GlobalAwsSsoRegion:      awsc.GetString(cfg.GlobalAwsSsoRegionField.FieldName),
		GlobalAwsOrgsEnabled:    awsc.GetBool(cfg.GlobalAwsOrgsEnabledField.FieldName),
		GlobalAwsSsoEnabled:     awsc.GetBool(cfg.GlobalAwsSsoEnabledField.FieldName),
		ExternalID:              awsc.GetString(cfg.ExternalIdField.FieldName),
		RoleARN:                 awsc.GetString(cfg.RoleArnField.FieldName),
		SCIMEndpoint:            awsc.GetString(cfg.ScimEndpointField.FieldName),
		SCIMToken:               awsc.GetString(cfg.ScimTokenField.FieldName),
		SCIMEnabled:             awsc.GetBool(cfg.ScimEnabledField.FieldName),
		UseAssumeRole:           awsc.GetBool(cfg.UseAssumeField.FieldName),
		SyncSecrets:             awsc.GetBool(cfg.SyncSecrets.FieldName),
		IamAssumeRoleName:       awsc.GetString(cfg.IamAssumeRoleName.FieldName),
	}

	cb, err := connector.New(ctx, config)
	if err != nil {
		l.Error("error creating connector", zap.Error(err))
		return nil, err
	}

	connector, err := connectorbuilder.NewConnector(ctx, cb)
	if err != nil {
		l.Error("error creating connector", zap.Error(err))
		return nil, err
	}

	return connector, nil
}
