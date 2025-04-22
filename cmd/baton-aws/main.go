package main

import (
	"context"
	"fmt"
	"os"

	"github.com/conductorone/baton-sdk/pkg/config"
	"github.com/conductorone/baton-sdk/pkg/connectorbuilder"
	"github.com/conductorone/baton-sdk/pkg/field"
	"github.com/conductorone/baton-sdk/pkg/types"
	"github.com/grpc-ecosystem/go-grpc-middleware/logging/zap/ctxzap"
	"github.com/spf13/viper"
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
		Configuration,
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

func getConnector(ctx context.Context, v *viper.Viper) (types.ConnectorServer, error) {
	l := ctxzap.Extract(ctx)

	err := field.Validate(Configuration, v)
	if err != nil {
		return nil, err
	}
	err = validateConfig(ctx, v)
	if err != nil {
		return nil, err
	}

	config := connector.Config{
		GlobalBindingExternalID: v.GetString(GlobalBindingExternalIdField.FieldName),
		GlobalRegion:            v.GetString(GlobalRegionField.FieldName),
		GlobalRoleARN:           v.GetString(GlobalRoleArnField.FieldName),
		GlobalSecretAccessKey:   v.GetString(GlobalSecretAccessKeyField.FieldName),
		GlobalAccessKeyID:       v.GetString(GlobalAccessKeyIdField.FieldName),
		GlobalAwsSsoRegion:      v.GetString(GlobalAwsSsoRegionField.FieldName),
		GlobalAwsOrgsEnabled:    v.GetBool(GlobalAwsOrgsEnabledField.FieldName),
		GlobalAwsSsoEnabled:     v.GetBool(GlobalAwsSsoEnabledField.FieldName),
		ExternalID:              v.GetString(ExternalIdField.FieldName),
		RoleARN:                 v.GetString(RoleArnField.FieldName),
		SCIMEndpoint:            v.GetString(ScimEndpointField.FieldName),
		SCIMToken:               v.GetString(ScimTokenField.FieldName),
		SCIMEnabled:             v.GetBool(ScimEnabledField.FieldName),
		UseAssumeRole:           v.GetBool(UseAssumeField.FieldName),
		SyncSecrets:             v.GetBool(SyncSecrets.FieldName),
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
