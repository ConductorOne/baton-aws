package bonbon

import (
	"context"
	"errors"
	"fmt"
	"net/http"

	awsSdk "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/conductorone/baton-aws/pkg/connector/bonbon/client"
	"github.com/conductorone/baton-sdk/pkg/connectorbuilder"
)

type Options struct {
	Region         string
	ApplicationArn string
	BaseURL        string
	HTTPClient     *http.Client
}

func NewBuilders(ctx context.Context, awsConfig awsSdk.Config, opts Options) ([]connectorbuilder.ResourceSyncerV2, error) {
	if err := ValidateRegion(opts.Region); err != nil {
		return nil, err
	}
	cfg := awsConfig.Copy()
	cfg.Region = opts.Region
	c := client.New(cfg, opts.Region, opts.HTTPClient, client.WithBaseURL(opts.BaseURL))

	apps := []string{}
	if opts.ApplicationArn != "" {
		apps = append(apps, opts.ApplicationArn)
	}

	return []connectorbuilder.ResourceSyncerV2{
		newApplicationBuilder(c, opts.ApplicationArn),
		newRoleBuilder(c, apps),
	}, nil
}

func DefaultCapabilityBuilders() []connectorbuilder.ResourceSyncerV2 {
	return []connectorbuilder.ResourceSyncerV2{
		newApplicationBuilder(nil, ""),
		newRoleBuilder(nil, nil),
	}
}

var ErrInvalidRegion = errors.New("bonbon: --global-bonbon-region must be us-east-1 or us-west-2 during private preview")

func ValidateRegion(region string) error {
	switch region {
	case "us-east-1", "us-west-2":
		return nil
	case "":
		return fmt.Errorf("bonbon: --global-bonbon-region is required")
	}
	return ErrInvalidRegion
}
