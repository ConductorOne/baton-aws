package connector

import (
	"context"

	awsSdk "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/conductorone/baton-aws/pkg/connector/bonbon"
	"github.com/conductorone/baton-sdk/pkg/connectorbuilder"
	"github.com/grpc-ecosystem/go-grpc-middleware/logging/zap/ctxzap"
	"go.uber.org/zap"
)

// BonbonConfig is the subset of Aws config that drives the Bonbon resource
// syncers. Pulled out so the wiring stays independent of the baton-aws-wide
// Config struct (eases the eventual move to a standalone baton-bonbon repo).
type BonbonConfig struct {
	Enabled        bool
	Region         string
	ApplicationArn string
	BaseURL        string
}

// bonbonResourceSyncers returns the Bonbon resource syncers wired against the
// supplied AWS config. Returns nil when disabled — callers append in place.
func (c *AWS) bonbonResourceSyncers(ctx context.Context, bc BonbonConfig) []connectorbuilder.ResourceSyncerV2 {
	l := ctxzap.Extract(ctx)
	if !bc.Enabled {
		return nil
	}

	awsCfg, err := c.getCallingConfig(ctx, c.globalRegion)
	if err != nil {
		l.Error("baton-aws: bonbon disabled — failed to load AWS calling config", zap.Error(err))
		return nil
	}

	bonbonAwsCfg := awsCfg.Copy()
	bonbonAwsCfg.Region = bc.Region

	identityStoreId := ""
	if c.identityInstance != nil {
		identityStoreId = awsSdk.ToString(c.identityInstance.IdentityStoreId)
	}

	syncers, err := bonbon.ResourceSyncers(bonbonAwsCfg, bonbon.Config{
		Region:          bc.Region,
		ApplicationArn:  bc.ApplicationArn,
		BaseURL:         bc.BaseURL,
		SSORegion:       c.ssoRegion,
		IdentityStoreId: identityStoreId,
	})
	if err != nil {
		l.Error("baton-aws: bonbon disabled — region validation failed", zap.Error(err))
		return nil
	}
	return syncers
}
