package bonbon

import (
	"context"
	"fmt"

	awsSdk "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/conductorone/baton-sdk/pkg/connectorbuilder"
)

// Config carries the per-sync inputs the Bonbon resource syncers need. SSORegion
// and IdentityStoreId are required to synthesize the cross-resource-type
// principal IDs that match what baton-aws's sso_user/sso_group syncers emit;
// without them, role grants would dangle.
type Config struct {
	Region          string
	ApplicationArn  string
	BaseURL         string
	SSORegion       string
	IdentityStoreId string
}

// SupportedRegions enumerates the regions Bonbon is currently exposed in
// during private preview. Operators picking anything outside this set get an
// explicit error at connector init rather than a 404 mid-sync.
var SupportedRegions = map[string]struct{}{
	"us-east-1": {},
	"us-west-2": {},
}

func ValidateRegion(region string) error {
	if region == "" {
		return fmt.Errorf("bonbon: region is required")
	}
	if _, ok := SupportedRegions[region]; !ok {
		return fmt.Errorf("bonbon: %q is not a supported region (private preview: us-east-1, us-west-2)", region)
	}
	return nil
}

// ResourceSyncers returns the two builders ready to slot into the parent
// baton-aws Connector's ResourceSyncers slice. Returns nil if cfg.Region is
// empty so the caller can short-circuit when the bonbon-enabled flag is off.
func ResourceSyncers(awsCfg awsSdk.Config, cfg Config, opts ...ClientOption) ([]connectorbuilder.ResourceSyncerV2, error) {
	if err := ValidateRegion(cfg.Region); err != nil {
		return nil, err
	}
	if cfg.BaseURL != "" {
		opts = append([]ClientOption{WithEndpoint(cfg.BaseURL)}, opts...)
	}
	client := NewClient(awsCfg, cfg.Region, opts...)

	return []connectorbuilder.ResourceSyncerV2{
		ApplicationBuilder(client, cfg.ApplicationArn),
		RoleBuilder(client, cfg.SSORegion, cfg.IdentityStoreId),
	}, nil
}

// DefaultCapabilities returns the resource syncers wired against an empty
// client. Used by the DefaultCapabilitiesBuilder path so the generated
// capabilities manifest always lists the Bonbon resource types — even when
// the connector boots with --global-bonbon-enabled=false.
func DefaultCapabilities() []connectorbuilder.ResourceSyncerV2 {
	return []connectorbuilder.ResourceSyncerV2{
		ApplicationBuilder(nil, ""),
		RoleBuilder(nil, "", ""),
	}
}

// Ctx is exported only to silence unused-import lint when the package is
// vendored without callers invoking the syncer methods directly.
var _ = context.Background
