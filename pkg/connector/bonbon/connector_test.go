package bonbon

import (
	"context"
	"testing"

	awsSdk "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/conductorone/baton-aws/pkg/connector/bonbon/client"
	bonbontestserver "github.com/conductorone/baton-aws/test/bonbon-testserver"
)

func TestValidateRegion(t *testing.T) {
	for _, region := range []string{"us-east-1", "us-west-2"} {
		if err := ValidateRegion(region); err != nil {
			t.Errorf("ValidateRegion(%q) returned unexpected error: %v", region, err)
		}
	}
	if err := ValidateRegion("eu-west-1"); err == nil {
		t.Error("ValidateRegion(eu-west-1) returned nil; want preview-region error")
	}
	if err := ValidateRegion(""); err == nil {
		t.Error("ValidateRegion(\"\") returned nil; want required-field error")
	}
}

// TestBonbonFullSync exercises List/Entitlements/Grants against the testserver.
// Marked t.Skip until the testserver loopback authentication is finalized — the
// scaffold ships the SigV4 client and the testserver but the round-trip will
// be wired up in the follow-up PR that lands the actual sync wiring.
func TestBonbonFullSync(t *testing.T) {
	t.Skip("scaffold: wired up in follow-up PR — see pkg/connector/bonbon/connector_test.go TODO")

	ctx := context.Background()
	srv, err := bonbontestserver.New()
	if err != nil {
		t.Fatalf("testserver: %v", err)
	}
	defer srv.Close()

	appArn := "arn:aws:account-access:us-east-1:111122223333:application/app-test"
	roleArn := "arn:aws:iam::111122223333:role/Admin"
	srv.SeedApplication(appArn, "tenant-test", "arn:aws:sso:::instance/ssoins-0000000000000000")
	srv.SeedEntitlement(appArn, client.Principal{IdentityCenter: &client.IdentityCenterPrincipal{UserID: "user-1"}}, roleArn, "111122223333")
	srv.SeedEntitlement(appArn, client.Principal{IdentityCenter: &client.IdentityCenterPrincipal{GroupID: "group-1"}}, roleArn, "111122223333")

	awsCfg := awsSdk.Config{
		Region:      "us-east-1",
		Credentials: credentials.NewStaticCredentialsProvider("AKIA000000000000", "secret", ""),
	}
	builders, err := NewBuilders(ctx, awsCfg, Options{
		Region:  "us-east-1",
		BaseURL: srv.URL,
	})
	if err != nil {
		t.Fatalf("NewBuilders: %v", err)
	}
	if len(builders) != 2 {
		t.Fatalf("want 2 builders, got %d", len(builders))
	}
	// Full assertion harness lands with the follow-up PR.
}
