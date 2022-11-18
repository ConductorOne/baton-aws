package connector

import (
	"context"
	"reflect"
	"testing"

	v2 "github.com/conductorone/baton-sdk/pb/c1/connector/v2"
)

/*func Test_connectorImpl_GetAsset(t *testing.T) {
	type args struct {
		req    *v2.AssetServiceGetAssetRequest
		server v2.AssetService_GetAssetServer
	}
	tests := []struct {
		name    string
		args    args
		wantErr bool
	}{
		// TODO: Add test cases.
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := &AWS{}
			if err := c.Asset(tt.args.req, tt.args.server); (err != nil) != tt.wantErr {
				t.Errorf("GetAsset() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}*/

func Test_connectorImpl_GetMetadata(t *testing.T) {
	type args struct {
		ctx context.Context
		req *v2.ConnectorServiceGetMetadataRequest
	}
	tests := []struct {
		name    string
		args    args
		want    *v2.ConnectorServiceGetMetadataResponse
		wantErr bool
	}{
		// TODO: Add test cases.
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := &AWS{}
			got, err := c.Metadata(tt.args.ctx)
			if (err != nil) != tt.wantErr {
				t.Errorf("GetMetadata() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("GetMetadata() got = %v, want %v", got, tt.want)
			}
		})
	}
}

/*
func Test_connectorImpl_ListEntitlements(t *testing.T) {
	type args struct {
		ctx context.Context
		req *v2.EntitlementsServiceListEntitlementsRequest
	}
	tests := []struct {
		name    string
		args    args
		want    *v2.EntitlementsServiceListEntitlementsResponse
		wantErr bool
	}{
		// TODO: Add test cases.
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := &connectorImpl{}
			got, err := c.ListEntitlements(tt.args.ctx, tt.args.req)
			if (err != nil) != tt.wantErr {
				t.Errorf("ListEntitlements() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("ListEntitlements() got = %v, want %v", got, tt.want)
			}
		})
	}
}

func Test_connectorImpl_ListGrants(t *testing.T) {
	type args struct {
		ctx context.Context
		req *v2.GrantsServiceListGrantsRequest
	}
	tests := []struct {
		name    string
		args    args
		want    *v2.GrantsServiceListGrantsResponse
		wantErr bool
	}{
		// TODO: Add test cases.
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := &connectorImpl{}
			got, err := c.ListGrants(tt.args.ctx, tt.args.req)
			if (err != nil) != tt.wantErr {
				t.Errorf("ListGrants() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("ListGrants() got = %v, want %v", got, tt.want)
			}
		})
	}
}*/

func Test_connectorImpl_ListResourceTypes(t *testing.T) {
	type args struct {
		ctx context.Context
		req *v2.ResourceTypesServiceListResourceTypesRequest
	}
	tests := []struct {
		name    string
		args    args
		want    *v2.ResourceTypesServiceListResourceTypesResponse
		wantErr bool
	}{
		// TODO: Add test cases.
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// c := &connectorImpl{}
			c := &AWS{}
			got, err := c.ListResourceTypes(tt.args.ctx, tt.args.req)
			if (err != nil) != tt.wantErr {
				t.Errorf("ListResourceTypes() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("ListResourceTypes() got = %v, want %v", got, tt.want)
			}
		})
	}
}

/*func Test_connectorImpl_ListResources(t *testing.T) {
	type args struct {
		ctx context.Context
		req *v2.ResourcesServiceListResourcesRequest
	}
	tests := []struct {
		name    string
		args    args
		want    *v2.ResourcesServiceListResourcesResponse
		wantErr bool
	}{
		// TODO: Add test cases.
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			//c := &connectorImpl{}
			c := &AWS{}
			got, err := c.ListResources(tt.args.ctx, tt.args.req)
			if (err != nil) != tt.wantErr {
				t.Errorf("ListResources() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("ListResources() got = %v, want %v", got, tt.want)
			}
		})
	}
}*/

func Test_connectorImpl_Validate(t *testing.T) {
	type args struct {
		ctx context.Context
		req *v2.ConnectorServiceValidateRequest
	}
	tests := []struct {
		name    string
		args    args
		want    *v2.ConnectorServiceValidateResponse
		wantErr bool
	}{
		// TODO: Add test cases.
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := &AWS{}
			got, err := c.Validate(tt.args.ctx)
			// got, err := c.Validate(tt.args.ctx, tt.args.req)
			if (err != nil) != tt.wantErr {
				t.Errorf("Validate() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("Validate() got = %v, want %v", got, tt.want)
			}
		})
	}
}
