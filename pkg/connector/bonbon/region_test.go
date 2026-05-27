package bonbon

import "testing"

func TestValidateRegion(t *testing.T) {
	cases := []struct {
		name    string
		region  string
		wantErr bool
	}{
		{name: "us-east-1", region: "us-east-1", wantErr: false},
		{name: "us-west-2", region: "us-west-2", wantErr: false},
		{name: "empty", region: "", wantErr: true},
		{name: "eu-central-1", region: "eu-central-1", wantErr: true},
		{name: "ap-southeast-1", region: "ap-southeast-1", wantErr: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := ValidateRegion(tc.region)
			gotErr := err != nil
			if gotErr != tc.wantErr {
				t.Fatalf("ValidateRegion(%q) err = %v; want error = %v", tc.region, err, tc.wantErr)
			}
		})
	}
}
