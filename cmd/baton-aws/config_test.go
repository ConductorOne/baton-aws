package main

import (
	"context"
	"fmt"
	"testing"

	"github.com/conductorone/baton-sdk/pkg/test"
	"github.com/conductorone/baton-sdk/pkg/ustrings"
	"github.com/spf13/viper"
)

const (
	exampleARN        = "arn:aws:iam::123456789012:role/David"
	exampleExternalID = "12345678901234567890123456789012"
	s3ARN             = "arn:aws:s3:::my_corporate_bucket/exampleobject.png"
)

func TestConfigs(t *testing.T) {
	ctx := context.Background()
	test.ExerciseTestCasesFromExpressions(
		t,
		Configuration,
		func(viper *viper.Viper) error { return validateConfig(ctx, viper) },
		ustrings.ParseFlags,
		[]test.TestCaseFromExpression{
			{
				"",
				true,
				"empty",
			},
			{
				"--use-assume",
				false,
				"externalID + ARN missing",
			},
			{
				fmt.Sprintf("--use-assume --external-id %s", exampleExternalID),
				false,
				"ARN missing",
			},
			{
				fmt.Sprintf("--use-assume --role-arn %s", exampleARN),
				false,
				"external ID missing",
			},
			{
				fmt.Sprintf("--use-assume --external-id 1 --role-arn %s", exampleARN),
				false,
				"externalID too short",
			},
			{

				fmt.Sprintf(
					"--use-assume --external-id %s --role-arn %s",
					exampleExternalID,
					s3ARN,
				),
				false,
				"ARN is not IAM",
			},
			{
				fmt.Sprintf(
					"--use-assume --external-id %s --role-arn %s",
					exampleExternalID,
					exampleARN,
				),
				true,
				"all",
			},
		},
	)
}
