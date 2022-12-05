![Baton Logo](./docs/images/baton-logo.png)

# `baton-aws` [![Go Reference](https://pkg.go.dev/badge/github.com/conductorone/baton-aws.svg)](https://pkg.go.dev/github.com/conductorone/baton-aws) ![main ci](https://github.com/conductorone/baton-aws/actions/workflows/main.yaml/badge.svg)

`baton-aws` is a connector for AWS built using the [Baton SDK](https://github.com/conductorone/baton-sdk). It communicates with the AWS API to sync data about which groups and users have access to accounts, groups, and roles within an AWS org.

Check out [Baton](https://github.com/conductorone/baton) to learn more the project in general.

# Getting Started

## brew

```
brew install conductorone/baton/baton conductorone/baton/baton-aws
baton-aws
baton resources
```

## docker

```
docker run --rm -v $(pwd):/out -e BATON_GLOBAL_SECRET_ACCESS_KEY=awsSecretAccessKey -e BATON_GLOBAL_ACCESS_KEY_ID=awsAccessKey ghcr.io/conductorone/baton-aws:latest -f "/out/sync.c1z"
docker run --rm -v $(pwd):/out ghcr.io/conductorone/baton:latest -f "/out/sync.c1z" resources
```

## source

```
go install github.com/conductorone/baton/cmd/baton@main
go install github.com/conductorone/baton-aws/cmd/baton-aws@main

BATON_GLOBAL_SECRET_ACCESS_KEY=awsSecretAccessKey BATON_GLOBAL_ACCESS_KEY_ID=awsAccessKey
baton resources
```

# Data Model

`baton-aws` will pull down information about the following AWS resources:

- Accounts
- Groups
- Users
- Roles

Set the `--global-aws-sso-enabled` and `--global-aws-orgs-enabled` flags to pull information about the following AWS IAM Identity Center resources:
- SSO Groups
- SSO Users

By default, `baton-aws` uses the AWS credentials from your AWS config. You can explicitly define the region, access key, and secret key by setting the following flags: `--global-secret-access-key`, `--global-access-key-id`, `--global-region`.

# Contributing, Support and Issues

We started Baton because we were tired of taking screenshots and manually building spreadsheets. We welcome contributions, and ideas, no matter how small -- our goal is to make identity and permissions sprawl less painful for everyone. If you have questions, problems, or ideas: Please open a Github Issue!

See [CONTRIBUTING.md](https://github.com/ConductorOne/baton/blob/main/CONTRIBUTING.md) for more details.

# `baton-aws` Command Line Usage

```
baton-aws

Usage:
  baton-aws [flags]
  baton-aws [command]

Available Commands:
  completion         Generate the autocompletion script for the specified shell
  help               Help about any command

Flags:
      --external-id string                  The external id for the aws account. ($BATON_EXTERNAL_ID)
  -f, --file string                         The path to the c1z file to sync with ($C1_FILE) (default "sync.c1z")
      --global-secret-access-key string     The global-secret-access-key for the aws account. ($BATON_GLOBAL_SECRET_ACCESS_KEY)
      --global-access-key-id string         The global-access-key-id for the aws account. ($BATON_GLOBAL_ACCESS_KEY_ID)
      --global-region string                The region for the aws account. ($BATON_GLOBAL_REGION)
      --use-assume-role bool                Enable support for assume role. ($BATON_GLOBAL_USE_ASSUME_ROLE)
      --external-id string                  The external id for the aws account. ($BATON_EXTERNAL_ID)
      --role-arn string                     The role arn for the aws account. ($BATON_ROLE_ARN)
      --global-binding-external-id string   The global external id for the aws account. ($BATON_GLOBAL_BINDING_EXTERNAL_ID)
      --global-role-arn string              The role arn for the binding aws account. ($BATON_GLOBAL_ROLE_ARN)
      --global-aws-sso-region string        The region for the sso identities. ($BATON_GLOBAL_AWS_SSO_REGION)
      --global-aws-sso-enabled bool         Enable support for AWS IAM Identity Center. ($BATON_GLOBAL_AWS_SSO_ENABLED)
      --global-aws-orgs-enabled bool        Enable support for AWS Organizations. ($BATON_GLOBAL_AWS_ORGS_ENABLED)
  -h, --help                                help for baton-aws
      --log-format string                   The output format for logs: json, console ($C1_LOG_FORMAT) (default "json")
      --log-level string                    The log level: debug, info, warn, error ($C1_LOG_LEVEL) (default "info")
      --role-arn string                     The role arn for the aws account. ($BATON_ROLE_ARN)
  -v, --version                             version for baton-aws

Use "baton-aws [command] --help" for more information about a command.

```
