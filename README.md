# baton-aws

## Usage
```
baton-aws

Usage:
  baton-aws [flags]
  baton-aws [command]

Available Commands:
  completion         Generate the autocompletion script for the specified shell
  help               Help about any command

Flags:
      --external-id string                  The external id for the aws account
  -f, --file string                         The path to the c1z file to sync with ($C1_FILE) (default "sync.c1z")
      --global-access-key-id string         The global-access-key-id for the aws account
      --global-binding-external-id string   The global external id for the aws account
      --global-region string                The region for the aws account
      --global-role-arn string              The role arn for the aws account
      --global-secret-access-key string     The global-secret-access-key for the aws account
  -h, --help                                help for baton-aws
      --log-format string                   The output format for logs: json, console ($C1_LOG_FORMAT) (default "json")
      --log-level string                    The log level: debug, info, warn, error ($C1_LOG_LEVEL) (default "info")
      --role-arn string                     The role arn for the aws account
  -v, --version                             version for baton-aws

Use "baton-aws [command] --help" for more information about a command.
```