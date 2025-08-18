package main

import (
	cfg "github.com/conductorone/baton-aws/pkg/config"
	"github.com/conductorone/baton-sdk/pkg/config"
)

func main() {
	config.Generate("aws", cfg.Config)
}
