package main

import (
	"log"

	"github.com/snyk/go-application-framework/pkg/devtools"

	"github.com/snyk/cli-extension-os-flows/pkg/osflows"
)

func main() {
	cmd, err := devtools.Cmd(osflows.Init)
	if err != nil {
		log.Fatal(err)
	}
	cmd.SilenceUsage = true
	if err := cmd.Execute(); err != nil {
		log.Fatal(err)
	}
}
