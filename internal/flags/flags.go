package flags

import "github.com/spf13/pflag"

const (
	FlagRiskScoreThreshold = "risk-score-threshold" // minimum risk score for which findings are included
	FlagUnifiedTestAPI     = "unified-test"         // use modern (non-legacy) workflow even without risk score threshold
)

// OSTestFlagSet returns a flag set for the Open Source Test workflow.
func OSTestFlagSet() *pflag.FlagSet {
	flagSet := pflag.NewFlagSet("snyk-cli-extension-os-flows", pflag.ExitOnError)

	flagSet.Bool(FlagUnifiedTestAPI, false, "Use the unified test API workflow.")
	flagSet.Int(FlagRiskScoreThreshold, -1, "Include findings at or over this risk score threshold")

	return flagSet
}
