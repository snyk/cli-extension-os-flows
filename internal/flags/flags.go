package flags

import "github.com/spf13/pflag"

// FlagRiskScoreThreshold is the flag for the minimum risk score for which findings are included.
const FlagRiskScoreThreshold = "risk-score-threshold"

// FlagUnifiedTestAPI forces use of the modern (non-legacy) workflow even without risk score threshold.
const FlagUnifiedTestAPI = "unified-test"

// OSTestFlagSet returns a flag set for the Open Source Test workflow.
func OSTestFlagSet() *pflag.FlagSet {
	flagSet := pflag.NewFlagSet("snyk-cli-extension-os-flows", pflag.ExitOnError)

	flagSet.Bool(FlagUnifiedTestAPI, false, "Use the unified test API workflow.")
	flagSet.Int(FlagRiskScoreThreshold, -1, "Include findings at or over this risk score threshold")

	return flagSet
}
