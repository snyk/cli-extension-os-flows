package common

import (
	"context"
	"fmt"
	"math"

	"github.com/snyk/go-application-framework/pkg/apiclients/testapi"

	"github.com/snyk/cli-extension-os-flows/internal/commands/cmdctx"
	cmdutil "github.com/snyk/cli-extension-os-flows/internal/commands/util"
	"github.com/snyk/cli-extension-os-flows/internal/legacy/transform"
	"github.com/snyk/cli-extension-os-flows/internal/util"
	"github.com/snyk/cli-extension-os-flows/pkg/flags"
)

// CreateLocalPolicy will create a local policy only if risk score or severity threshold or reachability filters are specified in the config.
func CreateLocalPolicy(cmdCtx context.Context, inputDir string) (*testapi.LocalPolicy, error) {
	riskScoreThreshold := getRiskScoreThreshold(cmdCtx)
	severityThreshold := getSeverityThreshold(cmdCtx)
	reachabilityFilter := getReachabilityFilter(cmdCtx)
	failOnPolicy, err := getFailOnPolicy(cmdCtx)
	if err != nil {
		return nil, err
	}
	localIgnores, err := getLocalIgnores(cmdCtx, inputDir)
	if err != nil {
		return nil, err
	}

	if riskScoreThreshold == nil && severityThreshold == nil && reachabilityFilter == nil && failOnPolicy.onUpgradable == nil && localIgnores == nil {
		var noPolicy *testapi.LocalPolicy
		return noPolicy, nil
	}

	// if we have some policy but no severity threshold, default to None
	if severityThreshold == nil {
		severityThreshold = util.Ptr(testapi.SeverityNone)
	}

	return &testapi.LocalPolicy{
		RiskScoreThreshold: riskScoreThreshold,
		SeverityThreshold:  severityThreshold,
		ReachabilityFilter: reachabilityFilter,
		FailOnUpgradable:   failOnPolicy.onUpgradable,
		Ignores:            localIgnores,
	}, nil
}

func convertReachabilityFilterToSchema(reachabilityFilter string) *testapi.ReachabilityFilter {
	if reachabilityFilter == "" {
		return nil
	}

	switch reachabilityFilter {
	case "not-applicable", "not applicable":
		return util.Ptr(testapi.ReachabilityFilterNoInfo)
	case "no-path-found", "no path found":
		return util.Ptr(testapi.ReachabilityFilterNoPathFound)
	case "reachable":
		return util.Ptr(testapi.ReachabilityFilterReachable)
	default:
		return nil
	}
}

func getRiskScoreThreshold(ctx context.Context) *uint16 {
	cfg := cmdctx.Config(ctx)
	logger := cmdctx.Logger(ctx)
	riskScoreThresholdInt := cfg.GetInt(flags.FlagRiskScoreThreshold)
	if riskScoreThresholdInt >= math.MaxUint16 {
		logger.Warn().Msgf("Risk score threshold %d exceeds maximum uint16 value. Setting to maximum.", riskScoreThresholdInt)
		maxVal := uint16(math.MaxUint16)
		return &maxVal
	} else if riskScoreThresholdInt >= 0 {
		rs := uint16(riskScoreThresholdInt)
		return &rs
	}
	return nil
}

func getSeverityThreshold(ctx context.Context) *testapi.Severity {
	cfg := cmdctx.Config(ctx)
	severityThresholdStr := cfg.GetString(flags.FlagSeverityThreshold)
	if severityThresholdStr != "" {
		st := testapi.Severity(severityThresholdStr)
		return &st
	}
	return nil
}

func getReachabilityFilter(ctx context.Context) *testapi.ReachabilityFilter {
	cfg := cmdctx.Config(ctx)
	reachabilityFiltersFromConfig := convertReachabilityFilterToSchema(cfg.GetString(flags.FlagReachabilityFilter))

	if reachabilityFiltersFromConfig != nil {
		return reachabilityFiltersFromConfig
	}

	return nil
}

type supportedFailOnPolicy struct {
	onUpgradable *bool
}

func getFailOnPolicy(ctx context.Context) (supportedFailOnPolicy, error) {
	cfg := cmdctx.Config(ctx)
	errFactory := cmdctx.ErrorFactory(ctx)
	failOnFromConfig := cfg.GetString(flags.FlagFailOn)

	var failOnPolicy supportedFailOnPolicy
	if failOnFromConfig == "" {
		return failOnPolicy, nil
	}

	switch failOnFromConfig {
	case "upgradable", "all":
		failOnPolicy.onUpgradable = util.Ptr(true)
	default:
		//nolint:wrapcheck // No need to wrap error factory errors.
		return failOnPolicy, errFactory.NewUnsupportedFailOnValueError(failOnFromConfig)
	}

	return failOnPolicy, nil
}

func getLocalIgnores(ctx context.Context, inputDir string) (*[]testapi.LocalIgnore, error) {
	policy, err := cmdutil.GetLocalPolicy(ctx, inputDir)
	if err != nil {
		return nil, fmt.Errorf("failed to get local ignores: %w", err)
	}
	if policy != nil {
		return transform.LocalPolicyToSchema(policy), nil
	}
	//nolint:nilnil // Intentionally returning nil ignores if no policy is present.
	return nil, nil
}
