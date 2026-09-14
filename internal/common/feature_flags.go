package common

import (
	"github.com/snyk/cli-extension-dep-graph/v2/pkg/ecosystems/orchestrator"
	"github.com/snyk/go-application-framework/pkg/configuration"

	"github.com/snyk/cli-extension-os-flows/internal/constants"
)

// UseUnifiedTestAPI reports whether `snyk test` should go through the unified test API.
//
// The `unified-test-api-os-cli` percentage rollout opts a customer in. The registry
// group/org flag `optOutUnifiedTestApiCliRollout` overrides it, so a single customer can be
// held on the legacy path without winding the rollout percentage back to 0.
func UseUnifiedTestAPI(config configuration.Configuration) bool {
	if config.GetBool(constants.FeatureFlagOptOutUnifiedTestAPIRollout) {
		return false
	}
	return config.GetBool(orchestrator.FlagUnifiedTestAPIOsCLI.Key)
}
