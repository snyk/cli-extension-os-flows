package common_test

import (
	"testing"

	"github.com/snyk/cli-extension-dep-graph/v2/pkg/ecosystems/orchestrator"
	"github.com/snyk/go-application-framework/pkg/configuration"
	"github.com/stretchr/testify/assert"

	"github.com/snyk/cli-extension-os-flows/internal/common"
	"github.com/snyk/cli-extension-os-flows/internal/constants"
)

func TestUseUnifiedTestAPI(t *testing.T) {
	t.Parallel()

	tcs := map[string]struct {
		rollout  bool
		optOut   bool
		expected bool
	}{
		"in the rollout and not opted out": {
			rollout:  true,
			optOut:   false,
			expected: true,
		},
		"in the rollout but opted out": {
			rollout:  true,
			optOut:   true,
			expected: false,
		},
		"not in the rollout and not opted out": {
			rollout:  false,
			optOut:   false,
			expected: false,
		},
		"not in the rollout and opted out": {
			rollout:  false,
			optOut:   true,
			expected: false,
		},
	}

	for tcName, tc := range tcs {
		t.Run(tcName, func(t *testing.T) {
			t.Parallel()

			cfg := configuration.New()
			cfg.Set(orchestrator.FlagUnifiedTestAPIOsCLI.Key, tc.rollout)
			cfg.Set(constants.FeatureFlagOptOutUnifiedTestAPIRollout, tc.optOut)

			assert.Equal(t, tc.expected, common.UseUnifiedTestAPI(cfg))
		})
	}
}
