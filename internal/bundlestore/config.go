package bundlestore

import (
	"strings"
	"time"

	"github.com/snyk/go-application-framework/pkg/configuration"
)

var defaultSnykCodeTimeout = 12 * time.Hour

// CodeClientConfig holds the configuration for the code client.
type CodeClientConfig struct {
	// LocalConfiguration is the underlying configuration source.
	LocalConfiguration configuration.Configuration
}

// Organization returns the organization ID from the configuration.
func (c *CodeClientConfig) Organization() string {
	return c.LocalConfiguration.GetString(configuration.ORGANIZATION)
}

// IsFedramp returns true if the configuration is set for FedRAMP.
func (c *CodeClientConfig) IsFedramp() bool {
	return c.LocalConfiguration.GetBool(configuration.IS_FEDRAMP)
}

// SnykCodeApi returns the Snyk Code API URL, replacing "api" with "deeproxy" in the base API URL.
//
//nolint:revive,var-naming // SnykCodeApi is intentionally cased this way.
func (c *CodeClientConfig) SnykCodeApi() string {
	//nolint:gocritic // Code copied verbatim from code-client-go
	return strings.Replace(c.LocalConfiguration.GetString(configuration.API_URL), "api", "deeproxy", -1)
}

// SnykApi returns the base Snyk API URL from the configuration.
//
//nolint:revive,var-naming // SnykApi is intentionally cased this way.
func (c *CodeClientConfig) SnykApi() string {
	return c.LocalConfiguration.GetString(configuration.API_URL)
}

// SnykCodeAnalysisTimeout returns the timeout duration for Snyk Code analysis.
// If not set in the configuration, it returns the default timeout.
func (c *CodeClientConfig) SnykCodeAnalysisTimeout() time.Duration {
	if !c.LocalConfiguration.IsSet(configuration.TIMEOUT) {
		return defaultSnykCodeTimeout
	}
	timeoutInSeconds := c.LocalConfiguration.GetInt(configuration.TIMEOUT)
	return time.Duration(timeoutInSeconds) * time.Second
}
