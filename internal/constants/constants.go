package constants

// ForceLegacyCLIEnvVar is an internal environment variable to force the legacy CLI flow.
const ForceLegacyCLIEnvVar = "SNYK_FORCE_LEGACY_CLI"

// FeatureFlagReachabilityForCLI is to gate the reachability capability on the CLI.
const FeatureFlagReachabilityForCLI = "internal_snyk_cli_reachability_enabled"

// FeatureFlagRiskScore is used to gate the risk score feature.
const FeatureFlagRiskScore = "internal_snyk_cli_experimental_risk_score"

// FeatureFlagRiskScoreInCLI is used to gate the risk score feature in the CLI.
const FeatureFlagRiskScoreInCLI = "internal_snyk_cli_experimental_risk_score_in_cli"

// FeatureFlagUseTestShimForOSCliTest gates routing DepGraph tests through the new test API.
const FeatureFlagUseTestShimForOSCliTest = "internal_snyk_cli_use_test_shim_for_os_cli_test"

// FeatureFlagUvCLI is used to gate uv support in the CLI.
const FeatureFlagUvCLI = "internal_snyk_cli_uv_enabled"

// UvLockFileName is the name of the uv lock file.
const UvLockFileName = "uv.lock"

// FeatureFlagShowMavenBuildScope is to gate the maven build scope feature.
const FeatureFlagShowMavenBuildScope = "internal_snyk_show_maven_scope_enabled"

// ShowMavenBuildScope is the feature flag name for the maven build scope feature.
const ShowMavenBuildScope = "show-maven-build-scope"

// FeatureFlagShowNpmScope is to gate the npm build scope feature.
const FeatureFlagShowNpmScope = "internal_snyk_show_npm_scope_enabled"

// ShowNpmScope is the feature flag name for the npm build scope feature.
const ShowNpmScope = "show-npm-scope"
