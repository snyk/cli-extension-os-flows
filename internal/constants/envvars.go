package constants

// EnableExperimentalUvSupportEnvVar is an internal environment variable to enable support for testing UV projects.
const EnableExperimentalUvSupportEnvVar = "SNYK_ENABLE_EXPERIMENTAL_UV_SUPPORT"

// ForceLegacyCLIEnvVar is an internal environment variable to force the legacy CLI flow.
const ForceLegacyCLIEnvVar = "SNYK_FORCE_LEGACY_CLI"

// FeatureFlagReachabilityForCLI is to gate the reachability capability on the CLI.
const FeatureFlagReachabilityForCLI = "internal_snyk_cli_reachability_enabled"

// FeatureFlagSBOMTestReachability is used to gate the sbom test reachability feature.
const FeatureFlagSBOMTestReachability = "internal_snyk_cli_sbom_test_reachability"

// FeatureFlagRiskScore is used to gate the risk score feature.
const FeatureFlagRiskScore = "internal_snyk_cli_experimental_risk_score"

// FeatureFlagRiskScoreInCLI is used to gate the risk score feature in the CLI.
const FeatureFlagRiskScoreInCLI = "internal_snyk_cli_experimental_risk_score_in_cli"
