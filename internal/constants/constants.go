package constants

// ForceLegacyCLIEnvVar is an internal environment variable to force the legacy CLI flow.
const ForceLegacyCLIEnvVar = "SNYK_FORCE_LEGACY_CLI"

// AutodetectOSSEnvVar opts a session into auto-detecting C/C++ artefacts in
// each input directory. When found, an extra unmanaged scan runs alongside
// the managed scan so mixed projects don't need an explicit --unmanaged flag.
const AutodetectOSSEnvVar = "SNYK_AUTODETECT_OSS"

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

// FeatureFlagDlfyCLIRollout is used to rollout the CLI flow to the dragonfly stack.
const FeatureFlagDlfyCLIRollout = "internal_snyk_cli_rollout_dfly_os_cli"

// FeatureFlagDflySbomMonitor is used to rollout the SBOM monitor flow to the dragonfly stack.
const FeatureFlagDflySbomMonitor = "internal_snyk_cli_rollout_dfly_sbom_monitor"

// FeatureFlagEnableSbomMonitor is used to opt in to the registry-based SBOM monitor flow.
const FeatureFlagEnableSbomMonitor = "internal_snyk_cli_enable_sbom_monitor"

// UploadingSourceCodeMessage is the message that's being rendered in the UI spinner while
// the source code is being uploaded.
const UploadingSourceCodeMessage = "Uploading source code..."
