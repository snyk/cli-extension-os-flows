package flags

import "github.com/spf13/pflag"

// Defines the command-line flags used in the OS-Flows CLI extension.
const (
	// Open Source.
	FlagFile               = "file"
	FlagProjectName        = "project-name"
	FlagRiskScoreThreshold = "risk-score-threshold"
	FlagSeverityThreshold  = "severity-threshold"

	// SBOM reachability.
	FlagReachability = "reachability"
	FlagSBOM         = "sbom"
	FlagSourceDir    = "source-dir"

	// Passed through to legacy CLI.
	FlagAllProjects                  = "all-projects"
	FlagExperimental                 = "experimental"
	FlagUnmanaged                    = "unmanaged"
	FlagDetectionDepth               = "detection-depth"
	FlagExclude                      = "exclude"
	FlagPruneRepeatedSubDependencies = "prune-repeated-subdependencies"
	FlagTargetReference              = "target-reference"
	FlagPolicyPath                   = "policy-path"
	FlagMavenAggregateProject        = "maven-aggregate-project"
	FlagScanUnmanaged                = "scan-unmanaged"
	FlagScanAllUnmanaged             = "scan-all-unmanaged"
	FlagSubProject                   = "sub-project"
	FlagAllSubProjects               = "all-sub-projects"
	FlagGradleSubProject             = "gradle-sub-project"
	FlagConfigurationMatching        = "configuration-matching"
	FlagConfigurationAttributes      = "configuration-attributes"
	FlagInitScript                   = "init-script"
	FlagNugetAssetsProjectName       = "assets-project-name"
	FlagNugetPkgsFolder              = "packages-folder"
	FlagDev                          = "dev"
	FlagNPMStrictOutOfSync           = "strict-out-of-sync"
	FlagYarnWorkspaces               = "yarn-workspaces"
	FlagPythonCommand                = "command"
	FlagPythonSkipUnresolved         = "skip-unresolved"
	FlagPythonPackageManager         = "package-manager"
	FlagRemoteRepoURL                = "remote-repo-url"
	FlagUnmanagedMaxDepth            = "max-depth"
	FlagVersion                      = "version"

	FlagFailFast                = "fail-fast"
	FlagPrintDeps               = "print-deps"
	FlagPrintDepPaths           = "print-dep-paths"
	FlagOrg                     = "org"
	FlagIgnorePolicy            = "ignore-policy"
	FlagTrustPolicies           = "trust-policies"
	FlagShowVulnerablePaths     = "show-vulnerable-paths"
	FlagFailOn                  = "fail-on"
	FlagProjectNamePrefix       = "project-name-prefix"
	FlagDotnetRuntimeResolution = "dotnet-runtime-resolution"
	FlagDotnetTargetFramework   = "dotnet-target-framework"
)

// OSTestFlagSet returns a flag set for the Open Source Test workflow.
func OSTestFlagSet() *pflag.FlagSet {
	flagSet := pflag.NewFlagSet("snyk-cli-extension-os-flows", pflag.ExitOnError)

	// Open Source
	flagSet.String(FlagFile, "", "Specify a package file.")
	flagSet.String(FlagProjectName, "", "Specify a name for the project.")

	flagSet.Int(FlagRiskScoreThreshold, -1, "Include findings at or over this risk score threshold.")
	flagSet.String(FlagSeverityThreshold, "", "Report only findings at the specified level or higher.")

	// Reachability
	flagSet.Bool(FlagReachability, false, "Run reachability analysis on source code.")

	flagSet.String(FlagSBOM, "", "Specify an SBOM file to be tested.")
	flagSet.String(FlagSourceDir, "", "Path of the directory containing the source code.")

	// Unused flags for passing to legacy CLI
	flagSet.Bool(FlagAllProjects, false, "Auto-detect all projects in the working directory (including Yarn workspaces).")
	flagSet.String(FlagExclude, "", "Can be used with --all-projects to indicate directory names and file names to exclude. Must be comma separated.")
	flagSet.String(FlagDetectionDepth, "", "Use with --all-projects to indicate how many subdirectories to search. "+
		"DEPTH must be a number, 1 or greater; zero (0) is the current directory.")
	flagSet.Bool(FlagExperimental, false, "Deprecated. Will be ignored.")
	flagSet.Bool(FlagUnmanaged, false, "For C/C++ only, scan all files for known open source dependencies and build an SBOM.")
	flagSet.Bool(FlagYarnWorkspaces, false, "Detect and scan Yarn Workspaces only when a lockfile is in the root.")
	flagSet.BoolP(FlagPruneRepeatedSubDependencies, "p", false, "Prune dependency trees, removing duplicate sub-dependencies.")
	flagSet.String(FlagVersion, "", "Specify a version for the collection of all projects in the working directory.")
	flagSet.Bool(FlagDev, false, "Include development-only dependencies. Applicable only for some package managers.")
	flagSet.Bool(FlagMavenAggregateProject, false, "Ensure all modules are resolvable by the Maven reactor.")
	flagSet.Bool(FlagScanUnmanaged, false, "Specify an individual JAR, WAR, or AAR file.")
	flagSet.Bool(FlagScanAllUnmanaged, false, "Auto-detect Maven, JAR, WAR, and AAR files recursively from the current folder.")
	flagSet.String(FlagSubProject, "", "Name of Gradle sub-project to test.")
	flagSet.String(FlagGradleSubProject, "", "Name of Gradle sub-project to test.")
	flagSet.Bool(FlagAllSubProjects, false, "Test all sub-projects in a multi-project build.")
	flagSet.String(FlagNPMStrictOutOfSync, "true", "Prevent testing out-of-sync lockfiles.")
	flagSet.Bool(FlagNugetAssetsProjectName, false,
		"When you are monitoring a .NET project using NuGet PackageReference uses the project name in project.assets.json if found.")
	flagSet.String(FlagNugetPkgsFolder, "", "Specify a custom path to the packages folder when using NuGet.")
	flagSet.String(FlagConfigurationMatching, "", "Resolve dependencies using only configuration(s) that match the specified Java regular expression.")
	flagSet.String(FlagConfigurationAttributes, "", "Select certain values of configuration attributes to install and resolve dependencies.")
	flagSet.String(FlagInitScript, "", "Use for projects that contain a Gradle initialization script.")
	flagSet.String(FlagPythonCommand, "", "Indicate which specific Python commands to use based on the Python version.")
	flagSet.String(FlagPythonSkipUnresolved, "", "Skip Python packages that cannot be found in the environment.")
	flagSet.String(FlagPythonPackageManager, "", `Add --package-manager=pip to your command if the file name is not "requirements.txt".`)
	flagSet.Int(FlagUnmanagedMaxDepth, 0, "Specify the maximum level of archive extraction for unmanaged scanning.")
	flagSet.Bool(FlagFailFast, false, "Stop scanning after the first vulnerability is found when used with --all-projects.")
	flagSet.Bool(FlagPrintDeps, false, "Print the dependency tree before sending it for analysis.")
	flagSet.Bool(FlagPrintDepPaths, false, "Display dependencies. Shows what files contributed to each dependency.")
	flagSet.String(FlagOrg, "", "Specify the <ORG_ID> to run Snyk commands tied to a specific organization.")
	flagSet.Bool(FlagIgnorePolicy, false, "Ignore all set policies, the current policy in the .snyk file, Org level ignores, and the project policy on snyk.io.")
	flagSet.Bool(FlagTrustPolicies, false, "Apply and use ignore rules from the Snyk policies in your dependencies.")
	flagSet.String(FlagShowVulnerablePaths, "", "Display the dependency paths from the top level dependencies down to the vulnerable packages.")
	flagSet.String(FlagFailOn, "", "Fail only when there are vulnerabilities that can be fixed.")
	flagSet.String(FlagProjectNamePrefix, "", "When monitoring a .NET project, use this option to add a custom prefix "+
		"to the name of files inside a project along with any desired separators.")
	flagSet.Bool(FlagDotnetRuntimeResolution, false, "You must use this option when you test .NET projects using Runtime Resolution Scanning.")
	flagSet.String(FlagDotnetTargetFramework, "", "Specify the target framework for .NET projects.")

	return flagSet
}
