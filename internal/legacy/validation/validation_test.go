package validation_test

import (
	"path/filepath"
	"testing"

	snyk_errors "github.com/snyk/error-catalog-golang-public/snyk_errors"
	"github.com/snyk/go-application-framework/pkg/configuration"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/snyk/cli-extension-os-flows/internal/legacy/validation"
	"github.com/snyk/cli-extension-os-flows/internal/outputworkflow"
	"github.com/snyk/cli-extension-os-flows/pkg/flags"
)

// Expected catalog Title and ErrorCode for errors from cli.NewInvalidFlagOptionError and cli.NewEmptyFlagOptionError.
// These must match github.com/snyk/error-catalog-golang-public/cli (see snyk_errors.Error struct: Title, ErrorCode, Detail).
const (
	catalogErrorCodeInvalidFlagOption = "SNYK-CLI-0004"
	catalogErrorCodeEmptyFlagOption   = "SNYK-CLI-0003"
	catalogTitleInvalidFlagOption     = "Invalid flag option"
	catalogTitleEmptyFlagOption       = "Empty flag option"
)

// assertCatalogError asserts that err is a catalog error with the expected ErrorCode, Title, and Detail.
func assertCatalogError(t *testing.T, err error, wantErrorCode, wantTitle, wantDetail string) {
	t.Helper()
	var catalogErr snyk_errors.Error
	require.ErrorAs(t, err, &catalogErr)
	assert.Equal(t, wantErrorCode, catalogErr.ErrorCode, "ErrorCode should match catalog")
	assert.Equal(t, wantTitle, catalogErr.Title, "Title should match catalog")
	assert.Equal(t, wantDetail, catalogErr.Detail, "Detail should match catalog")
}

// TestValidateFlagValues_EmptyConfig_ReturnsNoError hoists the common case: empty config passes all validations.
func TestValidateFlagValues_EmptyConfig_ReturnsNoError(t *testing.T) {
	t.Parallel()
	cfg := configuration.New()
	err := validation.ValidateFlagValues(cfg, validation.CommandTest)
	require.NoError(t, err)
}

func TestValidateFlagValues_Exclude_RequiresAllProjectsOrYarnWorkspaces(t *testing.T) {
	t.Parallel()

	t.Run("no error when exclude set with all-projects", func(t *testing.T) {
		t.Parallel()
		cfg := configuration.New()
		cfg.Set(flags.FlagExclude, "foo")
		cfg.Set(flags.FlagAllProjects, true)
		err := validation.ValidateFlagValues(cfg, validation.CommandTest)
		require.NoError(t, err)
	})

	t.Run("no error when exclude set with yarn-workspaces", func(t *testing.T) {
		t.Parallel()
		cfg := configuration.New()
		cfg.Set(flags.FlagExclude, "foo")
		cfg.Set(flags.FlagYarnWorkspaces, true)
		err := validation.ValidateFlagValues(cfg, validation.CommandTest)
		require.NoError(t, err)
	})

	t.Run("error when exclude set without all-projects or yarn-workspaces", func(t *testing.T) {
		t.Parallel()
		cfg := configuration.New()
		cfg.Set(flags.FlagExclude, "foo")
		err := validation.ValidateFlagValues(cfg, validation.CommandTest)
		require.Error(t, err)
		assertCatalogError(t, err, catalogErrorCodeInvalidFlagOption, catalogTitleInvalidFlagOption,
			"The --exclude option can only be used in combination with --all-projects or --yarn-workspaces.")
	})
}

func TestValidateFlagValues_Exclude_NonEmptyValue(t *testing.T) {
	t.Parallel()

	t.Run("error when exclude set to empty string (--exclude=)", func(t *testing.T) {
		t.Parallel()
		cfg := configuration.New()
		cfg.Set(flags.FlagExclude, "")
		cfg.Set(flags.FlagAllProjects, true)
		err := validation.ValidateFlagValues(cfg, validation.CommandTest)
		require.Error(t, err)
		assertCatalogError(t, err, catalogErrorCodeEmptyFlagOption, catalogTitleEmptyFlagOption,
			"Empty --exclude argument. Did you mean --exclude=subdirectory ?")
	})

	t.Run("error when exclude set to BareFlag sentinel (bare --exclude)", func(t *testing.T) {
		t.Parallel()
		cfg := configuration.New()
		cfg.Set(flags.FlagExclude, flags.InvalidFlagValue)
		cfg.Set(flags.FlagAllProjects, true)
		err := validation.ValidateFlagValues(cfg, validation.CommandTest)
		require.Error(t, err)
		assertCatalogError(t, err, catalogErrorCodeEmptyFlagOption, catalogTitleEmptyFlagOption,
			"Empty --exclude argument. Did you mean --exclude=subdirectory ?")
	})
}

func TestValidateFlagValues_Exclude_NoPathSeparator(t *testing.T) {
	t.Parallel()
	cfg := configuration.New()
	cfg.Set(flags.FlagExclude, filepath.Join("dir", "sub"))
	cfg.Set(flags.FlagAllProjects, true)
	err := validation.ValidateFlagValues(cfg, validation.CommandTest)
	require.Error(t, err)
	assertCatalogError(t, err, catalogErrorCodeInvalidFlagOption, catalogTitleInvalidFlagOption,
		"The --exclude argument must be a comma separated list of directory or file names and cannot contain a path.")
}

func TestValidateFlagValues_File_NonEmptyWhenSet(t *testing.T) {
	t.Parallel()
	cfg := configuration.New()
	cfg.Set(flags.FlagFile, "")
	err := validation.ValidateFlagValues(cfg, validation.CommandTest)
	require.Error(t, err)
	assertCatalogError(t, err, catalogErrorCodeEmptyFlagOption, catalogTitleEmptyFlagOption,
		"Empty --file argument. Did you mean --file=path/to/file ?")
}

func TestValidateFlagValues_FileAndProjectName_SlnNotSupportedWithProjectName(t *testing.T) {
	t.Parallel()

	t.Run("no error when file does not end with .sln", func(t *testing.T) {
		t.Parallel()
		cfg := configuration.New()
		cfg.Set(flags.FlagFile, "package.json")
		cfg.Set(flags.FlagProjectName, "my-project")
		err := validation.ValidateFlagValues(cfg, validation.CommandTest)
		require.NoError(t, err)
	})

	t.Run("no error when file is .sln but project-name not set", func(t *testing.T) {
		t.Parallel()
		cfg := configuration.New()
		cfg.Set(flags.FlagFile, "solution.sln")
		err := validation.ValidateFlagValues(cfg, validation.CommandTest)
		require.NoError(t, err)
	})

	t.Run("error when file ends with .sln and project-name set", func(t *testing.T) {
		t.Parallel()
		cfg := configuration.New()
		cfg.Set(flags.FlagFile, "solution.sln")
		cfg.Set(flags.FlagProjectName, "my-project")
		err := validation.ValidateFlagValues(cfg, validation.CommandTest)
		require.Error(t, err)
		assertCatalogError(t, err, catalogErrorCodeInvalidFlagOption, catalogTitleInvalidFlagOption,
			"The following option combination is not currently supported: file=*.sln + project-name")
	})
}

func TestValidateFlagValues_DetectionDepth_PositiveIntegerWhenSet(t *testing.T) {
	t.Parallel()

	t.Run("no error when detection-depth set to positive integer", func(t *testing.T) {
		t.Parallel()
		cfg := configuration.New()
		cfg.Set(flags.FlagDetectionDepth, "3")
		err := validation.ValidateFlagValues(cfg, validation.CommandTest)
		require.NoError(t, err)
	})

	detectionDepthDetail := "Unsupported value for --detection-depth flag. Expected a positive integer."
	t.Run("error when detection-depth set to zero", func(t *testing.T) {
		t.Parallel()
		cfg := configuration.New()
		cfg.Set(flags.FlagDetectionDepth, "0")
		err := validation.ValidateFlagValues(cfg, validation.CommandTest)
		require.Error(t, err)
		assertCatalogError(t, err, catalogErrorCodeInvalidFlagOption, catalogTitleInvalidFlagOption, detectionDepthDetail)
	})

	t.Run("error when detection-depth set to negative", func(t *testing.T) {
		t.Parallel()
		cfg := configuration.New()
		cfg.Set(flags.FlagDetectionDepth, "-1")
		err := validation.ValidateFlagValues(cfg, validation.CommandTest)
		require.Error(t, err)
		assertCatalogError(t, err, catalogErrorCodeInvalidFlagOption, catalogTitleInvalidFlagOption, detectionDepthDetail)
	})

	t.Run("error when detection-depth set to non-integer", func(t *testing.T) {
		t.Parallel()
		cfg := configuration.New()
		cfg.Set(flags.FlagDetectionDepth, "abc")
		err := validation.ValidateFlagValues(cfg, validation.CommandTest)
		require.Error(t, err)
		assertCatalogError(t, err, catalogErrorCodeInvalidFlagOption, catalogTitleInvalidFlagOption, detectionDepthDetail)
	})
}

func TestValidateFlagValues_JsonFileOutput_NonEmptyWhenSet(t *testing.T) {
	t.Parallel()

	t.Run("no error when json-file-output set with non-empty value", func(t *testing.T) {
		t.Parallel()
		cfg := configuration.New()
		cfg.Set(outputworkflow.OutputConfigKeyJSONFile, "/path/to/out.json")
		err := validation.ValidateFlagValues(cfg, validation.CommandTest)
		require.NoError(t, err)
	})

	t.Run("error when json-file-output set and value empty (--json-file-output=)", func(t *testing.T) {
		t.Parallel()
		cfg := configuration.New()
		cfg.Set(outputworkflow.OutputConfigKeyJSONFile, "")
		err := validation.ValidateFlagValues(cfg, validation.CommandTest)
		require.Error(t, err)
		assertCatalogError(t, err, catalogErrorCodeEmptyFlagOption, catalogTitleEmptyFlagOption,
			"Empty --json-file-output argument. Did you mean --file=path/to/output-file.json ?")
	})

	t.Run("error when json-file-output set to BareFlag sentinel (bare --json-file-output)", func(t *testing.T) {
		t.Parallel()
		cfg := configuration.New()
		cfg.Set(outputworkflow.OutputConfigKeyJSONFile, flags.InvalidFlagValue)
		err := validation.ValidateFlagValues(cfg, validation.CommandTest)
		require.Error(t, err)
		assertCatalogError(t, err, catalogErrorCodeEmptyFlagOption, catalogTitleEmptyFlagOption,
			"Empty --json-file-output argument. Did you mean --file=path/to/output-file.json ?")
	})
}

func TestValidateFlagValues_SarifFileOutput_NonEmptyWhenSet(t *testing.T) {
	t.Parallel()

	t.Run("no error when sarif-file-output set with non-empty value", func(t *testing.T) {
		t.Parallel()
		cfg := configuration.New()
		cfg.Set(outputworkflow.OutputConfigKeySarifFileOutput, "/path/to/out.sarif")
		err := validation.ValidateFlagValues(cfg, validation.CommandTest)
		require.NoError(t, err)
	})

	t.Run("error when sarif-file-output set and value empty (--sarif-file-output=)", func(t *testing.T) {
		t.Parallel()
		cfg := configuration.New()
		cfg.Set(outputworkflow.OutputConfigKeySarifFileOutput, "")
		err := validation.ValidateFlagValues(cfg, validation.CommandTest)
		require.Error(t, err)
		assertCatalogError(t, err, catalogErrorCodeEmptyFlagOption, catalogTitleEmptyFlagOption,
			"Empty --sarif-file-output argument. Did you mean --file=path/to/output-file.json ?")
	})

	t.Run("error when sarif-file-output set to BareFlag sentinel (bare --sarif-file-output)", func(t *testing.T) {
		t.Parallel()
		cfg := configuration.New()
		cfg.Set(outputworkflow.OutputConfigKeySarifFileOutput, flags.InvalidFlagValue)
		err := validation.ValidateFlagValues(cfg, validation.CommandTest)
		require.Error(t, err)
		assertCatalogError(t, err, catalogErrorCodeEmptyFlagOption, catalogTitleEmptyFlagOption,
			"Empty --sarif-file-output argument. Did you mean --file=path/to/output-file.json ?")
	})
}

func TestValidateFlagValues_Monitor_RejectsJsonFileOutput(t *testing.T) {
	t.Parallel()
	cfg := configuration.New()
	cfg.Set(outputworkflow.OutputConfigKeyJSONFile, "/path/to/out.json")
	err := validation.ValidateFlagValues(cfg, validation.CommandMonitor)
	require.Error(t, err)
	assertCatalogError(t, err, catalogErrorCodeInvalidFlagOption, catalogTitleInvalidFlagOption,
		"The following option combination is not currently supported: monitor + json-file-output")
}

func TestValidateFlagValues_Monitor_RejectsSarifFileOutput(t *testing.T) {
	t.Parallel()
	cfg := configuration.New()
	cfg.Set(outputworkflow.OutputConfigKeySarifFileOutput, "/path/to/out.sarif")
	err := validation.ValidateFlagValues(cfg, validation.CommandMonitor)
	require.Error(t, err)
	assertCatalogError(t, err, catalogErrorCodeInvalidFlagOption, catalogTitleInvalidFlagOption,
		"The following option combination is not currently supported: monitor + sarif-file-output")
}

func TestValidateFlagValues_ProjectBusinessCriticality_EmptyWhenSet(t *testing.T) {
	t.Parallel()

	t.Run("no error when project-business-criticality set with non-empty value", func(t *testing.T) {
		t.Parallel()
		cfg := configuration.New()
		cfg.Set(flags.FlagProjectBusinessCriticality, "high")
		err := validation.ValidateFlagValues(cfg, validation.CommandMonitor)
		require.NoError(t, err)
	})

	t.Run("no error when project-business-criticality set to empty string (--project-business-criticality=)", func(t *testing.T) {
		t.Parallel()
		// An explicit = with no value intentionally clears existing project attributes.
		cfg := configuration.New()
		cfg.Set(flags.FlagProjectBusinessCriticality, "")
		err := validation.ValidateFlagValues(cfg, validation.CommandMonitor)
		require.NoError(t, err)
	})

	t.Run("error when project-business-criticality set to BareFlag sentinel (bare --project-business-criticality)", func(t *testing.T) {
		t.Parallel()
		cfg := configuration.New()
		cfg.Set(flags.FlagProjectBusinessCriticality, flags.InvalidFlagValue)
		err := validation.ValidateFlagValues(cfg, validation.CommandMonitor)
		require.Error(t, err)
		assertCatalogError(t, err, catalogErrorCodeEmptyFlagOption, catalogTitleEmptyFlagOption,
			"--project-business-criticality must contain an '=' with a comma-separated list of values."+
				" To clear all existing values, pass no values i.e. --project-business-criticality=")
	})
}

func TestValidateFlagValues_ProjectTags_EmptyWhenSet(t *testing.T) {
	t.Parallel()

	t.Run("no error when project-tags set with non-empty value", func(t *testing.T) {
		t.Parallel()
		cfg := configuration.New()
		cfg.Set(flags.FlagProjectTags, "env=prod")
		err := validation.ValidateFlagValues(cfg, validation.CommandMonitor)
		require.NoError(t, err)
	})

	t.Run("no error when project-tags set to empty string (--project-tags=)", func(t *testing.T) {
		t.Parallel()
		// An explicit = with no value intentionally clears existing tags.
		cfg := configuration.New()
		cfg.Set(flags.FlagProjectTags, "")
		err := validation.ValidateFlagValues(cfg, validation.CommandMonitor)
		require.NoError(t, err)
	})

	t.Run("error when project-tags set to BareFlag sentinel (bare --project-tags)", func(t *testing.T) {
		t.Parallel()
		cfg := configuration.New()
		cfg.Set(flags.FlagProjectTags, flags.InvalidFlagValue)
		err := validation.ValidateFlagValues(cfg, validation.CommandMonitor)
		require.Error(t, err)
		assertCatalogError(t, err, catalogErrorCodeEmptyFlagOption, catalogTitleEmptyFlagOption,
			"--project-tags must contain an '=' with a comma-separated list of pairs (also separated with an '=')."+
				" To clear all existing values, pass no values i.e. --project-tags=")
	})
}
