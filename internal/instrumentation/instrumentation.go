package instrumentation

import "github.com/snyk/go-application-framework/pkg/analytics"

//go:generate go run github.com/golang/mock/mockgen -package=mocks -destination=../mocks/mock_instrumentation.go github.com/snyk/cli-extension-os-flows/internal/instrumentation Instrumentation

// Custom metric keys.
const (
	codeUploadTimeMs    string = "codeUploadMs"
	codeAnalysisTimeMs  string = "codeAnalysisMs"
	osAnalysisTimeMs    string = "osAnalysisMs"
	showMavenBuildScope string = "showMavenBuildScope"
	showNpmBuildScope   string = "showNpmBuildScope"
)

// Instrumentation defines the interface that we expect for instrumentation objects.
type Instrumentation interface {
	RecordCodeUploadTime(timeMs int64)
	RecordCodeAnalysisTime(timeMs int64)
	RecordOSAnalysisTime(timeMs int64)
	RecordShowMavenBuildScopeFlag(showMavenBuildScopeFlag bool)
	RecordShowNpmBuildScopeFlag(showNpmBuildScopeFlag bool)
}

// GAFInstrumentation is an implementation of Instrumentation that uses the GAF analytics.
type GAFInstrumentation struct {
	analytics analytics.Analytics
}

// RecordCodeUploadTime is used to record the time it takes to upload the source code.
func (gafI *GAFInstrumentation) RecordCodeUploadTime(timeMs int64) {
	gafI.analytics.AddExtensionIntegerValue(codeUploadTimeMs, int(timeMs))
}

// RecordCodeAnalysisTime is used to record the time it takes to do the code analysis.
func (gafI *GAFInstrumentation) RecordCodeAnalysisTime(timeMs int64) {
	gafI.analytics.AddExtensionIntegerValue(codeAnalysisTimeMs, int(timeMs))
}

// RecordOSAnalysisTime is used to record the time it takes to do the open source analysis.
func (gafI *GAFInstrumentation) RecordOSAnalysisTime(timeMs int64) {
	gafI.analytics.AddExtensionIntegerValue(osAnalysisTimeMs, int(timeMs))
}

// RecordShowMavenBuildScopeFlag is used to record the value of the show-maven-build-scope feature flag.
func (gafI *GAFInstrumentation) RecordShowMavenBuildScopeFlag(showMavenBuildScopeFlag bool) {
	gafI.analytics.AddExtensionBoolValue(showMavenBuildScope, showMavenBuildScopeFlag)
}

// RecordShowNpmBuildScopeFlag is used to record the value of the show-maven-build-scope feature flag.
func (gafI *GAFInstrumentation) RecordShowNpmBuildScopeFlag(showNpmBuildScopeFlag bool) {
	gafI.analytics.AddExtensionBoolValue(showNpmBuildScope, showNpmBuildScopeFlag)
}

// NewGAFInstrumentation will create a new GAFInstrumentation based on the provided GAF analytics.
func NewGAFInstrumentation(analytics analytics.Analytics) *GAFInstrumentation {
	return &GAFInstrumentation{analytics}
}
