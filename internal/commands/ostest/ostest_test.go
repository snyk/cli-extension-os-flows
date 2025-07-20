package ostest_test

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/golang/mock/gomock"
	"github.com/google/uuid"
	"github.com/rs/zerolog"
	"github.com/snyk/go-application-framework/pkg/apiclients/testapi"
	"github.com/snyk/go-application-framework/pkg/configuration"
	"github.com/snyk/go-application-framework/pkg/local_workflows/content_type"
	"github.com/snyk/go-application-framework/pkg/mocks"
	"github.com/snyk/go-application-framework/pkg/networking"
	"github.com/snyk/go-application-framework/pkg/workflow"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/snyk/cli-extension-os-flows/internal/commands/ostest"
	common "github.com/snyk/cli-extension-os-flows/internal/common"
	"github.com/snyk/cli-extension-os-flows/internal/flags"
	"github.com/snyk/cli-extension-os-flows/internal/legacy/definitions"
)

const mockServerURL = "https://mock.server/api"

var legacyWorkflowID = workflow.NewWorkflowIdentifier("legacycli")

func TestOSWorkflow_LegacyFlow(t *testing.T) {
	// Setup - No special flags set
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockEngine := mocks.NewMockEngine(ctrl)
	mockInvocationCtx := createMockInvocationCtxWithURL(t, ctrl, mockEngine, mockServerURL)

	// Mock the legacy flow to return successfully
	mockEngine.EXPECT().
		InvokeWithConfig(legacyWorkflowID, gomock.Any()).
		Return([]workflow.Data{}, nil).
		Times(1)

	// Execute
	_, err := ostest.OSWorkflow(mockInvocationCtx, []workflow.Data{})

	// Verify
	assert.NoError(t, err)
}

func TestOSWorkflow_ForceLegacyFlowWithEnvVar(t *testing.T) {
	t.Run("forces legacy flow when env var is set, even with unified flow flags", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		mockEngine := mocks.NewMockEngine(ctrl)
		mockInvocationCtx := createMockInvocationCtxWithURL(t, ctrl, mockEngine, mockServerURL)

		// Setup: set the env var and all flags that would normally trigger the unified flow
		config := mockInvocationCtx.GetConfiguration()
		config.Set(ostest.ForceLegacyCLIEnvVar, true)
		config.Set(ostest.FeatureFlagRiskScore, true)
		config.Set(ostest.FeatureFlagRiskScoreInCLI, true)
		config.Set(flags.FlagRiskScoreThreshold, 500)

		// Mock the legacy flow, which should be called despite the unified flow flags
		mockEngine.EXPECT().
			InvokeWithConfig(gomock.Any(), gomock.Any()).
			Return([]workflow.Data{}, nil).
			Times(1)

		// Execute
		_, err := ostest.OSWorkflow(mockInvocationCtx, []workflow.Data{})

		// Verify
		assert.NoError(t, err)
	})
}

// TestOSWorkflow_FlagCombinations tests various flag combinations to ensure correct routing
// between the legacy, unified, and reachability test flows.
func TestOSWorkflow_FlagCombinations(t *testing.T) {
	tests := []struct {
		name          string
		setup         func(config configuration.Configuration, mockEngine *mocks.MockEngine)
		expectedError string
	}{
		{
			name: "Risk score FFs enabled, expects unified flow (depgraph error)",
			setup: func(config configuration.Configuration, mockEngine *mocks.MockEngine) {
				config.Set(ostest.FeatureFlagRiskScore, true)
				config.Set(ostest.FeatureFlagRiskScoreInCLI, true)
				mockEngine.EXPECT().
					InvokeWithConfig(common.DepGraphWorkflowID, gomock.Any()).
					Return(nil, assert.AnError).
					Times(1) // Expect once if this path is taken
			},
			expectedError: "failed to get dependency graph",
		},
		{
			name: "Risk Score Threshold set, Risk Score FFs disabled",
			setup: func(config configuration.Configuration, _ *mocks.MockEngine) {
				config.Set(flags.FlagRiskScoreThreshold, 700)
				// Assuming ostest.FeatureFlagRiskScore is false by default
			},
			expectedError: "The feature you are trying to use is not available for your organization",
		},
		{
			name: "Risk Score Threshold set, CLI Risk Score FF disabled",
			setup: func(config configuration.Configuration, _ *mocks.MockEngine) {
				config.Set(flags.FlagRiskScoreThreshold, 700)
				config.Set(ostest.FeatureFlagRiskScore, true)
				// Assuming ostest.FeatureFlagRiskScoreInCLI is false by default
			},
			expectedError: "The feature you are trying to use is not available for your organization",
		},
		{
			name: "Risk Score Threshold set, both Risk Score FFs enabled, expects depgraph error",
			setup: func(config configuration.Configuration, mockEngine *mocks.MockEngine) {
				config.Set(flags.FlagRiskScoreThreshold, 700)
				config.Set(ostest.FeatureFlagRiskScore, true)
				config.Set(ostest.FeatureFlagRiskScoreInCLI, true)
				mockEngine.EXPECT().
					InvokeWithConfig(common.DepGraphWorkflowID, gomock.Any()).
					Return(nil, assert.AnError).
					Times(1) // Expect once if this path is taken after FFs pass
			},
			expectedError: "failed to get dependency graph",
		},
		{
			name: "SBOM reachability without feature flag",
			setup: func(config configuration.Configuration, _ *mocks.MockEngine) {
				config.Set(flags.FlagReachability, true)
				config.Set(flags.FlagSBOM, "bom.json")
				// Don't set the feature flag
			},
			expectedError: "The feature you are trying to use is not available for your organization",
		},
		{
			name: "Severity threshold set with FFs enabled, expects depgraph error",
			setup: func(config configuration.Configuration, mockEngine *mocks.MockEngine) {
				config.Set(ostest.FeatureFlagRiskScore, true)
				config.Set(ostest.FeatureFlagRiskScoreInCLI, true)
				config.Set(flags.FlagSeverityThreshold, "high")
				mockEngine.EXPECT().
					InvokeWithConfig(common.DepGraphWorkflowID, gomock.Any()).
					Return(nil, assert.AnError).
					Times(1)
			},
			expectedError: "failed to get dependency graph",
		},
		{
			name: "Severity threshold set with risk score threshold, expects depgraph error",
			setup: func(config configuration.Configuration, mockEngine *mocks.MockEngine) {
				config.Set(flags.FlagRiskScoreThreshold, 500)
				config.Set(flags.FlagSeverityThreshold, "medium")
				config.Set(ostest.FeatureFlagRiskScore, true)
				config.Set(ostest.FeatureFlagRiskScoreInCLI, true)
				mockEngine.EXPECT().
					InvokeWithConfig(common.DepGraphWorkflowID, gomock.Any()).
					Return(nil, assert.AnError).
					Times(1)
			},
			expectedError: "failed to get dependency graph",
		},
		{
			name: "Severity threshold without FFs enabled, uses legacy flow",
			setup: func(config configuration.Configuration, mockEngine *mocks.MockEngine) {
				config.Set(flags.FlagSeverityThreshold, "low")
				mockEngine.EXPECT().
					InvokeWithConfig(legacyWorkflowID, gomock.Any()).
					Return([]workflow.Data{}, nil).
					Times(1)
			},
			expectedError: "", // No error, should succeed via legacy path
		},
		{
			name: "All projects flag without FFs enabled, uses legacy flow",
			setup: func(config configuration.Configuration, mockEngine *mocks.MockEngine) {
				config.Set(flags.FlagAllProjects, true)
				mockEngine.EXPECT().
					InvokeWithConfig(legacyWorkflowID, gomock.Any()).
					Return([]workflow.Data{}, nil).
					Times(1)
			},
			expectedError: "", // No error, should succeed via legacy path
		},
		{
			name: "Only one risk score FF enabled, uses legacy flow",
			setup: func(config configuration.Configuration, mockEngine *mocks.MockEngine) {
				config.Set(ostest.FeatureFlagRiskScore, true)
				// ffRiskScoreInCLI is false by default
				mockEngine.EXPECT().
					InvokeWithConfig(gomock.Any(), gomock.Any()).
					Return([]workflow.Data{}, nil).
					Times(1)
			},
			expectedError: "", // No error, should succeed via legacy path
		},
		{
			name: "Only CLI risk score FF enabled, uses legacy flow",
			setup: func(config configuration.Configuration, mockEngine *mocks.MockEngine) {
				config.Set(ostest.FeatureFlagRiskScoreInCLI, true)
				// ffRiskScore is false by default
				mockEngine.EXPECT().
					InvokeWithConfig(gomock.Any(), gomock.Any()).
					Return([]workflow.Data{}, nil).
					Times(1)
			},
			expectedError: "", // No error, should succeed via legacy path
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			ctrl := gomock.NewController(t)
			defer ctrl.Finish()

			mockEngine := mocks.NewMockEngine(ctrl)
			mockInvocationCtx := createMockInvocationCtxWithURL(t, ctrl, mockEngine, mockServerURL)

			// Setup test case
			test.setup(mockInvocationCtx.GetConfiguration(), mockEngine)

			// Execute
			_, err := ostest.OSWorkflow(mockInvocationCtx, []workflow.Data{})

			// Verify
			if test.expectedError != "" {
				assert.Error(t, err)
				assert.Contains(t, err.Error(), test.expectedError, "Expected error to contain: %s", test.expectedError)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

// Helpers

// createMockInvocationCtx creates a mock invocation context with default values for our flags.
func createMockInvocationCtxWithURL(t *testing.T, ctrl *gomock.Controller, engine workflow.Engine, sbomServiceURL string) workflow.InvocationContext {
	t.Helper()

	mockConfig := configuration.New()
	mockConfig.Set(configuration.AUTHENTICATION_TOKEN, "<SOME API TOKEN>")
	mockConfig.Set(configuration.ORGANIZATION, uuid.New().String())
	mockConfig.Set(configuration.API_URL, sbomServiceURL)

	// Initialize with default values for our flags
	mockConfig.Set(flags.FlagRiskScoreThreshold, -1)
	mockConfig.Set(flags.FlagFile, "test-file.txt") // Add default test file

	mockLogger := zerolog.Nop()

	icontext := mocks.NewMockInvocationContext(ctrl)
	icontext.EXPECT().GetConfiguration().Return(mockConfig).AnyTimes()
	icontext.EXPECT().GetEnhancedLogger().Return(&mockLogger).AnyTimes()
	icontext.EXPECT().GetNetworkAccess().Return(networking.NewNetworkAccess(mockConfig)).AnyTimes()

	if engine != nil {
		icontext.EXPECT().GetEngine().Return(engine).AnyTimes()
	} else {
		icontext.EXPECT().GetEngine().Return(nil).AnyTimes()
	}

	// Mock network access
	mockNetwork := mocks.NewMockNetworkAccess(ctrl)
	mockNetwork.EXPECT().GetHttpClient().Return(&http.Client{}).AnyTimes()
	icontext.EXPECT().GetNetworkAccess().Return(mockNetwork).AnyTimes()

	return icontext
}

// mockAPIState holds the state for the mock API server.
type mockAPIState struct {
	t           *testing.T
	mu          sync.Mutex
	server      *httptest.Server
	jobToTestID map[string]string
	testStates  map[string]*testRunState
}

// testRunState holds the state for a single test run.
type testRunState struct {
	jobID  string
	testID string
	polls  int
}

// newMockAPIState creates a new mockAPIState.
func newMockAPIState(t *testing.T) *mockAPIState {
	t.Helper()
	s := &mockAPIState{
		t:           t,
		jobToTestID: make(map[string]string),
		testStates:  make(map[string]*testRunState),
	}
	s.server = httptest.NewServer(s)
	return s
}

// Close closes the mock server.
func (s *mockAPIState) Close() {
	s.server.Close()
}

// URL returns the mock server's URL.
func (s *mockAPIState) URL() string {
	return s.server.URL
}

// ServeHTTP is the main handler for the mock server.
func (s *mockAPIState) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	defer s.mu.Unlock()

	switch {
	case r.Method == http.MethodPost && strings.HasSuffix(r.URL.Path, "/tests"):
		s.handleCreateTest(w, r)
	case r.Method == http.MethodGet && strings.Contains(r.URL.Path, "/test_jobs/"):
		s.handlePollJob(w, r)
	case r.Method == http.MethodGet && strings.Contains(r.URL.Path, "/tests/") && !strings.HasSuffix(r.URL.Path, "/findings"):
		s.handleGetTestResult(w, r)
	case r.Method == http.MethodGet && strings.HasSuffix(r.URL.Path, "/findings"):
		s.handleGetFindings(w, r)
	default:
		http.Error(w, "unhandled request: "+r.Method+" "+r.URL.Path, http.StatusNotFound)
	}
}

func (s *mockAPIState) handleCreateTest(w http.ResponseWriter, _ *http.Request) {
	jobID := uuid.New()
	testID := uuid.New()

	state := &testRunState{
		jobID:  jobID.String(),
		testID: testID.String(),
		polls:  0,
	}
	s.jobToTestID[jobID.String()] = testID.String()
	s.testStates[testID.String()] = state

	w.Header().Set("Content-Type", "application/vnd.api+json")
	w.WriteHeader(http.StatusAccepted)
	respBody := fmt.Sprintf(`{
		"jsonapi": {"version": "1.0"},
		"data": {
			"type": "test_jobs",
			"id": "%s",
			"attributes": {"status": "pending"}
		}
	}`, jobID)
	_, err := w.Write([]byte(respBody))
	require.NoError(s.t, err)
}

func (s *mockAPIState) handlePollJob(w http.ResponseWriter, r *http.Request) {
	parts := strings.Split(r.URL.Path, "/")
	jobID := parts[len(parts)-1]
	testID, ok := s.jobToTestID[jobID]
	if !ok {
		http.Error(w, "job not found", http.StatusNotFound)
		return
	}
	state := s.testStates[testID]
	state.polls++

	if state.polls > 1 { // On second poll, redirect
		location := s.server.URL + "/orgs/some-org/tests/" + testID
		w.Header().Set("Location", location)
		w.Header().Set("Content-Type", "application/vnd.api+json")
		w.WriteHeader(http.StatusSeeOther)
		respBody := fmt.Sprintf(`{
			"jsonapi": {"version": "1.0"},
			"data": {
				"type": "test_jobs",
				"id": "%s",
				"attributes": {"status": "finished"},
				"relationships": {
					"test": {
						"data": { "type": "tests", "id": "%s" }
					}
				}
			},
			"links": { "related": "%s" }
		}`, jobID, testID, location)
		_, err := w.Write([]byte(respBody))
		require.NoError(s.t, err)
		return
	}

	w.Header().Set("Content-Type", "application/vnd.api+json")
	w.WriteHeader(http.StatusOK)
	respBody := fmt.Sprintf(`{
		"jsonapi": {"version": "1.0"},
		"data": {
			"type": "test_jobs",
			"id": "%s",
			"attributes": {"status": "pending"}
		}
	}`, jobID)
	_, err := w.Write([]byte(respBody))
	require.NoError(s.t, err)
}

func (s *mockAPIState) handleGetTestResult(w http.ResponseWriter, r *http.Request) {
	parts := strings.Split(r.URL.Path, "/")
	testID := parts[len(parts)-1]
	if _, ok := s.testStates[testID]; !ok {
		http.Error(w, "test not found", http.StatusNotFound)
		return
	}

	w.Header().Set("Content-Type", "application/vnd.api+json")
	w.WriteHeader(http.StatusOK)
	pass := testapi.Pass
	parsedTestID := uuid.MustParse(testID)
	testData := testapi.TestData{
		Id:   &parsedTestID,
		Type: testapi.TestDataTypeTests,
		Attributes: testapi.TestAttributes{
			State:            &testapi.TestState{Execution: testapi.Finished},
			Outcome:          &testapi.TestOutcome{Result: pass},
			RawSummary:       &testapi.FindingSummary{Count: 0},
			EffectiveSummary: &testapi.FindingSummary{Count: 0},
			Subject:          testapi.TestSubject{},
		},
	}
	err := json.NewEncoder(w).Encode(struct {
		Data    testapi.TestData               `json:"data"`
		Jsonapi testapi.IoSnykApiCommonJsonApi `json:"jsonapi"`
	}{Data: testData, Jsonapi: testapi.IoSnykApiCommonJsonApi{Version: "1.0"}})
	require.NoError(s.t, err)
}

func (s *mockAPIState) handleGetFindings(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "application/vnd.api+json")
	w.WriteHeader(http.StatusOK)
	_, err := w.Write([]byte(`{"jsonapi":{"version":"1.0"},"data":[]}`))
	require.NoError(s.t, err)
}

// TestOSWorkflow_AllProjects_UnifiedFlow tests the behavior of the OS workflow
// when the --all-projects flag is used with the unified test flow.
// It verifies that multiple dependency graphs are processed and their results are aggregated.
func TestOSWorkflow_AllProjects_UnifiedFlow(t *testing.T) {
	// Setup
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockAPI := newMockAPIState(t)
	defer mockAPI.Close()

	mockEngine := mocks.NewMockEngine(ctrl)
	mockInvocationCtx := createMockInvocationCtxWithURL(t, ctrl, mockEngine, mockAPI.URL())

	// Configure for --all-projects and unified flow
	config := mockInvocationCtx.GetConfiguration()
	config.Set(ostest.FeatureFlagRiskScore, true)
	config.Set(ostest.FeatureFlagRiskScoreInCLI, true)
	config.Set(flags.FlagAllProjects, true)

	// Temporarily reduce the poll interval for this test to avoid timeouts.
	originalPollInterval := ostest.PollInterval
	ostest.PollInterval = testapi.MinPollInterval
	t.Cleanup(func() { ostest.PollInterval = originalPollInterval })

	// Mock depgraph workflow to return two depgraphs
	depGraph1Bytes, err := json.Marshal(testapi.IoSnykApiV1testdepgraphRequestDepGraph{
		SchemaVersion: "1.2.0",
		PkgManager:    testapi.IoSnykApiV1testdepgraphRequestPackageManager{Name: "npm"},
		Pkgs: []testapi.IoSnykApiV1testdepgraphRequestPackage{
			{Id: "proj1@1.0.0", Info: testapi.IoSnykApiV1testdepgraphRequestPackageInfo{Name: "proj1", Version: "1.0.0"}},
		},
		Graph: testapi.IoSnykApiV1testdepgraphRequestGraph{
			RootNodeId: "root",
			Nodes: []testapi.IoSnykApiV1testdepgraphRequestNode{
				{NodeId: "root", PkgId: "proj1@1.0.0", Deps: []testapi.IoSnykApiV1testdepgraphRequestNodeRef{}},
			},
		},
	})
	require.NoError(t, err)
	depGraph2Bytes, err := json.Marshal(testapi.IoSnykApiV1testdepgraphRequestDepGraph{
		SchemaVersion: "1.2.0",
		PkgManager:    testapi.IoSnykApiV1testdepgraphRequestPackageManager{Name: "maven"},
		Pkgs: []testapi.IoSnykApiV1testdepgraphRequestPackage{
			{Id: "proj2@2.0.0", Info: testapi.IoSnykApiV1testdepgraphRequestPackageInfo{Name: "proj2", Version: "2.0.0"}},
		},
		Graph: testapi.IoSnykApiV1testdepgraphRequestGraph{
			RootNodeId: "root",
			Nodes: []testapi.IoSnykApiV1testdepgraphRequestNode{
				{NodeId: "root", PkgId: "proj2@2.0.0", Deps: []testapi.IoSnykApiV1testdepgraphRequestNodeRef{}},
			},
		},
	})
	require.NoError(t, err)

	mockData1 := mocks.NewMockData(ctrl)
	mockData1.EXPECT().GetPayload().Return(depGraph1Bytes).AnyTimes()
	mockData1.EXPECT().GetMetaData(common.ContentLocationKey).Return("proj1/package.json", nil).AnyTimes()

	mockData2 := mocks.NewMockData(ctrl)
	mockData2.EXPECT().GetPayload().Return(depGraph2Bytes).AnyTimes()
	mockData2.EXPECT().GetMetaData(common.ContentLocationKey).Return("proj2/pom.xml", nil).AnyTimes()

	depGraphs := []workflow.Data{mockData1, mockData2}

	mockEngine.EXPECT().
		InvokeWithConfig(common.DepGraphWorkflowID, gomock.Any()).
		Return(depGraphs, nil).
		Times(1)

	// Execute
	results, err := ostest.OSWorkflow(mockInvocationCtx, []workflow.Data{})

	// Verify
	require.NoError(t, err)
	require.NotEmpty(t, results)

	var jsonOutputs []workflow.Data
	var summaryOutputs []workflow.Data
	for _, r := range results {
		if r.GetContentType() == ostest.ApplicationJSONContentType {
			jsonOutputs = append(jsonOutputs, r)
		} else if r.GetContentType() == content_type.TEST_SUMMARY {
			summaryOutputs = append(summaryOutputs, r)
		}
	}

	// Should have 1 JSON output (as an array of results) and 0 summary outputs (since there are no findings)
	assert.Len(t, jsonOutputs, 1)
	assert.Len(t, summaryOutputs, 0)

	// Verify JSON output is an array of 2 results
	var legacyResults []definitions.LegacyVulnerabilityResponse
	payload, ok := jsonOutputs[0].GetPayload().([]byte)
	require.True(t, ok, "Payload is not of type []byte")
	unmarshalErr := json.Unmarshal(payload, &legacyResults)
	require.NoError(t, unmarshalErr, "Failed to unmarshal legacy vulnerability responses")
	assert.Len(t, legacyResults, 2)

	// The order is not guaranteed, so we check for presence
	projectNames := []string{legacyResults[0].ProjectName, legacyResults[1].ProjectName}
	assert.Contains(t, projectNames, "proj1")
	assert.Contains(t, projectNames, "proj2")
}
