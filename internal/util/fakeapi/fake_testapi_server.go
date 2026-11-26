// Package fakeapi provides HTTP fakes of Snyk APIs for workflow tests.
package fakeapi

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/google/uuid"
	"github.com/snyk/go-application-framework/pkg/apiclients/testapi"
	"github.com/stretchr/testify/require"
)

// TestAPIServer is an in-process fake of the Test API, upload revisions and settings endpoints that records create-test request bodies.
type TestAPIServer struct {
	t                *testing.T
	mu               sync.Mutex
	server           *httptest.Server
	jobToTestID      map[string]string
	testStates       map[string]*testRunState
	createTestBodies [][]byte
}

// testRunState holds the state for a single test run.
type testRunState struct {
	jobID  string
	testID string
	polls  int
}

// NewTestAPIServer starts a TestAPIServer.
func NewTestAPIServer(t *testing.T) *TestAPIServer {
	t.Helper()
	s := &TestAPIServer{
		t:           t,
		jobToTestID: make(map[string]string),
		testStates:  make(map[string]*testRunState),
	}
	s.server = httptest.NewServer(s)
	return s
}

// Close shuts the server down.
func (s *TestAPIServer) Close() {
	s.server.Close()
}

// URL returns the server's base URL.
func (s *TestAPIServer) URL() string {
	return s.server.URL
}

// CreateTestBodies returns the raw bodies of the create-test requests received so far.
func (s *TestAPIServer) CreateTestBodies() [][]byte {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.createTestBodies
}

// ServeHTTP routes requests to the fake endpoints.
func (s *TestAPIServer) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	defer s.mu.Unlock()

	switch {
	case r.Method == http.MethodPost && strings.HasSuffix(r.URL.Path, "/tests"):
		s.handleCreateTest(w, r)
	case strings.Contains(r.URL.Path, "/upload_revisions"):
		s.handleUploadRevision(w, r)
	case r.Method == http.MethodGet && strings.Contains(r.URL.Path, "/test_jobs/"):
		s.handlePollJob(w, r)
	case r.Method == http.MethodGet && strings.Contains(r.URL.Path, "/tests/") && !strings.HasSuffix(r.URL.Path, "/findings"):
		s.handleGetTestResult(w, r)
	case r.Method == http.MethodGet && strings.HasSuffix(r.URL.Path, "/findings"):
		s.handleGetFindings(w, r)
	case r.Method == http.MethodGet && strings.Contains(r.URL.Path, "/settings/opensource"):
		s.handleGetSettings(w, r)
	default:
		http.Error(w, "unhandled request: "+r.Method+" "+r.URL.Path, http.StatusNotFound)
	}
}

func (s *TestAPIServer) handleGetSettings(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "application/vnd.api+json")
	w.WriteHeader(http.StatusOK)
	respBody := `{
			"jsonapi": {"version": "1.0"},
			"data": {
				"type": "opensource_settings",
				"attributes": {
					"reachability": {
						"enabled": true
					}
				}
			}
		}`
	_, err := w.Write([]byte(respBody))
	require.NoError(s.t, err)
}

func (s *TestAPIServer) handleUploadRevision(w http.ResponseWriter, r *http.Request) {
	status, sealed := http.StatusCreated, false
	switch {
	case strings.HasSuffix(r.URL.Path, "/files"):
		w.WriteHeader(http.StatusNoContent)
		return
	case r.Method == http.MethodPatch:
		status, sealed = http.StatusOK, true
	}

	w.Header().Set("Content-Type", "application/vnd.api+json")
	w.WriteHeader(status)
	_, err := fmt.Fprintf(w, `{"data":{"id":"%s","type":"upload_revision","attributes":{"revision_type":"snapshot","sealed":%t}}}`, uuid.New(), sealed)
	require.NoError(s.t, err)
}

func (s *TestAPIServer) handleCreateTest(w http.ResponseWriter, r *http.Request) {
	body, err := io.ReadAll(r.Body)
	require.NoError(s.t, err)
	s.createTestBodies = append(s.createTestBodies, body)

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
	_, err = w.Write([]byte(respBody))
	require.NoError(s.t, err)
}

func (s *TestAPIServer) handlePollJob(w http.ResponseWriter, r *http.Request) {
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

func (s *TestAPIServer) handleGetTestResult(w http.ResponseWriter, r *http.Request) {
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
			State:            &testapi.TestState{Execution: testapi.TestExecutionStatesFinished},
			Outcome:          &testapi.TestOutcome{Result: pass},
			RawSummary:       &testapi.FindingSummary{Count: 0},
			EffectiveSummary: &testapi.FindingSummary{Count: 0},
			Subject:          &testapi.TestSubject{},
		},
	}
	err := json.NewEncoder(w).Encode(struct {
		Data    testapi.TestData               `json:"data"`
		Jsonapi testapi.IoSnykApiCommonJsonApi `json:"jsonapi"`
	}{Data: testData, Jsonapi: testapi.IoSnykApiCommonJsonApi{Version: "1.0"}})
	require.NoError(s.t, err)
}

func (s *TestAPIServer) handleGetFindings(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "application/vnd.api+json")
	w.WriteHeader(http.StatusOK)
	_, err := w.Write([]byte(`{"jsonapi":{"version":"1.0"},"data":[]}`))
	require.NoError(s.t, err)
}
