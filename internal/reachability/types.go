//nolint:tagliatelle // We must match API spec.
package reachability

import "github.com/google/uuid"

// Type aliases for better readability and type safety.
type (
	// OrgID represents a Snyk OrgID.
	OrgID = uuid.UUID
	// BundleHash represents a unique identifier for a code bundle.
	BundleHash = string
	// ID represents a unique identifier for a reachability analysis.
	ID = uuid.UUID
)

// ResourceType represents the type of resource in API requests.
type ResourceType string

// ResourceTypeReachability is the resource type used for reachability analysis requests.
const ResourceTypeReachability ResourceType = "reachability"

// StartReachabilityAttributes contains the attributes needed to start a reachability analysis.
type StartReachabilityAttributes struct {
	BundleID string `json:"bundle_id"`
}

// StartReachabilityRequestData contains the data payload for starting a reachability analysis.
type StartReachabilityRequestData struct {
	Type       ResourceType                `json:"type"`
	Attributes StartReachabilityAttributes `json:"attributes"`
}

// StartReachabilityRequestBody is the top-level request body for starting a reachability analysis.
type StartReachabilityRequestBody struct {
	Data StartReachabilityRequestData `json:"data"`
}

// StartReachabilityResponseData contains the response data when starting a reachability analysis.
type StartReachabilityResponseData struct {
	ID ID `json:"id"`
}

// StartReachabilityResponseBody is the top-level response body when starting a reachability analysis.
type StartReachabilityResponseBody struct {
	Data StartReachabilityResponseData `json:"data"`
}

// ScanStatus represents the status of a reachability analysis scan.
type ScanStatus string

// Reachability scan status constants.
const (
	// ScanStatusDone indicates the reachability analysis has completed successfully.
	ScanStatusDone ScanStatus = "done"
	// ScanStatusFailed indicates the reachability analysis has failed.
	ScanStatusFailed ScanStatus = "failed"
	// ScanStatusInProgress indicates the reachability analysis is currently running.
	ScanStatusInProgress ScanStatus = "in_progress"
	// ScanStatusTimeout indicates the reachability analysis has timed out.
	ScanStatusTimeout ScanStatus = "timeout"
	// ScanStatusUnknown indicates the reachability analysis status is unknown.
	ScanStatusUnknown ScanStatus = "unknown"
)

// GetReachabilityResponseAttributes contains the attributes from a reachability status response.
type GetReachabilityResponseAttributes struct {
	Status ScanStatus `json:"status"`
}

// GetReachabilityResponseData contains the response data when getting reachability analysis status.
type GetReachabilityResponseData struct {
	Attributes GetReachabilityResponseAttributes `json:"attributes"`
}

// GetReachabilityResponseBody is the top-level response body when getting reachability analysis status.
type GetReachabilityResponseBody struct {
	Data GetReachabilityResponseData `json:"data"`
}
