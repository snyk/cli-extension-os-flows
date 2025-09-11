package settings

import "github.com/google/uuid"

// Type aliases for better readability and type safety.
type (
	// OrgID represents a Snyk OrgID.
	OrgID = uuid.UUID
)

// ResponseReachability contains reachability settings from the API response.
type ResponseReachability struct {
	Enabled bool `json:"enabled"`
}

// ResponseAttributes contains the attributes from a reachability settings response.
type ResponseAttributes struct {
	Reachability ResponseReachability `json:"reachability"`
}

// ResponseData contains the data from a reachability settings response.
type ResponseData struct {
	Attributes ResponseAttributes `json:"attributes"`
}

// ResponseBody is the top-level response body for reachability settings.
type ResponseBody struct {
	Data ResponseData `json:"data"`
}
