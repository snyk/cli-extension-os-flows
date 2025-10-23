package settings

import "context"

type FakeClient struct {
	results map[OrgID]struct {
		IsEnabled bool
		Err       error
	}
}

// IsReachabilityEnabled implements Client.
func (f *FakeClient) IsReachabilityEnabled(ctx context.Context, orgID OrgID) (bool, error) {
	return f.results[orgID].IsEnabled, f.results[orgID].Err
}

var _ Client = (*FakeClient)(nil)

func NewFakeClient(
	results map[OrgID]struct {
		IsEnabled bool
		Err       error
	},
) *FakeClient {
	return &FakeClient{results}
}
