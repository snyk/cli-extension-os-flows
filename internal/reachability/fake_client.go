package reachability

import (
	"context"
	"errors"
)

type FakeReachabilityClient struct {
	id       ID
	startErr error
	waitErr  error
}

var _ Client = (*FakeReachabilityClient)(nil)

func (f *FakeReachabilityClient) WithStartErr(err error) {
	f.startErr = err
}

func (f *FakeReachabilityClient) WithWaitErr(err error) {
	f.waitErr = err
}

func NewFakeClient(reachabilityID ID) *FakeReachabilityClient {
	return &FakeReachabilityClient{id: reachabilityID}
}

func (f *FakeReachabilityClient) StartReachabilityAnalysis(ctx context.Context, orgID OrgID, revisionID RevisionID) (ID, error) {
	return f.id, f.startErr
}

func (f *FakeReachabilityClient) WaitForReachabilityAnalysis(ctx context.Context, orgID OrgID, reachabilityID ID) error {
	if f.id == reachabilityID {
		return f.waitErr
	}
	return errors.New("unknown reachability id")
}
