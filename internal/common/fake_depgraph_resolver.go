package service

import "github.com/snyk/go-application-framework/pkg/workflow"

type fakeDepgraphResolver struct {
	depgraphs []DepgraphWithIdentity
	err       error
}

// NewFakeDepgraphResolver creates a new FakeDepgraphResolver.
func NewFakeDepgraphResolver(depgraphs []DepgraphWithIdentity, err error) DepgraphResolver {
	return &fakeDepgraphResolver{depgraphs, err}
}

func (fdr *fakeDepgraphResolver) GetDepGraphsWithIdentity(ictx workflow.InvocationContext, inputDir string) ([]DepgraphWithIdentity, error) {
	if fdr.err != nil {
		return nil, fdr.err
	}

	return fdr.depgraphs, nil
}
