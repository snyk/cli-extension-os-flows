package ostest_test

import (
	"encoding/json"
	"testing"

	"github.com/golang/mock/gomock"
	"github.com/snyk/cli-extension-os-flows/internal/commands/cmdctx"
	"github.com/snyk/cli-extension-os-flows/internal/commands/ostest"
	common "github.com/snyk/cli-extension-os-flows/internal/common"
	"github.com/snyk/cli-extension-os-flows/internal/fileupload"
	"github.com/snyk/go-application-framework/pkg/apiclients/testapi"
	"github.com/snyk/go-application-framework/pkg/configuration"
	gafmocks "github.com/snyk/go-application-framework/pkg/mocks"
	"github.com/snyk/go-application-framework/pkg/workflow"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func Test_RunDflyDepgraphFlow(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	ffc := fileupload.NewFakeClient()
	mockEngine := gafmocks.NewMockEngine(ctrl)
	mockIctx := gafmocks.NewMockInvocationContext(ctrl)
	mockIctx.EXPECT().GetEngine().Return(mockEngine).AnyTimes()
	cfg := configuration.New()
	mockIctx.EXPECT().GetConfiguration().Return(cfg).AnyTimes()
	mockIctx.EXPECT().GetEnhancedLogger().Return(&nopLogger).AnyTimes()

	d := gafmocks.NewMockData(ctrl)
	dg := testapi.IoSnykApiV1testdepgraphRequestDepGraph{
		SchemaVersion: "1.2.0",
		PkgManager:    testapi.IoSnykApiV1testdepgraphRequestPackageManager{Name: "npm"},
		Pkgs: []testapi.IoSnykApiV1testdepgraphRequestPackage{
			{Id: "proj@1.0.0", Info: testapi.IoSnykApiV1testdepgraphRequestPackageInfo{Name: "proj", Version: "1.0.0"}},
		},
		Graph: testapi.IoSnykApiV1testdepgraphRequestGraph{RootNodeId: "root"},
	}
	bytes, err := json.Marshal(dg)
	require.NoError(t, err)

	d.EXPECT().GetPayload().Return(bytes).AnyTimes()
	d.EXPECT().GetMetaData(common.NormalisedTargetFileKey).Return("proj/package.json", nil).AnyTimes()
	d.EXPECT().GetMetaData(common.TargetFileFromPluginKey).Return("proj/package.json", nil).AnyTimes()
	d.EXPECT().GetMetaData(common.TargetKey).Return("{}", nil).AnyTimes()

	depGraphDatas := []workflow.Data{d}
	mockEngine.EXPECT().InvokeWithConfig(common.DepGraphWorkflowID, gomock.Any()).Return(depGraphDatas, nil).Times(1)

	ctx := t.Context()
	ctx = cmdctx.WithIctx(ctx, mockIctx)
	ctx = cmdctx.WithLogger(ctx, &nopLogger)
	ctx = cmdctx.WithProgressBar(ctx, &nopProgressBar)

	err = ostest.RunDflyDepgraphFlow(ctx, ".", ffc)
	require.NoError(t, err)

	assert.Equal(t, 1, ffc.GetUploadCount())
	paths := ffc.GetRevisionPaths(ffc.GetLastRevisionID())
	require.Len(t, paths, 1)
	assert.Contains(t, paths[0], "snyk-depgraph-")
}
