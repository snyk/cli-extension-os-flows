package transform_test

import (
	"testing"
	"time"

	testapiinline "github.com/snyk/cli-extension-os-flows/internal/util/testapi"

	"github.com/snyk/cli-extension-os-flows/internal/legacy/transform"

	"github.com/snyk/cli-extension-os-flows/internal/legacy/definitions"

	"github.com/google/uuid"
	"github.com/rs/zerolog"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/snyk/go-application-framework/pkg/apiclients/testapi"
	"github.com/snyk/go-application-framework/pkg/utils"

	"github.com/snyk/cli-extension-os-flows/internal/util/testfactories"
)

func Test_projectLevelIgnore(t *testing.T) {
	relationship := testfactories.NewShimPolicyRelationship(func(rel *testapiinline.PolicyRelationship) {
		rel.Data.Id = uuid.MustParse("e4c284d4-a75e-4ec5-b5d0-d2d14f8fa48e")
		rel.Data.Attributes.Policies = []testapi.Policy{
			{
				Id: uuid.MustParse("00000000-dead-beef-0000-000000000000"),
				AppliedPolicy: testfactories.NewAppliedPolicyFromIgnore(t, func(ignore *testapi.Ignore) {
					ignore.Ignore.Reason = "the ignore reason"
					ignore.Ignore.ReasonType = utils.Ptr(testapi.NotVulnerable)
					ignore.Ignore.Source = "api"
					ignore.Ignore.Path = utils.Ptr([]string{"*"})
					ignore.Ignore.Created = utils.Ptr(mustBeTime(t, "2025-08-28T07:35:48.637Z"))
					ignore.Ignore.Expires = utils.Ptr(mustBeTime(t, "2025-11-05T23:00:00.000Z"))
					ignore.Ignore.DisregardIfFixable = utils.Ptr(false)
					ignore.Ignore.IgnoredBy = &testapi.IgnoredBy{
						Id:    uuid.MustParse("ea77548d-5444-407b-8d03-85d8bf5b8146"),
						Name:  "Test User",
						Email: utils.Ptr("test.user@example.com"),
					}
				}),
			},
		}
	})

	vuln := definitions.Vulnerability{}
	transform.ProcessPolicyRelationshipsForVuln(&vuln, relationship, utils.Ptr(zerolog.Nop()))

	require.NotNil(t, vuln.IsIgnored)
	assert.True(t, *vuln.IsIgnored)
	assert.Nil(t, vuln.AppliedPolicyRules)
	require.NotNil(t, vuln.Filtered)
	require.NotNil(t, vuln.Filtered.Ignored)
	require.Len(t, *vuln.Filtered.Ignored, 1)

	ignored := (*vuln.Filtered.Ignored)[0]
	assert.Equal(t, "the ignore reason", ignored.Reason)
	assert.Equal(t, "not-vulnerable", ignored.ReasonType)
	assert.Equal(t, "api", ignored.Source)
	assert.Equal(t, "2025-08-28T07:35:48.637Z", ignored.Created)
	assert.Equal(t, "2025-11-05T23:00:00Z", ignored.Expires)
	assert.Equal(t, false, ignored.DisregardIfFixable)

	require.Len(t, ignored.Path, 1)
	assert.Equal(t, "*", ignored.Path[0]["module"])

	assert.Equal(t, "ea77548d-5444-407b-8d03-85d8bf5b8146", ignored.IgnoredBy.Id)
	assert.Equal(t, "Test User", ignored.IgnoredBy.Name)
	assert.Equal(t, "test.user@example.com", ignored.IgnoredBy.Email)
	assert.Equal(t, false, ignored.IgnoredBy.IsGroupPolicy)
}

func mustBeTime(t *testing.T, str string) time.Time {
	t.Helper()
	parsed, err := time.Parse(time.RFC3339Nano, str)
	require.NoError(t, err)
	return parsed
}
