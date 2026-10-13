package presenters_test

import (
	"testing"

	"github.com/snyk/go-application-framework/pkg/apiclients/testapi"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/snyk/cli-extension-os-flows/internal/presenters"
	"github.com/snyk/cli-extension-os-flows/internal/util"
)

func TestGroupFindingsByComponent(t *testing.T) {
	findingWithKey := func(key string) testapi.FindingData {
		return testapi.FindingData{Attributes: &testapi.FindingAttributes{ComponentKey: util.Ptr(key)}}
	}
	findingWithoutKey := func() testapi.FindingData {
		return testapi.FindingData{Attributes: &testapi.FindingAttributes{}}
	}

	t.Run("empty input returns a single flat group", func(t *testing.T) {
		groups := presenters.GroupFindingsByComponent(nil)
		require.Len(t, groups, 1)
		assert.Empty(t, groups[0].Component)
		assert.Empty(t, groups[0].Findings)
	})

	t.Run("a single distinct component renders as a flat group", func(t *testing.T) {
		findings := []testapi.FindingData{findingWithKey("comp-a"), findingWithKey("comp-a")}
		groups := presenters.GroupFindingsByComponent(findings)
		require.Len(t, groups, 1)
		assert.Empty(t, groups[0].Component, "fewer than two components should not surface a header")
		assert.Equal(t, findings, groups[0].Findings)
	})

	t.Run("findings without a component key render as a flat group", func(t *testing.T) {
		findings := []testapi.FindingData{findingWithoutKey(), findingWithoutKey()}
		groups := presenters.GroupFindingsByComponent(findings)
		require.Len(t, groups, 1)
		assert.Empty(t, groups[0].Component)
	})

	t.Run("multiple components are grouped in first-seen order", func(t *testing.T) {
		findings := []testapi.FindingData{
			findingWithKey("comp-b"),
			findingWithKey("comp-a"),
			findingWithKey("comp-b"),
		}
		groups := presenters.GroupFindingsByComponent(findings)
		require.Len(t, groups, 2)
		assert.Equal(t, "comp-b", groups[0].Component)
		assert.Len(t, groups[0].Findings, 2)
		assert.Equal(t, "comp-a", groups[1].Component)
		assert.Len(t, groups[1].Findings, 1)
	})

	t.Run("keyless findings form an empty-component group alongside keyed components", func(t *testing.T) {
		findings := []testapi.FindingData{
			findingWithKey("comp-a"),
			findingWithoutKey(),
			findingWithKey("comp-b"),
		}
		groups := presenters.GroupFindingsByComponent(findings)
		require.Len(t, groups, 3)
		assert.Equal(t, "comp-a", groups[0].Component)
		assert.Empty(t, groups[1].Component)
		assert.Equal(t, "comp-b", groups[2].Component)
	})
}
