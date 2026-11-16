package osmonitor

import (
	"context"
	"strings"

	"github.com/google/uuid"
	"github.com/snyk/go-application-framework/pkg/apiclients/testapi"
	"github.com/snyk/go-application-framework/pkg/configuration"
	"github.com/snyk/go-application-framework/pkg/utils/ufm"
	"github.com/snyk/go-application-framework/pkg/workflow"

	"github.com/snyk/cli-extension-os-flows/internal/commands/cmdctx"
	"github.com/snyk/cli-extension-os-flows/internal/commands/ostest"
	"github.com/snyk/cli-extension-os-flows/internal/common"
)

const (
	monitorSeparator     = "\n-------------------------------------------------------\n"
	monitorNotifications = "Notifications about newly disclosed issues related to these dependencies will be emailed to you.\n"
)

type monitoredProject struct {
	path      string
	name      string
	projectID *uuid.UUID
}

// recordingDepgraphResolver keeps the dep graphs it resolves, so each monitored project can be
// printed after the test has run.
type recordingDepgraphResolver struct {
	common.DepgraphResolver
	depGraphs []common.DepgraphWithIdentity
}

func (r *recordingDepgraphResolver) GetDepGraphsWithIdentity(
	ictx workflow.InvocationContext,
	inputDir string,
) ([]common.DepgraphWithIdentity, error) {
	depGraphs, err := r.DepgraphResolver.GetDepGraphsWithIdentity(ictx, inputDir)
	r.depGraphs = depGraphs
	//nolint:wrapcheck // The recorder is transparent; the flow wraps the resolver's error.
	return depGraphs, err
}

func monitoredProjects(inputDir string, depGraphs []common.DepgraphWithIdentity, wfData []workflow.Data) []monitoredProject {
	projectIDs := componentProjectIDs(wfData)
	projects := make([]monitoredProject, 0, len(depGraphs))
	for _, dg := range depGraphs {
		projects = append(projects, monitoredProject{
			path:      inputDir,
			name:      projectName(dg),
			projectID: projectIDs[componentKey(dg.Identity)],
		})
	}
	return projects
}

func componentProjectIDs(wfData []workflow.Data) map[string]*uuid.UUID {
	projectIDs := map[string]*uuid.UUID{}
	for _, data := range wfData {
		for _, result := range ufm.GetTestResultsFromWorkflowData(data) {
			components, ok := result.Get(testapi.TestResultComponents).(*[]testapi.TestComponent)
			if !ok || components == nil {
				continue
			}
			for _, component := range *components {
				if component.ProjectId != nil {
					projectIDs[component.Key] = component.ProjectId
				}
			}
		}
	}
	return projectIDs
}

// componentKey mirrors how sca-engine keys a test component by its identity
// (componentIDFromIdentity), so a component can be matched to the dep graph it came from.
func componentKey(identity common.Identity) string {
	projectType := identity.Type
	if projectType == "" {
		projectType = "unknown"
	}

	discriminator := "unidentified-project"
	switch {
	case identity.TargetFile != "":
		discriminator = identity.TargetFile
	case identity.Name != "":
		discriminator = identity.Name
	}

	key := projectType + ":" + discriminator
	if identity.TargetRuntime != nil && *identity.TargetRuntime != "" {
		key += ":" + *identity.TargetRuntime
	}
	return key
}

// projectName is the name legacy monitor prints: the dep graph's root package.
func projectName(dg common.DepgraphWithIdentity) string {
	if dg.DepGraph != nil {
		if root := dg.DepGraph.GetRootPkg(); root != nil && root.Info.Name != "" {
			return root.Info.Name
		}
	}
	return dg.Identity.Name
}

func monitorOutputData(ctx context.Context, projects []monitoredProject) workflow.Data {
	cfg := cmdctx.Config(ctx)
	progressBar := cmdctx.ProgressBar(ctx)

	//nolint:errcheck // We don't need to fail the command due to UI errors.
	progressBar.Clear()

	orgSlugOrID := cfg.GetString(configuration.ORGANIZATION_SLUG)
	if orgSlugOrID == "" {
		orgSlugOrID = cfg.GetString(configuration.ORGANIZATION)
	}
	appURL := strings.TrimSuffix(cfg.GetString(configuration.WEB_APP_URL), "/")

	return ostest.NewWorkflowData("text/plain", []byte(formatMonitorOutput(projects, appURL, orgSlugOrID)))
}

func formatMonitorOutput(projects []monitoredProject, appURL, orgSlugOrID string) string {
	blocks := make([]string, 0, len(projects))
	for _, project := range projects {
		humanReadableName := project.path
		if project.name != "" {
			humanReadableName += " (" + project.name + ")"
		}

		var block strings.Builder
		block.WriteString("\nMonitoring " + humanReadableName + "...\n\n")
		if project.projectID != nil {
			block.WriteString("Explore this snapshot at " + appURL + "/org/" + orgSlugOrID + "/project/" + project.projectID.String() + "\n\n")
		}
		block.WriteString(monitorNotifications)
		blocks = append(blocks, block.String())
	}
	return strings.Join(blocks, "\n"+monitorSeparator)
}
