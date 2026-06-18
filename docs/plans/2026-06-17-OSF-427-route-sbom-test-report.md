# OSF-427: Route `snyk sbom test --report` to cli-extension-os-flows Implementation Plan

> REQUIRED SUB-SKILL: Use the executing-plans skill to implement this plan task-by-task.

**Goal:** Route `snyk sbom test --report` through `cli-extension-os-flows` (Dragonfly), require `--asset-name` and `--file`, run as a stateful test (`publish_report=true`), and remove the now-superseded `snyk monitor --sbom=…` Dragonfly entrypoint.

**Architecture:** Reuse the existing `common.RunSbomFlow` (already supports `publishReport *bool`) but invoke it from the `ostest` workflow when `--sbom` and `--report` are both set and the `rollout-dfly-sbom-monitor` FF is enabled. Add new `--report` and `--asset-name` flags to `OSTestFlagSet`, validate them up-front (before any Test API call), thread `--asset-name` into `TestConfiguration` (via the GAF field once it lands), and delete `osmonitor.RunSbomMonitorFlow` plus its entrypoint in `osmonitor/workflow.go`.

**Tech Stack:** Go, `pflag`, `github.com/snyk/go-application-framework` (GAF) `testapi`, `gomock`, `testify`, `go-snaps`, `golangci-lint`.

**Branch:** `OSF-427-route-sbom-test-report` off `main`.

**Skipped per request:** The "Please update [the acceptance test](https://github.com/snyk/cli/pull/6870)" step from the ticket — no `snyk/cli` PR changes are part of this plan.

---

## Pre-flight

### Task 0: Branch setup

**Files:** _none_

**Step 1: Confirm clean tree**

Run: `git status`
Expected: working tree clean, on `main`.

**Step 2: Create and switch to the feature branch**

```bash
git checkout -b OSF-427-route-sbom-test-report
```

**Step 3: Sanity-check baseline test suite**

Run: `make test` (or `go test ./...`)
Expected: ALL PASS — confirms a green starting point before any TDD work.

---

## Phase 1 — Surface the new flags

### Task 1: Add `--report` flag to `OSTestFlagSet`

**Files:**

- Modify: `pkg/flags/flags.go`
- Test: `pkg/flags/flags_test.go`

**Step 1: Write the failing test**

In `flags_test.go`, add a sub-test (or extend the existing flag-presence test) that asserts `OSTestFlagSet().Lookup("report")` returns a non-nil bool flag with default `false` and a non-empty usage string. Mirror the existing pattern used for `FlagReachability`.

**Step 2: Run the test to verify it fails**

Run: `go test ./pkg/flags/...`
Expected: FAIL — `report` flag missing.

**Step 3: Add the flag**

In `pkg/flags/flags.go`:

- Add the constant: `FlagReport = "report"` near the other Open Source flags.
- In `OSTestFlagSet()`, register: `flagSet.Bool(FlagReport, false, "Persist the test result as a stateful report (snapshot) in Snyk.")`.

Do NOT add `--report` to `OSMonitorFlagSet()` — `report` is a `test`-only flag.

**Step 4: Run ALL tests**

Run: `go test ./...`
Expected: ALL PASS.

**Step 5: Refactor**

Skim `OSTestFlagSet()` for an opportunity to group the new `--report` flag near other test-output-affecting flags. Use the @refactoring skill if anything substantial emerges; otherwise leave as-is.

**Step 6: Run ALL tests**

Run: `go test ./...`
Expected: ALL PASS.

**Step 7: Commit**

```bash
git add pkg/flags/flags.go pkg/flags/flags_test.go
git commit -m "feat(flags): add --report flag to OS test flagset"
```

---

### Task 2: Add `--asset-name` flag to `OSTestFlagSet`

**Files:**

- Modify: `pkg/flags/flags.go`
- Test: `pkg/flags/flags_test.go`

**Step 1: Write the failing test**

Add a sub-test asserting `OSTestFlagSet().Lookup("asset-name")` returns a non-nil string flag with empty default and a non-empty usage string.

**Step 2: Run the test to verify it fails**

Run: `go test ./pkg/flags/...`
Expected: FAIL.

**Step 3: Add the flag**

In `pkg/flags/flags.go`:

- Add the constant: `FlagAssetName = "asset-name"`.
- In `OSTestFlagSet()`, register: `flagSet.String(FlagAssetName, "", "Required when running --sbom test --report. Identifies the asset under which the snapshot is stored.")`.

**Step 4: Run ALL tests**

Run: `go test ./...`
Expected: ALL PASS.

**Step 5: Refactor**

None expected.

**Step 6: Run ALL tests**

Run: `go test ./...`
Expected: ALL PASS.

**Step 7: Commit**

```bash
git add pkg/flags/flags.go pkg/flags/flags_test.go
git commit -m "feat(flags): add --asset-name flag to OS test flagset"
```

---

## Phase 2 — Validation (mandatory `--asset-name` and `--file`)

These steps add validation that fires _before any Test API call_ (per the AC). The validation must only kick in for the `sbom test --report` path; we keep regular `snyk test` and `snyk sbom test` (no `--report`) untouched.

### Task 3: Add a typed error for missing `--asset-name`

**Files:**

- Modify: `internal/errors/errors.go`
- Test: `internal/errors/errors_test.go`

**Step 1: Write the failing test**

In `errors_test.go`, add `TestErrorFactory_NewMissingAssetNameError` asserting that the returned error wraps a sensible internal cause and the user-facing message contains both `--asset-name` and a hint that it is required for `sbom test --report`.

**Step 2: Run the test to verify it fails**

Run: `go test ./internal/errors/...`
Expected: FAIL.

**Step 3: Add the factory method**

In `errors.go`, add:

```go
// NewMissingAssetNameError creates an error for when --asset-name is required but missing.
func (ef *ErrorFactory) NewMissingAssetNameError() *OSFlowsExtensionError {
    return ef.newErr(
        fmt.Errorf("asset-name flag not set"),
        "Flag `--asset-name` is required when running `snyk sbom test --report`.",
    )
}
```

(Reuse `NewMissingFilenameFlagError` for `--file`; no new error needed there.)

**Step 4: Run ALL tests**

Run: `go test ./...`
Expected: ALL PASS.

**Step 5: Refactor**

None expected.

**Step 6: Run ALL tests**

Run: `go test ./...`
Expected: ALL PASS.

**Step 7: Commit**

```bash
git add internal/errors/errors.go internal/errors/errors_test.go
git commit -m "feat(errors): add error for missing --asset-name on sbom test --report"
```

---

### Task 4: Validate `--file` and `--asset-name` are mandatory for `sbom test --report`

**Files:**

- Modify: `internal/commands/ostest/routing.go`
- Test: `internal/commands/ostest/routing_test.go`

**Design note:** Place the new validation inside `RouteToFlow` (or a small `validateSbomReport` helper called from it) so it runs **after** `ParseFlowConfig` and **before** any `RunSbomFlow` call. It must trigger only when `fc.SBOM != "" && fc.Report && fc.FFDflySbomMonitor` (we will add `Report` and `FFDflySbomMonitor` to `FlowConfig` in this same task — see step 3a).

**Step 1: Write the failing tests**

Add four new sub-tests to `routing_test.go`:

1. `Test_RouteToFlow_SbomReport_FFOff_FallsThrough` — `--sbom`, `--report`, FF off → behaves like today (no asset-name validation, no error).
2. `Test_RouteToFlow_SbomReport_FFOn_NoFile_Errors` — `--sbom`, `--report`, FF on, `--file` missing → error from `NewMissingFilenameFlagError`, no further work.
3. `Test_RouteToFlow_SbomReport_FFOn_NoAssetName_Errors` — `--sbom`, `--report`, FF on, `--file` set, `--asset-name` empty → error from `NewMissingAssetNameError`.
4. `Test_RouteToFlow_SbomReport_FFOn_BothPresent_ReturnsSbomFlow` — happy path returns `SbomFlow`.

Use the existing test helpers/factories in `routing_test.go` to construct contexts and `FlowConfig`.

**Step 2: Run tests to verify they fail**

Run: `go test ./internal/commands/ostest/... -run RouteToFlow_SbomReport`
Expected: FAIL — fields and validation don't exist yet.

**Step 3: Add `Report` and `FFDflySbomMonitor` to `FlowConfig`**

In `routing.go`:

- Extend `FlowConfig` with:
    - `Report bool`
    - `FFDflySbomMonitor bool`
    - `AssetName string`
- In `ParseFlowConfig`, populate them from `cfg.GetBool(flags.FlagReport)`, `cfg.GetBool(constants.FeatureFlagDflySbomMonitor)`, and `cfg.GetString(flags.FlagAssetName)`.

**Step 3a: Add the validation helper and call site**

Add to `routing.go`:

```go
func validateSbomReport(fc *FlowConfig, errFactory *internalErrors.ErrorFactory) error {
    if fc.SBOM == "" || !fc.Report || !fc.FFDflySbomMonitor {
        return nil
    }
    if cfg.GetString(flags.FlagFile) == "" { /* see note */ }
    if fc.AssetName == "" {
        return errFactory.NewMissingAssetNameError()
    }
    return nil
}
```

For `--file`, reuse `fc.FileFlag` (already present on `FlowConfig`) and return `errFactory.NewMissingFilenameFlagError()` when empty.

Call `validateSbomReport(fc, errFactory)` from `RouteToFlow` _before_ the `switch` statement.

**Step 3b: Register the FF for the `test` workflow**

In `internal/commands/ostest/workflow.go`, extend the `featureFlags` map in `RegisterWorkflows` with:

```go
constants.FeatureFlagDflySbomMonitor: "rollout-dfly-sbom-monitor",
```

so the FF is available to the test workflow's configuration (it is currently only registered in `osmonitor`).

**Step 4: Run ALL tests**

Run: `go test ./...`
Expected: ALL PASS — including the four new tests.

**Step 5: Refactor**

Look at `RouteToFlow` and `validateSbomReport` for opportunities to keep cohesion high (e.g., move `--file`/`--asset-name` checks into a single helper). Use the @refactoring skill.

**Step 6: Run ALL tests**

Run: `go test ./...`
Expected: ALL PASS.

**Step 7: Commit**

```bash
git add internal/commands/ostest/routing.go internal/commands/ostest/routing_test.go internal/commands/ostest/workflow.go
git commit -m "feat(ostest): require --file and --asset-name for sbom test --report"
```

---

## Phase 3 — Routing `sbom test --report` to the SBOM flow with `publish_report=true`

The existing `executeFlow` already calls `common.RunSbomFlow(..., publishReport=nil, …)` for the `SbomFlow` case. We need to pass `util.Ptr(true)` whenever `--report` is set _and_ the `rollout-dfly-sbom-monitor` FF is on; otherwise keep `nil`.

### Task 5: Thread `publishReport` through `executeFlow` for the SBOM flow

**Files:**

- Modify: `internal/commands/ostest/workflow.go`
- Test: `internal/commands/ostest/workflow_test.go` (or new `internal/commands/ostest/sbom_report_test.go`)

**Step 1: Write the failing tests**

Add two tests:

1. `Test_OSWorkflow_SbomReport_FFOn_PassesPublishReportTrue` — invokes the test workflow with `--sbom=…`, `--report`, `--file=…`, `--asset-name=foo`, FF on; uses a capturing test client (mirroring `setupCapturingTestClient` from `osmonitor` tests) and asserts `capturedConfig.PublishReport != nil && *capturedConfig.PublishReport == true`.
2. `Test_OSWorkflow_SbomTest_NoReport_PassesPublishReportNil` — same but without `--report`; assert `capturedConfig.PublishReport == nil`.

If a capturing test client doesn't yet exist in the `ostest` test package, copy the pattern from `internal/commands/osmonitor/test_helpers_test.go` rather than re-deriving it.

**Step 2: Run tests to verify they fail**

Run: `go test ./internal/commands/ostest/... -run SbomReport`
Expected: FAIL — `executeFlow` always passes `nil`.

**Step 3: Plumb `publishReport` from `FlowConfig` into `executeFlow`**

In `workflow.go`:

- Change `executeFlow` signature to accept `publishReport *bool`.
- In `OSWorkflow`, compute `var publishReport *bool; if flowCfg.Report && flowCfg.FFDflySbomMonitor { publishReport = util.Ptr(true) }` and pass it through `processAllInputDirectories` → `processInputDirectory` → `executeFlow`.
- In the `SbomFlow` case, replace the existing literal `nil` argument to `common.RunSbomFlow` with the new `publishReport` parameter.

Leave `DflyDepgraphFlow` and `DepgraphFlow` cases passing `nil` for now — they are not part of this ticket.

**Step 4: Run ALL tests**

Run: `go test ./...`
Expected: ALL PASS.

**Step 5: Refactor**

Inspect the threading of `publishReport` through three function layers — consider grouping it on a small `flowOpts` struct if more flow-level options are likely to follow. Defer if speculative (YAGNI).

**Step 6: Run ALL tests**

Run: `go test ./...`
Expected: ALL PASS.

**Step 7: Commit**

```bash
git add internal/commands/ostest/workflow.go internal/commands/ostest/workflow_test.go internal/commands/ostest/sbom_report_test.go
git commit -m "feat(ostest): publish_report=true when sbom test --report and FF enabled"
```

---

### Task 6: Honor `--report` in `ShouldUseLegacyFlow`

`ShouldUseLegacyFlow` decides whether to delegate to the legacy CLI. Today, `--report` is unknown to it; we need it to count as a "new feature" so we don't fall back to legacy when `--sbom --report --asset-name` are present.

**Files:**

- Modify: `internal/commands/ostest/routing.go`
- Test: `internal/commands/ostest/routing_test.go`

**Step 1: Write the failing test**

`Test_ShouldUseLegacyFlow_SbomReport_FFOn_NotLegacy` — `FFDflySbomMonitor=true`, `Report=true`, `SBOM!=""` ⇒ returns `false`.

**Step 2: Run test to verify it fails**

Run: `go test ./internal/commands/ostest/... -run ShouldUseLegacyFlow_SbomReport`
Expected: FAIL — `--report` isn't part of `hasNewFeatures`.

**Step 3: Update `ShouldUseLegacyFlow`**

Add `(fc.Report && fc.FFDflySbomMonitor && fc.SBOM != "")` to the `hasNewFeatures` disjunction. Update the debug log line to include the SBOM monitor FF status.

**Step 4: Run ALL tests**

Run: `go test ./...`
Expected: ALL PASS.

**Step 5: Refactor**

None expected.

**Step 6: Run ALL tests**

Run: `go test ./...`
Expected: ALL PASS.

**Step 7: Commit**

```bash
git add internal/commands/ostest/routing.go internal/commands/ostest/routing_test.go
git commit -m "feat(ostest): treat sbom test --report as a non-legacy path"
```

---

## Phase 4 — Wire `--asset-name` into the Test API call

This step depends on the `go-application-framework` `testapi` package gaining an `AssetName` (or equivalent) field on `TestConfiguration`. As of this plan, that field does not exist yet (we only have `TargetName`, which is a different concept).

### Task 7: Bump `go-application-framework` to a version that exposes `AssetName`

**Files:**

- Modify: `go.mod`, `go.sum`

**Step 1: Confirm the upstream change**

Check the latest `go-application-framework` commits / tags for the addition of `AssetName *string \`json:"asset_name,omitempty"\`` on `TestConfiguration` (or an equivalent name agreed with the platform team). If unavailable, **stop here** and ask the user how to proceed.

**Step 2: Bump the dep**

```bash
go get github.com/snyk/go-application-framework@<the-version-that-has-AssetName>
go mod tidy
```

**Step 3: Run ALL tests**

Run: `go test ./...`
Expected: ALL PASS — confirms no API breakage.

**Step 4: Commit**

```bash
git add go.mod go.sum
git commit -m "chore(deps): bump go-application-framework to vX.Y.Z (TestConfiguration.AssetName)"
```

---

### Task 8: Pass `--asset-name` into `TestConfiguration`

**Files:**

- Modify: `internal/common/dfly_depgraph_flow.go` (`BuildTestConfig`)
- Modify: `internal/common/sbom_flow.go` (passes through `BuildTestConfig`)
- Test: `internal/common/dfly_depgraph_flow_test.go` (extend the existing `BuildTestConfig` table-driven tests)

**Step 1: Write the failing test**

Extend `Test_RunDflyDepgraphFlow_PublishReportForwarded`-style coverage with a new `Test_BuildTestConfig_AssetNameForwarded` (or extend an existing table-driven test) asserting that `BuildTestConfig` returns `*tc.AssetName == "my-asset"` when `cfg.Set(flags.FlagAssetName, "my-asset")`. Also add `Test_BuildTestConfig_AssetNameUnset_NotForwarded` for the negative case.

**Step 2: Run test to verify it fails**

Run: `go test ./internal/common/... -run BuildTestConfig_AssetName`
Expected: FAIL — field/wiring missing.

**Step 3: Update `BuildTestConfig`**

In `dfly_depgraph_flow.go`:

```go
if an := cfg.GetString(flags.FlagAssetName); an != "" {
    testConfig.AssetName = &an
}
```

(Place it next to the other optional fields for consistency.)

**Step 4: Run ALL tests**

Run: `go test ./...`
Expected: ALL PASS.

**Step 5: Refactor**

`BuildTestConfig` is starting to look like a `for k, v := range optionalStrings` loop. Consider using the @refactoring skill to extract a small helper if there are now ≥6 of these `if x != ""` blocks.

**Step 6: Run ALL tests**

Run: `go test ./...`
Expected: ALL PASS.

**Step 7: Commit**

```bash
git add internal/common/dfly_depgraph_flow.go internal/common/dfly_depgraph_flow_test.go
git commit -m "feat(common): forward --asset-name into TestConfiguration.AssetName"
```

---

## Phase 5 — Remove the `snyk monitor --sbom` Dragonfly entrypoint

Per design decision, `snyk sbom test --report` replaces the now-defunct `monitor --sbom=…` Dragonfly path. Remove that path so we have a single owner for SBOM "stateful" behavior.

### Task 9: Delete `RunSbomMonitorFlow` and its entrypoint

**Files:**

- Delete: `internal/commands/osmonitor/sbom_flow.go`
- Delete: `internal/commands/osmonitor/sbom_flow_test.go`
- Modify: `internal/commands/osmonitor/workflow.go`
- Modify: `internal/commands/osmonitor/workflow_test.go`

**Step 1: Write the failing test**

Update `Test_OSWorkflow_DflyFFEnabled_WithSBOM_UsesSbomFlow` (and friends) so that the **expected** behavior when running `snyk monitor --sbom=…` is: a clear, user-facing error indicating that `monitor --sbom` is no longer supported and instructing the user to switch to `sbom test --report`. Pick one of:

- (a) Reuse `errFactory.NewInvalidLegacyFlagError("--sbom")` (or similar) — simplest.
- (b) Add a new `NewSbomMonitorRemovedError(...)` factory method with a deprecation message — clearer but more code.

Encode the assertion (e.g., `assert.ErrorContains(t, err, "sbom test --report")`).

**Step 2: Run test to verify it fails**

Run: `go test ./internal/commands/osmonitor/...`
Expected: FAIL — current code still routes `--sbom` to `runSbomMonitorEntrypoint`.

**Step 3: Remove the entrypoint and surface the deprecation error**

In `osmonitor/workflow.go`:

- Delete `runSbomMonitorEntrypoint` and its only caller block:

  ```go
  if sbomPath := cfg.GetString(flags.FlagSBOM); sbomPath != "" {
      ...
      return runSbomMonitorEntrypoint(ctx, sbomPath)
  }
  ```

  Replace it with a short branch that returns the deprecation error (chosen above) when `cfg.GetString(flags.FlagSBOM) != ""`.

- Remove the `--sbom` field from `OSMonitorFlagSet()` if and only if (b) was chosen and after confirming that no other monitor code paths read it. If unsure, **leave the flag declared** (so we still produce a friendly error rather than an "unknown flag" parse failure).

- Remove the `constants.FeatureFlagDflySbomMonitor` entry from the monitor's `RegisterWorkflows` config map (it has been moved to the test workflow in Task 4 step 3b).

Then delete `osmonitor/sbom_flow.go` and `osmonitor/sbom_flow_test.go`.

**Step 4: Run ALL tests**

Run: `go test ./...`
Expected: ALL PASS.

**Step 5: Refactor**

`osmonitor/workflow.go` will be slightly leaner now — verify imports are still all used and the `setupDflyMonitor` helper is still needed by `runDflyMonitorEntrypoint`. Use the @refactoring skill if anything is dead.

**Step 6: Run ALL tests**

Run: `go test ./...`
Expected: ALL PASS.

**Step 7: Commit**

```bash
git add -A internal/commands/osmonitor/
git commit -m "refactor(osmonitor): remove sbom monitor dragonfly path, superseded by sbom test --report"
```

---

## Phase 6 — End-to-end and hygiene

### Task 10: Add an end-to-end-style test exercising the full happy path

**Files:**

- Test: `internal/commands/ostest/sbom_report_e2e_test.go`

**Step 1: Write the failing test**

Construct a single test that:

1. Builds a mock invocation context with a real `OSTestFlagSet`.
2. Sets `--sbom=testdata/bom.json`, `--report`, `--file=bom.json`, `--asset-name=my-app`, and FFs `internal_snyk_cli_rollout_dfly_sbom_monitor=true`.
3. Invokes `ostest.OSWorkflow` with a capturing test client + fake file upload client.
4. Asserts:
    - `capturedConfig.PublishReport != nil && *capturedConfig.PublishReport == true`
    - `capturedConfig.AssetName != nil && *capturedConfig.AssetName == "my-app"`
    - `ffc.GetUploadCount() == 1` (just the SBOM)
    - No error returned.

**Step 2: Run test to verify it fails**

Run: `go test ./internal/commands/ostest/... -run SbomReport_E2E`
Expected: PASS once Phases 1–4 are done; FAIL otherwise (this is a regression net).

**Step 3: Iterate until green**

If any earlier task missed a wiring detail, fix it in that task's commit (don't fold here).

**Step 4: Run ALL tests**

Run: `go test ./...`
Expected: ALL PASS.

**Step 5: Refactor**

None expected — this is a thin integration test on top of well-tested units.

**Step 6: Run ALL tests**

Run: `go test ./...`
Expected: ALL PASS.

**Step 7: Commit**

```bash
git add internal/commands/ostest/sbom_report_e2e_test.go
git commit -m "test(ostest): end-to-end happy path for sbom test --report"
```

---

### Task 11: Lint, snapshots, and CI prep

**Files:** _none_

**Step 1: Run the linter**

Run: `make lint` (or `golangci-lint run`)
Expected: zero new findings. Fix or `//nolint:` only if the rule is mechanical and there is no behavior change.

**Step 2: Refresh snapshots if any drifted**

Run: `UPDATE_SNAPS=true go test ./...` only if snapshot tests in `__snapshots__/` legitimately need to update; otherwise leave them.

**Step 3: Run ALL tests once more**

Run: `go test ./...`
Expected: ALL PASS.

**Step 4: Commit (if anything changed)**

```bash
git add -A
git commit -m "chore: lint and snapshot fixes for OSF-427"
```

(Skip if no diff.)

---

## Out of scope / explicitly skipped

- Updating the `snyk/cli` acceptance test in PR [snyk/cli#6870](https://github.com/snyk/cli/pull/6870) — explicitly skipped at the user's request.
- Exit-code matrix work (clean × snapshot stored vs. failed) — covered by sibling ticket **OSF-428**, not this one.
- "View your asset(s) at: …" output line — covered by sibling ticket **OSF-429**.
- Risk score, reachability, and other depgraph flows — untouched by this ticket.

## Assumptions worth flagging during execution

1. `go-application-framework` will expose `TestConfiguration.AssetName` (or an agreed alias). If platform names it differently (`AssetID`, `Asset`, etc.), revisit Tasks 7–8.
2. The legacy CLI still owns `snyk sbom test` invocations that are **not** `--report`; this plan does not change that.
3. Removing `monitor --sbom=…` is a behavior change for any user currently relying on it; release notes should call this out (out of code scope, but worth raising in the PR description).
