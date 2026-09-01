# AGENTS.md

Single source of truth for AI coding agents working on this project. Read this before making any changes.

`CLAUDE.md` intentionally delegates here — update this file, not the pointer.

A Go CLI extension that provides Snyk's unified Open Source testing flows. It runs inside the Go Application Framework (GAF) alongside the legacy TypeScript CLI, whose observable behaviour it has to reproduce exactly.

## Scope

These rules cover Go source under `internal/` and `pkg/`, the TypeSpec definitions under `internal/legacy/definitions/`, and the CircleCI configuration.

## Architecture

`pkg/osflows` is the composition root. Dependencies arrive in two stages: GAF's workflow engine supplies the outer layer, and `cmdctx` carries the inner layer through the context. Flow dispatch is a single switch in `internal/commands/ostest/routing.go` — there is no mediator, command bus or event bus, so a new flow is added there rather than by hooking in elsewhere.

### Conventions

- New tests live in an external `<pkg>_test` package — `testpackage` is enabled.
- The per-path linter exclusions in `.golangci.yaml` are deliberate. Work within them; do not widen an escape to cover new paths.
- `cmdctx` getters return `nil` rather than panicking when a dependency was never set, so callers nil-check instead of relying on the getter to fail loudly.
- File naming is mixed across the tree — match the package you are working in rather than imposing one.

### Danger zone

`internal/util/integration_tests_setup.go` opens with `///go:build integration` — three slashes, so it is a comment, not a build constraint, and the file is compiled into every build including non-integration ones. Treat any reasoning about which files the `integration` tag selects as suspect until this is fixed.

Treat these areas as high-risk: prefer the smallest possible change,
add tests before modifying, and ask a human reviewer before landing.

## Code conventions

### Style and formatting

Formatting and linting are enforced by tooling — run `make format` / `make lint`
instead of reasoning about style; they are authoritative. The enabled linters and their
thresholds live in `.golangci.yaml`; read them there rather than assuming.

### Best practices for new code

Apply these principles when writing **new** code. Do not refactor existing code to comply unless explicitly asked.

When you touch a file that has existing violations:
1. Write your new code correctly.
2. Leave the surrounding violation untouched.
3. Emit: "⚠️ Legacy debt: [file:line] — [which principle], left alone to avoid scope creep."

- **Single Responsibility Principle (SRP)**
- **Avoid Hasty Abstractions (AHA)**

## Generated code

Never hand-edit these — they are auto-generated:

| Path | Generator | Regenerate with |
|------|-----------|-----------------|
| `internal/legacy/definitions/spec.yaml` | TypeSpec (`tsp`) from `*.tsp` | `make generate` |
| `internal/legacy/definitions/oapi.gen.go` | oapi-codegen | `make generate` |
| `internal/mocks/mock_*.go` | mockgen | `go generate ./...` |
| `pkg/semver/*/js/build/index.js` | esbuild — committed and pulled in with `//go:embed` | `npm run build` in that ecosystem's `js/` directory |
| `**/__snapshots__/` | go-snaps | `UPDATE_SNAPS=true go test ./...` |

## Testing

> **Note:** No automated coverage enforcement found in CI or config. Consider adding a threshold.

Integration tests are behind the `integration` build tag and talk to a real Snyk API, so they need `SNYK_ORG_ID`, `SNYK_API_BASE_URL` and `SNYK_API_TOKEN` in the environment.

| Command | What it runs |
|---------|--------------|
| `make test` | Unit tests |
| `go test -tags integration -run Integration ./...` | Integration tests against a live API |
| `UPDATE_SNAPS=true go test ./...` | Rewrites go-snaps snapshots after an intended output change |

### AI agent testing protocol

**1. Test-first: fail before pass.**

Before writing implementation, write a test that exercises the new behavior. Run it — it **must
fail** first. A test that passes before the change is testing the wrong thing; discard it and write
another. Implement, then run again. This cycle counts as one attempt; you have **3 attempts** total.
If fail-then-pass cannot be achieved, stop and warn: "Warning: could not achieve
fail-before/pass-after for [test name] — [reason]."

If writing a test before implementation is genuinely not feasible (e.g., the change is in test
scaffolding itself), document the reason explicitly.

**2. Do not add tests for pre-existing untested code you touch.**

When modifying existing code that has no tests, report it: "Warning: [file/function] has no
existing test coverage. This change is unverified." Do **not** add tests for it — that is out of
scope and may introduce incorrect assumptions about existing behavior. Do write tests for any
**new** behavior you add, even if it lives in an existing file.

## Local development

Go and Node versions are pinned in `.tool-versions`; the TypeSpec compiler is also required. `make install-tools` fetches the Go-side tooling. Put machine-specific Make overrides in `local.mk`; it is gitignored so it never reaches a PR.

## Commits and PRs

**Commit format:** Conventional Commits with a bracketed Jira ticket — `<type>: <subject> [OSF-nnn]`
Branch naming: `<type>/<ticket>/<kebab-case-description>`.

## Before you finish

Before presenting any change, verify each item below. Do not report work as complete until every applicable item passes.

- [ ] `make test` passes
- [ ] `make lint` passes
- [ ] `make format` run and output committed
- [ ] `make generate` and `go generate ./...` re-run if their sources changed, and the results committed
- [ ] Snapshots regenerated with `UPDATE_SNAPS=true` only when the output change was intended
- [ ] Integration tests run if the change touches an API-facing path
- [ ] Commit message follows `<type>: <subject> [OSF-nnn]`
- [ ] New code has test coverage (or warning documented)
- [ ] All CircleCI gates pass
