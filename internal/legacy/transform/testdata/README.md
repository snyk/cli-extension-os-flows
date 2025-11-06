# Test Fixtures
Follow these instructions to recreate the `-legacy.json` and `-findings.json` files.

First the legacy json output:

```bash
snyk test --file=go.mod --json > [state-of-policies]-legacy.json
```

In order to grab the API findings, start a reachability test:

```bash
TEST_ID=$(snyk test --file=go.mod --reachability --debug 2>&1 | grep '/findings' | sed -E 's|.*\/tests/([0-9a-f-]+)/.*|\1|') && echo test ID $TEST_ID
```

...then use the recorded test ID to fetch the findings:

```bash
curl -H "Authorization: token $SNYK_TOKEN" "https://api.dev.snyk.io/rest/orgs/$SNYK_ORG/tests/$TEST_ID/findings?limit=100&version=2024-10-15" > [state-of-policies]-findings.json
```

