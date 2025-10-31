# Test Fixtures
Follow these instructions to recreate the `-legacy.json` and `-findings.json` files.

First the legacy json output:

```bash
snyk test --file=go.mod --json > [state-of-policies]-legacy.json
```

In order to grab the API findings, start a reachability test:

```bash
snyk test --file=go.mod --reachability --debug 2>&1 | grep '/findings'
```

This will print out the API endpoint used to fetch the findings. Copy the endpoint and use it to fetch the findings:

```bash
curl -H "Authorization: token $SNYK_TOKEN" "FINDINGS_URL_FROM_THE_PREVIOUS_COMMAND" > [state-of-policies]-findings.json
```

