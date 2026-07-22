# Preflight — QuickBooks Online App Review Check

**Monitor your live QuickBooks Online app against the security rules Intuit's reviewers grade — automatically, after every deploy and on a schedule.**

Preflight probes your *deployed* app against the runtime security requirements Intuit
checks during App Store review and re-checks annually. It runs after you deploy, and
on a recurring schedule, so you catch a regression before Intuit does.

This is **not** a generic vulnerability scanner. It checks the specific, deterministic
rules from Intuit's published security requirements — the ones a Semgrep or Snyk has
no concept of.

> **Why not on every push?** These are *runtime* checks — TLS version, response
> headers, cookie flags. They can only be verified against a **running, deployed**
> app, not against source in a pull request. So Preflight runs *after* deployment and
> on a schedule, not on push. (Source-level checks like OAuth token storage and
> data-usage rules — the ones that belong on push — are part of the full review at
> [preflightci.dev](https://preflightci.dev).)

---

## What it checks

Runtime/deployment checks — deterministic, no false positives, no source code required:

| Check | Intuit requirement |
|-------|--------------------|
| **HTTPS enforced** | HTTPS must be enforced on all pages |
| **TLS version** | TLS 1.1 minimum; 1.2+ recommended |
| **Cache-Control** | Sensitive pages must use `no-store`, not `private` |
| **Session cookie flags** | Cookies must set `Secure` and `HttpOnly` |
| **TRACE disabled** | Unused HTTP methods must be disabled |
| **Token-endpoint redirect** | Token-bearing endpoints must `302` redirect, not return HTML |

## Usage

### Recommended: run after each deploy

Trigger Preflight when a deployment finishes, so it probes the version you just shipped:

```yaml
name: QBO Preflight (post-deploy)
on:
  deployment_status

jobs:
  preflight:
    # only run once the deployment actually succeeded
    if: github.event.deployment_status.state == 'success'
    runs-on: ubuntu-latest
    steps:
      - uses: preflightci/preflight-qbo-review@v1
        with:
          url: ${{ github.event.deployment_status.target_url }}
          token-endpoint: /oauth/callback   # optional
```

If your deploy runs as its own job, you can instead chain Preflight after it in the
same workflow (`needs: deploy`) and pass your app URL directly.

### Recommended: schedule a recurring compliance check

Intuit re-reviews listed apps (and any app with 500+ connections) **annually, or more
often at their discretion**, and expects you to stay compliant after publishing. A
weekly probe catches drift before that review:

```yaml
name: QBO Preflight (weekly monitor)
on:
  schedule:
    - cron: '0 13 * * 1'   # Mondays 13:00 UTC
  workflow_dispatch:        # allow manual runs too

jobs:
  preflight:
    runs-on: ubuntu-latest
    steps:
      - uses: preflightci/preflight-qbo-review@v1
        with:
          url: https://your-app.example.com
          fail-on: warn      # alert on warnings too, for monitoring
```

### On-demand

Trigger manually any time (e.g. right before you submit) with `workflow_dispatch`, or
run the script directly: `python3 preflight_check.py --url https://your-app.example.com`.

### Inputs

| Input | Required | Default | Description |
|-------|----------|---------|-------------|
| `url` | yes | — | Base URL of your deployed app to probe |
| `token-endpoint` | no | `''` | Path of a token-bearing endpoint to check the 302 rule |
| `fail-on` | no | `fail` | Fail the workflow on `fail`, `warn`, or `never` |
| `format` | no | `text` | Log output: `text` or `json` |

## What it does *not* check (yet)

Preflight's free checks cover the deterministic **runtime** rules. The **source-level**
checks — which belong on push, and need code access or expert triage — are part of the
full review at **[preflightci.dev](https://preflightci.dev)**:

- OAuth refresh-token encryption and key storage
- QuickBooks data-usage rules (no logging/exporting QBO data)
- The injection / XSS / CSRF attack set, mapped to Intuit's review categories

## Disclaimer

Preflight is an independent tool built against Intuit's publicly documented
requirements. It is **not** affiliated with, operated by, or endorsed by Intuit, and
passing these checks does not guarantee your app will pass Intuit's review.

## License

MIT
