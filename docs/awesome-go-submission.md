# awesome-go submission

Everything a maintainer needs to open the one-line pull request against
[avelino/awesome-go](https://github.com/avelino/awesome-go). Copy from this file;
no further preparation is required.

**Audit date: 2026-08-07.** awesome-go's requirements change over time. If you are
reading this more than a month or two after that date, re-run the checks in
[Re-verifying this audit](#re-verifying-this-audit) before submitting.

Verified against `avelino/awesome-go@main`:
[`CONTRIBUTING.md`](https://github.com/avelino/awesome-go/blob/main/CONTRIBUTING.md),
[`.github/PULL_REQUEST_TEMPLATE.md`](https://github.com/avelino/awesome-go/blob/main/.github/PULL_REQUEST_TEMPLATE.md),
and the blocking CI implementation at
[`.github/scripts/check-quality/main.go`](https://github.com/avelino/awesome-go/blob/main/.github/scripts/check-quality/main.go).

## The entry line

```markdown
- [deidentify](https://github.com/aliengiraffe/deidentify) - Deterministic, format-preserving removal of personally identifiable information from text and structured data.
```

- **Category:** `## Security`
- **Insert between:** `Crenox` (line above) and `dongle` (line below)

Context, so you can locate the insertion point by eye:

```markdown
- [Crenox](https://github.com/crenoxhq/crenox) - Zero-dependency pre-commit secret scanner using Aho-Corasick for high-performance credentials leak detection.
- [deidentify](https://github.com/aliengiraffe/deidentify) - Deterministic, format-preserving removal of personally identifiable information from text and structured data.
- [dongle](https://github.com/golang-module/dongle) - A simple, semantic and developer-friendly golang package for encoding&decoding and encryption&decryption.
```

The entry satisfies awesome-go's format rules: link text is the exact package name
(`deidentify`, matching the `go.mod` module path), the description follows the link
on the same line, is non-promotional, and ends with a period.

**Category choice.** `## Security` over `## Text Processing`: the library's purpose is
data protection and compliance, not text manipulation, and comparable data-protection
libraries (`acra`, `pii-shield`, `redact`) are already listed under Security. Submit to
one category only.

## PR body links

Paste these into the four required-link checkboxes of awesome-go's PR template. All
four were confirmed reachable by an anonymous (logged-out) client on 2026-08-07.

```
Forge link (github.com, gitlab.com, etc): https://github.com/aliengiraffe/deidentify
pkg.go.dev: https://pkg.go.dev/github.com/aliengiraffe/deidentify
goreportcard.com: https://goreportcard.com/report/github.com/aliengiraffe/deidentify
Coverage service link: https://app.codecov.io/gh/aliengiraffe/deidentify
```

awesome-go's CI parses these out of the PR body with regexes that require the
`label: url` shape shown above — keep the label text, and do not move a URL onto its
own line. The coverage regex accepts only `coveralls.io`, `codecov.io`, or
`app.codecov.io` hosts.

## Audit table

Status as verified on 2026-08-07. "Blocking" means awesome-go's CI fails the PR;
"warning" means the check reports but does not block.

| Requirement | Severity | Status | Evidence (2026-08-07) |
| --- | --- | --- | --- |
| ≥5 months of history | Warning | **Pass** | First commit `50b0fc0`, 2025-05-20 — ~14.6 months |
| Open source license | Warning | **Pass** | MIT; GitHub reports `licenseInfo.key = mit` |
| `go.mod` at repo root | Blocking | **Pass** | `module github.com/aliengiraffe/deidentify`, `go 1.24.2` |
| ≥1 SemVer release `vX.Y.Z` | Blocking | **Pass** | `v1.0.2`, released 2026-08-07 |
| Repo accessible, not archived | Blocking | **Pass** | Public; `isArchived = false` |
| pkg.go.dev reachable | Blocking | **Pass** | HTTP 200; serves `v1.0.2` — see [pkg.go.dev](#pkggodev-serves-v102) |
| Go Report Card grade A-/A/A+ | Blocking | **Pass** | Passes as `grade unknown` — see [Go Report Card](#go-report-card-sunset) |
| Coverage link reachable | Warning | **Pass** | Anonymous 200 — see [Coverage](#coverage-report-is-publicly-reachable) |
| Coverage ≥80% (non-data package) | Manual review | **Pass** | 92.5% of statements on `941672f` |
| Doc comments on all public APIs | Manual review | **Pass** | `doc.go` + doc comments on every exported symbol (PR #47, shipped in `v1.0.2`) |
| CI/CD configured | Warning | **Pass** | `.github/workflows/go.yml`, `release.yml`, `benchmark-profile.yml` |
| README present | Warning | **Pass** | `README.md` with install, usage, and supported-PII-types table |
| Description non-promotional | Warning | **Pass** | Repo description and README overview rewritten — see [Non-promotional](#non-promotional-description) |
| No bug reports older than 6 months | Warning | **Pass** | Open issues: #48 and #46 (both 2026-08-07) and #3 (Renovate dashboard, not a bug) |
| Issues/PRs answered within ~2 weeks | Manual review | **Gap** | 5 open Renovate PRs; oldest #41 from 2026-04-10 — see [Maintenance](#maintenance-signal-open-renovate-prs) |
| Entry format and alphabetical order | Blocking | **Pass** | See [The entry line](#the-entry-line) |

One item is a **Gap**, and it is a manual-review signal rather than an automated
check. It is a maintainer decision, deliberately out of scope for this document.

### Go Report Card (sunset)

`goreportcard.com` has been sunset. The report page now serves the notice *"After more
than a decade of serving the ecosystem, Go Report Card has been sunset,"* recommends
`golangci-lint` or self-hosting, and no longer computes grades. The badge endpoint
renders the literal text `go report: retired`.

awesome-go's `CONTRIBUTING.md` and PR template still ask for a Go Report Card link with
a grade of A- or better, which reads as an unresolvable contradiction. **It is not.**
Reading the blocking check itself —
[`check-quality/main.go`](https://github.com/avelino/awesome-go/blob/main/.github/scripts/check-quality/main.go),
function `checkGoReportCard` — resolves it:

```go
m := reGrade.FindSubmatch(body)
if m == nil {
    return "unknown", true // reachable but no grade found
}
```

The check fetches the URL and looks for a `Grade: X` string. If the page is reachable
but contains no grade, it returns `ok = true`. Verified on 2026-08-07: the sunset page
returns **HTTP 200** and contains **no** `Grade:` match. The blocking check therefore
**passes**, reporting `✅ Go Report Card: OK (grade unknown)`.

**Consequences for the submission:**

1. **Keep the `goreportcard.com` link in the PR body.** Omitting it is an unconditional
   critical failure (`Go Report Card: missing from PR body`). The link passing as
   "grade unknown" is strictly better than not supplying one.
2. **The badge is removed from this repo's README.** It resolved to `go report: retired`
   and linked to a sunset notice. awesome-go's CI reads the *PR body*, never the
   README, so removing the badge costs nothing and avoids shipping a dead badge.
3. **`golangci-lint` stands in as the quality signal.** This is what awesome-go's own
   sunset guidance points at. `golangci-lint run ./...` reports **0 issues** on
   `main`, and the lint job in `.github/workflows/go.yml` enforces it on every PR.

One caveat to answer honestly if a reviewer asks: the PR template has a manual checkbox
reading *"The repo documentation has a goreportcard link (grade A- or better)."* This
repo's documentation no longer carries that link, for the reason in point 2. Say so
plainly in the PR — the automated check, which is the one that blocks, passes.

### pkg.go.dev serves v1.0.2

Confirmed 2026-08-07.

- `https://proxy.golang.org/github.com/aliengiraffe/deidentify/@latest` resolves to
  `v1.0.2` at commit `941672f2bad561f04084aa214f2ad4695ff0aa75`.
- `https://pkg.go.dev/github.com/aliengiraffe/deidentify` — HTTP 200, header renders
  `Version: v1.0.2` with the `Latest` chip.
- `https://pkg.go.dev/github.com/aliengiraffe/deidentify@v1.0.2` — HTTP 200. (This URL
  404'd earlier the same day while pkg.go.dev finished indexing the new tag; that has
  since cleared.)
- The rendered overview is `doc.go` from PR #47, including the determinism explanation
  and the `Getting started`, `Supported PII types`, `Structured data`, `Concurrency`,
  and `Limitations` sections.

`v1.0.2` was released from `941672f`, the commit that merged PR #47's documentation, so
a reviewer following the pkg.go.dev link lands on the documented API rather than
February's `v1.0.1`. No further release is needed for this submission.

### Coverage report is publicly reachable

Confirmed 2026-08-07 with an unauthenticated client:

- `https://codecov.io/gh/aliengiraffe/deidentify` — HTTP 301 → `https://app.codecov.io/gh/aliengiraffe/deidentify` — HTTP 200.
- `https://codecov.io/gh/aliengiraffe/deidentify/branch/main/graph/badge.svg` — HTTP 200.

The project renders for anonymous visitors; no login is required. awesome-go's
`isReachable` treats any 2xx or 3xx as reachable, so either URL passes, but prefer the
canonical `https://app.codecov.io/gh/aliengiraffe/deidentify` in the PR body to avoid
depending on the redirect.

Local figure, for cross-reference:

```
$ go test -coverprofile=cover.out . && go tool cover -func=cover.out | tail -1
total:  (statements)  92.5%
```

`codecov.yml` sets an 80% project target, matching awesome-go's floor for
non-data-related packages.

### Non-promotional description

awesome-go flags superlative and marketing language. Both places that carried it have
been rewritten.

**GitHub repo description** — applied 2026-08-07 via `gh repo edit`:

> _Before:_ Simple yet powerful tool for identifying and anonymizing personal information in various formats.
>
> _After:_ Go library that detects personally identifiable information in text and structured data and replaces it with deterministic, format-preserving substitutes.

**README overview paragraph** — see `README.md`. The phrases "simple yet powerful",
"powerful tools", "rich anonymization", and "extensive variety" are gone. The
installation snippet, usage examples, and supported-PII-types table are untouched.

### Maintenance signal: open Renovate PRs

awesome-go's manual review looks for issues and PRs answered within roughly two weeks.
Five Renovate PRs are open and visible to a reviewer:

| PR | Title | Opened |
| --- | --- | --- |
| [#41](https://github.com/aliengiraffe/deidentify/pull/41) | Update actions/github-script action to v9 | 2026-04-10 |
| [#42](https://github.com/aliengiraffe/deidentify/pull/42) | Update softprops/action-gh-release action to v3 | 2026-04-12 |
| [#43](https://github.com/aliengiraffe/deidentify/pull/43) | Update codecov/codecov-action action to v7 | 2026-06-07 |
| [#44](https://github.com/aliengiraffe/deidentify/pull/44) | Update actions/checkout action to v7 | 2026-06-18 |
| [#45](https://github.com/aliengiraffe/deidentify/pull/45) | Update actions/setup-go action to v7 | 2026-07-16 |

These are bot-authored dependency bumps, not user reports, and none is a blocking
check. Triaging them before submitting would improve the impression a reviewer forms of
the project's maintenance cadence. That is a maintainer decision and is not required by
this document.

## Re-verifying this audit

Re-run before opening the upstream PR if this file has gone stale.

```bash
# Local quality gates — these stand in for the Go Report Card grade
gofmt -l .                 # expect no output
go vet ./...               # expect clean
golangci-lint run ./...    # expect "0 issues."
go test ./...              # expect all packages ok
go test -run Example ./...  # runnable examples that pkg.go.dev renders
go test -coverprofile=cover.out . && go tool cover -func=cover.out | tail -1  # expect >= 80%

# Link reachability, as an anonymous client
for u in \
  https://github.com/aliengiraffe/deidentify \
  https://pkg.go.dev/github.com/aliengiraffe/deidentify \
  https://goreportcard.com/report/github.com/aliengiraffe/deidentify \
  https://app.codecov.io/gh/aliengiraffe/deidentify ; do
  printf '%s -> %s\n' "$u" "$(curl -sL -o /dev/null -w '%{http_code}' "$u")"
done

# pkg.go.dev is serving the latest tag
curl -s https://proxy.golang.org/github.com/aliengiraffe/deidentify/@latest

# Alphabetical neighbours are still Crenox and dongle
curl -s https://raw.githubusercontent.com/avelino/awesome-go/main/README.md \
  | awk '/^## Security$/,/^## [^S]/' | grep -iE '^- \[(crenox|dongle)\]'
```

Also re-read
[`check-quality/main.go`](https://github.com/avelino/awesome-go/blob/main/.github/scripts/check-quality/main.go).
It is the source of truth for what actually blocks a submission, and it has diverged
from the prose in `CONTRIBUTING.md` at least once — see
[Go Report Card](#go-report-card-sunset).

## Out of scope

Deliberately not covered here, and not required to submit:

- Opening or merging the PR against `avelino/awesome-go`. That is a human action.
- Triaging the five open Renovate PRs.
- Issue #46 (regex recompilation in `Text()`). Unrelated performance work.
