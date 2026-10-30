# velocloud-diag-sanitizer

A Go tool for inspecting and sanitizing VeloCloud Edge diagnostic bundles
before they leave a customer's environment.

Diagnostic bundles contain command output, logs, interface and routing
details, VPN configuration, and proprietary debug dumps — all of which can
carry customer-identifiable or security-sensitive data. This tool walks a
bundle, classifies and inspects every file, produces a sanitized copy at a
separate output path, and verifies the result. See `docs/threat-model.md`
for what counts as sensitive.

## Status: network pseudonymization (Task 3A)

| Capability                                        | Status            |
|---------------------------------------------------|-------------------|
| CLI (`inspect`, `sanitize`, `verify`, `version`)  | Implemented       |
| Bundle discovery (safe walk, symlink handling)    | Implemented       |
| Content classification (text/mixed/binary/empty)  | Implemented       |
| `inspect` report (text + JSON)                    | Implemented       |
| Sensitive-content detection (read-only)           | Implemented       |
| `sanitize`: copy + IPv4/MAC/identity/domain pseudonymization | Implemented |
| `sanitize`: credential + PEM private-key redaction  | Implemented       |
| IPv6 detection + risk reporting (no pseudonymization) | Implemented     |
| `verify` (independent residual-data check)          | Implemented       |
| IPv6/mixed/binary transformation                    | Future phase      |
| Web frontend                                      | Future phase      |

Sanitize scope: text files are streamed and rewritten in place (in the
output copy): IPv4/MAC identifiers, labeled identity values (hostname,
site, customer, username, email, serial, org), and labeled domain/FQDN
fields (domain, domain_name, dns_domain, search_domain, fqdn — incl.
delimiter-preserving lists) are pseudonymized with keyed HMAC-SHA-256 —
private IPv4 → 10/8, public/CGNAT → 100.64/10, MACs → locally
administered unicast, identity values → `kind-<hex>`, domains →
`dom-<hex>.example.invalid` (whole-token; no subdomain relationship).
Labeled credential values (passwords, tokens, API keys, PSKs, community
strings, authorization headers) are replaced with `[REDACTED]`, and PEM
private-key block bodies are redacted (markers kept; malformed blocks →
file excluded, `requires-review`). IPv6 addresses are detected and
reported but intentionally unchanged. Certificates, special IPv4
ranges, ambiguous domain values, and unlabeled content are intentionally
unchanged. Mixed-NUL, binary and unknown files are excluded and marked
`requires-review`; symlinks are never recreated. No subnet/prefix or
subdomain relationship is preserved — only per-identifier consistency.

With `-copy-untransformed`, mixed/binary/unknown files are instead copied
**byte-for-byte** and marked `unchanged-by-policy` — they are *not*
sanitized and may contain unredacted sensitive data. Files that fail
transformation (oversized lines, malformed PEM, read/write errors) are
never downgraded to a copy.

`verify` re-inspects an output independently (read-only) and reports an
outcome: `findings_detected`, `review_required`, or
`no_detected_findings_with_limitations`, splitting residuals into
expected-policy and unresolved. Exit 0 only for the last outcome; a
successful run never means the bundle is safe.

`verify -provenance REPORT.json` optionally ingests a prior sanitize
JSON report. It is structurally validated and its claimed counts are
summarized as **reported processing history** — supporting evidence,
never proof. Provenance cannot suppress observed findings; a malformed
or output-inconsistent report forces `review_required` at minimum.

## Build

Requires only the Go toolchain (no npm, no Docker, no CGO). The only
third-party modules are `modernc.org/sqlite` and `golang.org/x/crypto` (plus
their transitive modules), used by the `serve` account store; they must be in
the Go module cache at build time (see `docs/auth.md`). Everything works
offline at run time.

```sh
make build        # produces bin/sanitizer
make test         # go test ./...
make check        # gofmt + vet + tests
```

## Usage

```sh
sanitizer inspect [-json] [-o FILE] INPUT   # read-only analysis
sanitizer analyze [-json] [-o FILE] [-diag-key-file FILE] INPUT
                                        # read-only diagnostic evidence timeline
sanitizer sanitize [-json] [-o FILE] [-key-file FILE] [-copy-untransformed] INPUT OUTPUT
sanitizer verify [-json] [-o FILE] [-provenance REPORT.json] OUTPUT
                                        # independent residual check
```

`INPUT` is a diagnostic-bundle directory. The bundle is never modified;
symlinks inside it are recorded but never followed.

`sanitize` requires a hex mapping key via `-key-file` or the
`SANITIZER_KEY` environment variable (generate one with
`openssl rand -hex 32`). The key is never written to the output or the
report; keep it safe — it is required to reproduce the same mappings.

`analyze` extracts normalized link/tunnel events from confirmed sources
into an evidence timeline. It is **not** a diagnosis: absence of events
never means a component was healthy. Sensitive identifiers appear only
as keyed HMAC tags (`ip-…`, `peer-…`, `link-…`, `name-…`):

- **Default:** a fresh random 256-bit key per run — tags are
  run-specific and cannot be correlated across separate invocations.
- **`-diag-key-file FILE`:** a hex key file (generate with
  `openssl rand -hex 32`, store mode `0600`, back up securely) gives
  stable tags across runs for longitudinal diffing. Loss of the file
  loses tag comparability forever; exposure lets anyone confirm
  guessed identifiers against old reports — treat it like the sanitize
  key, but **use a different file**: never reuse the sanitize key.
  Missing/malformed files fail closed; nothing falls back silently.
- Truncated HMAC tags are correlation handles, not anonymization —
  reports remain sensitive documents regardless of key mode.

## Module path

This directory is its own Go module, nested inside the repository module
`github.com/gocisse/diag-tool`:

```
module github.com/gocisse/diag-tool/velocloud-diag-sanitizer
```

Build, vet, and test commands must run from this directory (the module
root). The parent `go.mod` does not cover this subtree.

## Layout

```
cmd/sanitizer/        main entry point
internal/cli/         argument parsing, exit codes
internal/discovery/   safe bundle enumeration (never follows symlinks)
internal/classify/    content sniffing: text / mixed / binary / empty / unknown
internal/inspect/     sensitive-content detectors (interface defined, none yet)
internal/sanitize/    copy engine, keyed token map, credential/PEM redaction
internal/verify/      independent residual-data verification
internal/report/      structured report types + JSON/text renderers
internal/pipeline/    orchestrates the stages
web/                  future React/TypeScript/Vite frontend (embed later)
tests/testdata/       synthetic fixtures only — never real customer data
docs/                 architecture and threat model
plans/                roadmap and phase reports
```

## Safety limitations

- `inspect` is read-only; detectors flag **candidate** sensitive content.
  An empty findings list does not mean a bundle is safe.
- Classification is a **hint**, not proof a file is safe to share.
- Binary files are not content-inspected (marked `unsupported`).
- Lines over 4 MiB are truncated; per-file findings are capped at 5000.
