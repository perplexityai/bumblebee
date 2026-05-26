# bumblebee

Bumblebee is a read-only inventory collector for package, extension,
and developer-tool metadata on macOS and Linux developer endpoints.

It answers a narrow supply-chain response question: when an advisory
names a package, extension, or version, which developer machines show
a match in their on-disk metadata right now?

SBOMs help answer what shipped, and EDR helps answer what ran or
touched the network, but supply-chain response often needs a different
view: messy local state across lockfiles, package-manager metadata,
extension manifests, and supported developer-tool configs.

Bumblebee turns that scattered on-disk state into structured NDJSON
component records and, when given an exposure catalog, flags exact
matches for fast, read-only exposure checks when responders already
know what they are looking for.

## Scope

- Single static binary, Go 1.25+, zero non-stdlib dependencies.
- Three scan profiles (`baseline`, `project`, `deep`) for different
  populations and cadences.
- Reads only the lockfiles, package-manager install metadata,
  extension manifests, and supported MCP JSON configs listed in
  [docs/inventory-sources.md](docs/inventory-sources.md). No package
  manager execution (`npm ls`, `pip show`, `go list`, ...) and no
  source-file reads. MCP host configs can carry environment values
  and credentials in their `env` blocks; Bumblebee parses these
  configs for the server inventory it needs but does not emit those
  values in its records.

## Coverage

| Family | Emitted `ecosystem` | Sources |
|---|---|---|
| npm | `npm` | `package-lock.json`, `npm-shrinkwrap.json`, `node_modules/.package-lock.json`, `node_modules/<pkg>/package.json` |
| pnpm | `npm` | `pnpm-lock.yaml`, `.pnpm/.../package.json` |
| Yarn | `npm` | `yarn.lock` (Classic + Berry) |
| Bun | `npm` | `bun.lock`; `bun.lockb` presence as diagnostic |
| PyPI | `pypi` | `*.dist-info/METADATA`, `INSTALLER`, `direct_url.json`, `*.egg-info/PKG-INFO` |
| Go modules | `go` | `go.sum`, `go.mod` |
| RubyGems | `rubygems` | `Gemfile.lock`, installed `*.gemspec` |
| Composer | `packagist` | `composer.lock`, `vendor/composer/installed.json` |
| MCP | `mcp` | JSON host configs: `mcp.json`, `.mcp.json`, `claude_desktop_config.json`, `mcp_config.json`, `mcp_settings.json`, `cline_mcp_settings.json`, plus `~/.gemini/settings.json` (Gemini CLI / Code Assist). Non-JSON configs (Codex `config.toml`, Continue YAML) are not parsed in v0.1. |
| Editor extensions | `editor-extension` | VS Code, Cursor, Windsurf, VSCodium manifests |
| Browser extensions | `browser-extension` | Chromium-family (`manifest.json`) and Firefox (`extensions.json`) per profile |

Per-ecosystem detail: [docs/inventory-sources.md](docs/inventory-sources.md).

## Install

Requires Go 1.25+. Zero non-stdlib dependencies.

```sh
# Install the latest tagged release into $GOBIN.
go install github.com/perplexityai/bumblebee/cmd/bumblebee@latest

# Or pin a specific tag.
go install github.com/perplexityai/bumblebee/cmd/bumblebee@v0.1.1
```

To build from a checkout:

```sh
go build -o bumblebee ./cmd/bumblebee
go test ./...
```

Stamp an explicit version at build time:

```sh
go build -ldflags "-X main.Version=v0.1.1" -o bumblebee ./cmd/bumblebee
```

`bumblebee version` prints the version plus the VCS revision, build
time, and Go runtime — so a record emitted in production can be traced
back to a specific build. Version precedence: `-ldflags` override,
module version recorded by `go install`, then the in-tree default
tracked in `VERSION`.

### Self-test

After installing, run a built-in end-to-end check against embedded
fixtures:

```sh
bumblebee selftest
# selftest OK (2 findings in 1ms)
```

The fixtures live inside the binary, use deliberately fake package
names (`bumblebee-selftest-evil@0.0.0`), and make no network calls. A
non-zero exit means the local install can no longer detect what it
should — a fast pre-deployment smoke test for fleet rollouts.

## Profiles

Bumblebee is a one-shot scanner: each invocation performs a single scan
and exits. Cadence is the runner's responsibility (cron, launchd, systemd,
MDM, etc.). Each record carries `profile` and a per-root `root_kind` so
receivers can keep populations separate.

| Profile | Scans | Use for |
|---|---|---|
| `baseline` | Common global/user package roots, language toolchains, editor extensions, browser extensions, and MCP configs. | Recurring lightweight inventory via an external runner. |
| `project` | Configured development directories, such as `~/code`, `~/src`, or `~/work`. | Recurring inventory for known project workspaces. |
| `deep` | Explicit `--root` paths, including broad roots like `$HOME`. | On-demand incident or campaign checks, usually with `--ecosystem`, `--exposure-catalog`, and `--findings-only`. |

`baseline` and `project` refuse bare-home roots; only `deep` walks them.

## Quick start

```sh
# Baseline global inventory.
bumblebee scan --profile baseline > inventory.ndjson

# Daily project sweep with explicit roots.
bumblebee scan --profile project \
  --root "$HOME/code" \
  --root "$HOME/Developer"

# Limit a run to selected emitted ecosystems.
bumblebee scan --profile baseline \
  --ecosystem npm,pypi \
  --ecosystem go

# On-demand exposure scan against a published advisory.
bumblebee scan --profile deep \
  --root "$HOME" \
  --exposure-catalog ./catalog.json \
  --max-duration 10m
```

Preview the resolved roots without scanning:

```sh
bumblebee roots --profile baseline
# prints "<root_kind>\t<path>" lines
```

`--root` is a filesystem path to scan; repeatable, required for `deep`,
optional for the other profiles. `--ecosystem` is repeatable and
comma-separated. `--exposure-catalog` accepts a JSON file or a directory
of `*.json` catalogs (merged non-recursively, all files must share
`schema_version`). `--findings-only` requires `--exposure-catalog` and
suppresses package records while keeping findings. `bumblebee scan --help`
lists every flag.

## Output

Records are NDJSON, one per line. Diagnostics go to stderr as NDJSON. Each
run ends with a `scan_summary` record; receivers use it to decide whether
to promote a run to current state. See [docs/transport.md](docs/transport.md)
for HTTPS/file output and [docs/state-model.md](docs/state-model.md) for the
receiver-side current-state model.

For interactive terminal use, `bumblebee scan --output=terminal` renders a
colorized summary, a compact findings table, and a live spinner on stderr
while the scan runs. The default `stdout` mode remains NDJSON for tooling.

Package record:

<details>
<summary>Example package record</summary>

```json
{
  "record_type": "package",
  "record_id": "package:...",
  "schema_version": "0.1.0",
  "scanner_name": "bumblebee",
  "scanner_version": "v0.1.1",
  "run_id": "9b1f0c2e4d5a6b7c8d9e0f1a2b3c4d5e",
  "scan_time": "2026-05-15T18:22:01.482Z",
  "endpoint": {
    "hostname": "alex-mbp",
    "os": "darwin",
    "arch": "arm64",
    "username": "alex",
    "uid": "501",
    "device_id": "MDM-7F4A2B"
  },
  "profile": "project",
  "ecosystem": "npm",
  "package_name": "@tanstack/query-core",
  "normalized_name": "@tanstack/query-core",
  "version": "5.59.20",
  "project_path": "/Users/alex/code/web-app",
  "root_kind": "project_root",
  "package_manager": "pnpm",
  "source_type": "pnpm-lockfile",
  "source_file": "/Users/alex/code/web-app/pnpm-lock.yaml",
  "has_lifecycle_scripts": false,
  "confidence": "high"
}
```

</details>

`confidence`:

- `high` — exact identity and version came from canonical metadata.
- `medium` — identity is reliable, but version or source is partial.
- `low` — config/path/spec reference only; not proof of an installed exact version.

Finding record (exposure-catalog match):

<details>
<summary>Example finding record</summary>

```json
{
  "record_type": "finding",
  "record_id": "finding:...",
  "schema_version": "0.1.0",
  "scanner_name": "bumblebee",
  "scanner_version": "v0.1.1",
  "run_id": "3a8c7d1e9f0b2a4c6d8e0f1a2b3c4d5e",
  "scan_time": "2026-05-15T18:22:01.482Z",
  "endpoint": {
    "hostname": "alex-mbp",
    "os": "darwin",
    "arch": "arm64",
    "username": "alex",
    "uid": "501",
    "device_id": "MDM-7F4A2B"
  },
  "profile": "deep",
  "finding_type": "package_exposure",
  "severity": "critical",
  "catalog_id": "advisory-2026-0042",
  "catalog_name": "example-pkg 1.2.3 (compromised release)",
  "ecosystem": "npm",
  "package_name": "example-pkg",
  "normalized_name": "example-pkg",
  "version": "1.2.3",
  "root_kind": "deep_home_root",
  "project_path": "/Users/alex/code/web-app",
  "source_type": "pnpm-lockfile",
  "source_file": "/Users/alex/code/web-app/pnpm-lock.yaml",
  "confidence": "high",
  "evidence": "exact name+version match (version=1.2.3)"
}
```

</details>

`record_id` is a content-addressed hash of a canonical identity tuple per
record type, stable across runs. Per-record-type field lists and dedupe
guidance: [docs/state-model.md](docs/state-model.md#record-identity-record_id).

## Exposure Catalog Format

Minimal JSON, exact `(ecosystem, name, version)` matching only:

```json
{
  "schema_version": "0.1.0",
  "entries": [
    {
      "id": "advisory-2026-0042",
      "name": "example-pkg 1.2.3 (compromised release)",
      "ecosystem": "npm",
      "package": "example-pkg",
      "versions": ["1.2.3"],
      "severity": "critical"
    }
  ]
}
```

The catalog must be a JSON object with `schema_version` and `entries`
keys. Bare top-level arrays are rejected. Unsupported future
`schema_version` values are rejected. Multiple catalog files can be
loaded together by pointing `--exposure-catalog` at a directory; see
the flag description above.

### Sample exposure catalogs

The [`threat_intel/`](threat_intel/) directory holds maintained exposure
catalogs built from public threat-intelligence reporting on recent
supply-chain campaigns, assembled with
[Perplexity Computer](https://www.perplexity.ai/computer) and updated
via PRs as new campaigns are reported. See
[`threat_intel/README.md`](threat_intel/README.md) for the current
catalog list and review guidance.

## License

Apache License 2.0. See [LICENSE](LICENSE).
