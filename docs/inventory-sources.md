# Inventory sources

This document describes, per ecosystem, where installed-package state lives
on disk, what `bumblebee` reads, and what it deliberately does not.

Per-ecosystem ordering below matches v0.1 prioritization, which was driven
by recent supply-chain incidents — see the [Why these ecosystems](#why-these-ecosystems)
section at the bottom for the reporting that informed it.

The `ecosystem` field on every record matches OSV ecosystem identifiers
where one exists (`npm`, `pypi`, `go`, `rubygems`, `packagist`, ...). For
ecosystems OSV does not yet enumerate, the value matches the
[Package URL](https://github.com/package-url/purl-spec) `type` convention
instead (`conda`). `mcp` and `editor-extension` are project-local values
for execution surfaces that do not map cleanly to a package registry;
both are emitted without resolved package versions.

## `ecosystem` vs source toolchain

pnpm, Yarn, and Bun lockfiles all install packages from the npm
registry, so their records emit `ecosystem=npm`. The specific manager
and source file are preserved on each record via `package_manager`
(`npm` / `pnpm` / `yarn` / `bun`) and `source_type` (`pnpm-lockfile`,
`yarn-lockfile`, `bun-lockfile`, ...). `--ecosystem` accepts the
OSV-aligned values above only; `--ecosystem npm` covers all four
package managers.

## Profile-to-source mapping

Each scan profile reads from a different slice of the sources below:

| Profile     | Sources walked                                                                                                                                                                                                |
|-------------|---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| `baseline` | Homebrew lib prefixes; `/Library/Python`; Linux system Python (`/usr/lib/python*`, plus `/usr/local/lib`); user Python (`~/.local/lib/python*`, `~/.local/share/pipx/venvs`, `pyenv`); language version managers (`asdf`, `nvm`, `rbenv`, `rvm`); `~/.cargo`; `~/go`; conda/pixi prefixes (`~/.pixi`, `~/miniconda3`, `~/anaconda3`, `~/miniforge3`, `~/mambaforge`, `~/micromamba`); editor-extension trees; MCP config locations; per-profile browser-extension trees (Chromium-family + Firefox-family, including common snap/flatpak paths). No project trees. |
| `project`   | Configured developer/project roots (`~/code`, `~/src`, `~/Developer`, `~/Projects`, `~/workspace`, and any explicit `--root`). All ecosystem parsers below apply within those trees.                            |
| `deep`      | Operator-supplied roots, typically a bare home directory during a campaign. Same ecosystem parsers; recommended only in combination with `--exposure-catalog` to emit `record_type=finding` records.            |

The `source_type` values emitted are the same across profiles. What
changes is the population of files the walker visits.

## npm

Files read:

- `package-lock.json`, `npm-shrinkwrap.json`, `node_modules/.package-lock.json`
  — lockfileVersion 1, 2, and 3 are all supported via a single union schema.
- `node_modules/<pkg>/package.json` and `node_modules/@scope/<pkg>/package.json`
  — bounded to those two depths. Subtree under `node_modules/<pkg>/` is not
  enumerated.

Captured fields emitted on the record: `package_name`, `version`,
`install_scope` (dev/prod), `direct_dependency`, `has_lifecycle_scripts`,
and `lifecycle_scripts` (the names of any defined npm lifecycle hooks:
`preinstall`, `install`, `postinstall`, `prepare`, `preprepare`,
`postprepare`). Lifecycle script bodies are NOT captured. The resolved
URL and integrity hash in the lockfile are read for parsing but are
intentionally not emitted in v0.1's slim schema (see
[`internal/model/model.go`](../internal/model/model.go)).

References:

- npm `package-lock.json` format: <https://docs.npmjs.com/cli/v10/configuring-npm/package-lock-json>
- npm scripts (lifecycle): <https://docs.npmjs.com/cli/v10/using-npm/scripts>

## pnpm

Files read:

- `pnpm-lock.yaml` (v5, v6, v9). A line-oriented parser reads the top-level
  `packages:` block and captures each version-bearing key plus its
  `dev:` flag and `requiresBuild` flag. `resolution:` integrity/tarball are
  read but not emitted on records in v0.1's slim schema.
  Other sections (`importers:`, `snapshots:`, `settings:`, ...) are ignored.
  The parser assumes pnpm's stable indent scheme (entry keys at exactly
  2 spaces; nested fields at 4+ spaces) and emits a one-shot diagnostic
  if a line under `packages:` deviates from that pattern. The pnpm-specific
  `requiresBuild` flag is surfaced via the boolean `has_lifecycle_scripts`;
  it is intentionally NOT placed in `lifecycle_scripts`, which is reserved
  for actual npm hook names (`install`, `postinstall`, ...).
- `node_modules/.pnpm/<name>@<version>[_peer]/node_modules/<name>/package.json`
  — pnpm's content-addressed install layout. We extract name and version
  from the store directory name and emit a medium-confidence installed
  record.

The on-disk encoding for scoped names in pnpm's store uses `+`:
`@tanstack+query-core@5.0.0`. The parser converts that back to
`@tanstack/query-core`.

References:

- pnpm lockfile schema (v9 notes): <https://pnpm.io/9.x/cli/install>
- pnpm symlinked node_modules layout: <https://pnpm.io/symlinked-node-modules-structure>

## Yarn

Files read:

- `yarn.lock` — both Yarn Classic v1 and Yarn Berry (v2+). Berry's
  `__metadata` block is recognized and skipped. For each top-level entry
  header (one or more comma-separated `name@spec` descriptors followed by
  `:`), we extract `package_name` (from the first descriptor) and
  `version`. `resolved` / `integrity` / `checksum` lines are read but
  not emitted on records in v0.1's slim schema.

Yarn PnP's `.pnp.cjs` and `.pnp.data.json` are NOT parsed in v0.1. The
`yarn.lock` file itself is authoritative for inventory and is present in
both linker modes.

Berry protocols (`workspace:`, `patch:`, `portal:`, `git+ssh:`, `file:`,
`http(s):`) are not decoded. The package name is extracted from the
header descriptor and `version` is read from the entry body exactly as
written in the lockfile. v0.1 does not emit `resolved` / `integrity` /
`checksum` on records, so operators who need to distinguish "a workspace
dep" from "a registry dep" should inspect the source `yarn.lock` directly
using the `source_file` field on the record.

References:

- Yarn Classic lockfile format: <https://classic.yarnpkg.com/lang/en/docs/yarn-lock/>
- Yarn Berry lockfile reference: <https://yarnpkg.com/configuration/yarnrc>

## Bun

Files read:

- `bun.lock` — Bun's text JSONC lockfile. The parser strips `//` and
  `/* */` comments and trailing commas, then JSON-parses. The schema
  `{"packages": { "<id>": ["<name>@<version>", {...}] }}` and the simpler
  `{"packages": { "<id>": {"version": "..."} }}` shape are both handled.
  Diagnostics: an unterminated `/* */` block comment is reported as a
  warning (the original bytes are then passed to `json.Unmarshal`, which
  produces a parse error with line/offset). Array-form entries whose
  first element does not parse as `<name>@<version>` are also reported
  as warnings so silent record loss is visible to operators.
  The sibling `package.json` next to a parsed `bun.lock` is read only
  to annotate `direct_dependency`; no other `package.json` files are
  walked by the Bun scanner.
- `bun.lockb` — Bun's binary lockfile. NOT parsed in v0.1; a diagnostic is
  emitted noting presence. Bun 1.1+ defaults to text `bun.lock`, so this
  case is rare on recent installs.

References:

- Bun text lockfile: <https://bun.com/docs/install/lockfile>

## PyPI

Files read:

- `*.dist-info/METADATA` (PEP 566) plus adjacent `INSTALLER` (PEP 376) and
  `direct_url.json` (PEP 610).
- Legacy `*.egg-info/PKG-INFO` (lower confidence).

We read only the RFC-822 header block of METADATA / PKG-INFO and stop at
the first blank line, so the description payload is never scanned.

References:

- PEP 566 (METADATA): <https://peps.python.org/pep-0566/>
- PEP 376 (database of installed dists): <https://peps.python.org/pep-0376/>
- PEP 610 (direct URL origin): <https://peps.python.org/pep-0610/>
- PEP 503 (name normalization): <https://peps.python.org/pep-0503/>

## Go modules

Files read:

- `go.sum` — authoritative content-hash record of every module version Go
  has fetched into the module cache. Each `module v1.2.3 h1:...` line
  produces a high-confidence record. `module v1.2.3/go.mod` companion
  lines are deduplicated against the module line.
- `go.mod` — the `require` block. Direct vs indirect is inferred from the
  `// indirect` trailing comment. Lower confidence than `go.sum` because
  `go.mod` requires may not all be in the final build set.

Baseline includes `~/go` (and therefore `~/go/pkg/mod`, the per-user
module cache) when it exists. Each cached module checks in as
`<mod>@<version>/go.mod`, so on Go-heavy hosts the baseline output can be
dominated by Go cache records — often tens of thousands of lines. That
is intentional package-presence coverage of every module version Go has
ever downloaded for the user, not a project inventory. To scope a run
down, pair `--ecosystem` with a non-go selection (e.g.
`--ecosystem npm,pypi`) or run the `project` profile against specific
workspaces.

We do not walk into the module cache's source-file subtrees; matching
is filename-based on `go.mod` / `go.sum` only, and the individual
module directories are not enumerated for anything else.

References:

- `go.sum` and `go.mod` reference: <https://go.dev/ref/mod#go-sum-files>
- Module cache layout: <https://go.dev/ref/mod#module-cache>

## RubyGems / Bundler

Files read:

- `Gemfile.lock` — `GEM`, `GIT`, and `PATH` sections. Only top-level
  `    name (version)` lines (exactly 4 spaces of indent) are captured;
  dependency lines at 6+ spaces are ignored to avoid double-counting
  transitive deps.
- `*.gemspec` under `specifications/<name>-<ver>.gemspec` or
  `gems/<name>-<ver>/<name>.gemspec` *when* the great-grandparent looks
  like a recognized installed-gems root (e.g. a Ruby ABI directory like
  `3.2.0` under `gems/`, a sibling `specifications/` directory, or a
  Bundler `vendor/bundle/ruby/<ver>/` layout). Arbitrary vendored
  source trees that happen to contain a `gems/<x>-<y>/*.gemspec` shape
  are rejected to avoid duplicating Gemfile.lock entries with a
  different `project_path`. A regex-based reader extracts `s.name` and
  `s.version` from the canonical generated forms (`s.version = "1.2.3"`
  and `s.version = Gem::Version.new("1.2.3")`); no Ruby is interpreted.
  Gemspecs that compute fields procedurally fall back to the parent
  directory `<name>-<ver>` split, then to the filename split.

References:

- Bundler `Gemfile.lock`: <https://bundler.io/v2.5/man/gemfile.5.html>
- RubyGems specification format: <https://guides.rubygems.org/specification-reference/>

## Composer / Packagist

Files read:

- `composer.lock` — JSON. Both `packages` (prod) and `packages-dev` (dev)
  arrays are captured. Each entry yields `package_name`, `version`, and
  `install_scope` (prod/dev). `dist.url`, `dist.shasum`, and per-package
  `type` are read for parsing but not emitted on records in v0.1's slim
  schema.
- `vendor/composer/installed.json` — both Composer v1 (root array) and v2
  (`{"packages": [...]}`) shapes are recognized. An empty v2 envelope
  (`{"packages": []}`) is accepted as a valid empty file and does not
  fall through to a v1 parse error.

References:

- `composer.lock` format: <https://getcomposer.org/doc/01-basic-usage.md#commit-your-composer-lock-file-to-version-control>
- `vendor/composer/installed.json` (Composer v2): <https://getcomposer.org/doc/articles/plugins.md>

## Conda / pixi

Files read:

- `<env>/conda-meta/<name>-<version>-<build>.json` — the per-package
  install record conda, mamba, micromamba, and pixi all write when a
  package is linked into an environment prefix. Each record carries
  exact `name`, `version`, `build`, and channel fields emitted by the
  package builder, so a parsed record is high-confidence proof that the
  named package version is currently linked into the surrounding
  environment.

The walker matches any `*.json` file whose immediate parent directory is
`conda-meta`; the sibling `history` text file is not JSON and is not
matched. The `conda-meta` schema has many additional fields
(`files`, `paths_data`, `link`, `depends`, `constrains`, ...) which are
deliberately not decoded; only `name`, `version`, `channel`, and
`schannel` are read.

The environment prefix that owns the record (the parent of `conda-meta/`)
is recorded as `project_path` so receivers can group records by
environment. `package_manager` is `conda` for records installed from a
conda channel and `pip` for pip-installed packages that conda has
recorded under the same `conda-meta/` directory (these have
`schannel: "pypi"`); this preserves the ability to tell pip and conda
installs apart inside a shared env.

The `pixi.lock` project lockfile and `pixi.toml` / `pyproject.toml`
`[tool.pixi]` manifests are NOT parsed in this release. `conda-meta` is
the authoritative installed-state source and is shared by every
conda-compatible package manager, so it carries the highest-signal
inventory of what is actually linked into an environment right now.

The baseline profile adds `~/.pixi`, `~/miniconda3`, `~/anaconda3`,
`~/miniforge3`, `~/mambaforge`, and `~/micromamba` as user-package roots
when present; project-tree scans pick up `.pixi/envs/*/conda-meta/`
inside walked workspaces automatically.

The emitted `ecosystem` value is `conda`. OSV does not yet define a
conda ecosystem identifier; the value matches the
[Package URL](https://github.com/package-url/purl-spec/blob/master/PURL-TYPES.rst#conda)
`pkg:conda/<name>@<version>` convention.

References:

- conda-meta record schema (per-package JSON): <https://docs.conda.io/projects/conda/en/latest/user-guide/concepts/pkg-specs.html>
- Pixi environments and lockfile layout: <https://pixi.sh/latest/reference/project_configuration/>
- PURL `conda` type: <https://github.com/package-url/purl-spec/blob/master/PURL-TYPES.rst#conda>

## MCP server configs

Files read (JSON only):

- `mcp.json`, `.mcp.json`, `claude_desktop_config.json`, `mcp_config.json`,
  `mcp_settings.json`, `cline_mcp_settings.json`.
- `settings.json` when its parent directory is `.gemini` (Gemini CLI /
  Gemini Code Assist user settings). Dispatch is path-aware because
  `settings.json` is an ambiguous basename — most notably VS Code's user
  settings file uses the same name and must not be fed to the MCP parser.
  The top-level `mcpServers` envelope is the same shape as Cursor /
  Claude Code; the existing JSON parser handles it without changes.

Non-JSON MCP host configs (e.g. Codex `config.toml`, Continue YAML)
are not parsed in v0.1 even when the surrounding host directory is
walked.

### Locations and envelopes

Well-known locations (not exhaustive — the walker finds these by basename
anywhere under a configured root):

- `~/.cursor/mcp.json`
- `~/.codeium/windsurf/mcp_config.json`
- Claude Code user-home: `~/.claude/.mcp.json`, plus any `.mcp.json` /
  `mcp.json` written under `~/.claude/` plugin subdirectories.
- Gemini CLI / Gemini Code Assist user-home: `~/.gemini/settings.json`
  (top-level `mcpServers`).
- macOS Claude Desktop: `~/Library/Application Support/Claude/claude_desktop_config.json`
- Linux Claude Desktop: `~/.config/Claude/claude_desktop_config.json`,
  `~/.config/Claude Code/claude_desktop_config.json`
- Windows Claude Desktop: `%APPDATA%\Claude\claude_desktop_config.json`
- Per-project: `.mcp.json` at a repo root

Recognized envelopes:

- `{ "mcpServers": {...} }`
- `{ "servers": {...} }`
- flat `{ "<id>": {...} }`

A flat entry is recognized when it carries `command`, `url`, non-empty
`args`, or a `type` field. Environment values and environment key names
are never captured — neither is retained in v0.1's slim schema.

### Package identity

For each server, `PackageName` is parsed from the command and args:

- `npx -y @modelcontextprotocol/server-github` →
  `@modelcontextprotocol/server-github`
- `uvx mcp-server-time` → `mcp-server-time`
- `python -m mypkg.server` → `python:mypkg.server`

If an npm-style selector is present (`@playwright/mcp@latest`,
`left-pad@1.2.3`), the full spec is preserved in `requested_spec` and
`PackageName` is normalized to the bare name. The configured server id is
always preserved in `server_name`.

For `uv run <script-or-dir>` without `--from <pkg>`, no package identity
is inferred; the record falls back to the server id with `confidence=low`.
`uvx`, `uv tool run <pkg>`, and `uv run --from <pkg> ...` use the
published package name.

Docker/OCI image refs split a pinned tag into `version`:
`hashicorp/terraform-mcp-server:0.4.0` becomes
`package_name=hashicorp/terraform-mcp-server`, `version=0.4.0`. Untagged
images keep an empty version rather than synthesizing `latest`.
Registry-port refs split only on the colon after the last slash. Digest
refs (`name@sha256:...`) stay in `package_name` with an empty version.

### Matching behavior

Example jq filters:

```
# All MCP server records
jq 'select(.record_type == "package" and .source_type == "mcp-config")' inventory.ndjson

# MCP records that pinned a version selector (@latest, @1.2.3, ...)
jq 'select(.source_type == "mcp-config" and (.requested_spec // "") != "")
    | {server_name, package_name, requested_spec, source_file}' inventory.ndjson
```

For npm/PyPI/uv MCP launchers the record's `version` field stays empty:
MCP configs reference packages by spec without pinning to an installed
version, so installed-version resolution is not possible without running
the package manager — the requested selector (if any) is recorded in
`requested_spec`. Docker launchers are the exception: an explicit image
tag is captured in `version` directly, since the tag is the OCI
equivalent of a pinned version.

Confidence is recorded as `low` for MCP records by default. Docker
launchers whose image reference carries a pinned tag or `@sha256:`
digest are bumped to `medium`: the tag/digest is the only MCP shape
that ties a configured server to an immutable identity. Wording stays
conservative — these are configured references, not running processes,
and bumblebee never executes anything during the scan.

`root_kind` on an MCP record is not always `mcp_config_root`. The
scanner prefers the `root_kind` of the enclosing configured root when
one exists: an `.mcp.json` discovered inside a `project_root` is tagged
`project_root`, and the same file under a `deep_home_root` is tagged
`deep_home_root`. `mcp_config_root` is the fallback when no enclosing
root contains the file (e.g. an explicit MCP root passed through the
scanner config).

Remote MCP entries (sse/http transports identified by a `url`,
`serverUrl`, or `httpUrl` field with no `command`) are emitted as
package records with `package_manager=mcp-remote`. The sanitized
endpoint is recorded in `requested_spec` reduced to `scheme://host`
(or `//host` for scheme-less network-path references) — userinfo,
query, fragment, and path are all dropped so embedded credentials
cannot leak, even when they hide in a path segment — and
`package_name` falls back to the server id. Headers and env values
are never captured. The URL is not treated as a package identity:
catalog matching against `mcp-remote` records is limited to records
whose package_name (the server id) appears in a catalog with an empty
version, which is intentionally narrow.

Exposure-catalog matches against MCP records work on name only when
the catalog entry's `versions` includes `""`, plus exact-version
matching for docker launchers with pinned tags. v0.1 does not attempt
npm/PyPI resolution of MCP specs.

References:

- MCP introduction: <https://modelcontextprotocol.io/>
- MCP server configuration: <https://modelcontextprotocol.io/quickstart/user>

## Browser extensions (Chromium-family + Firefox)

Files read:

- Chromium-family (Chrome, Chromium, Brave, Edge, Vivaldi, Arc, Comet):
  `<profile>/Extensions/<extension_id>/<version>/manifest.json`.
  The `<extension_id>` is the 32-char a–p id. When `name` is a
  `__MSG_<key>__` placeholder, we read
  `<version>/_locales/<default_locale>/messages.json` (falling back to
  `en`) to resolve it. No other extension or profile asset is opened.
- Firefox-family (Firefox, LibreWolf, Waterfox):
  `<profile>/extensions.json`. We emit one record per add-on with
  `type=extension`; themes and system add-ons are skipped. Per-extension
  XPI/source files under `<profile>/extensions/` are not opened.

Captured fields: extension name (from `manifest.name` or
`defaultLocale.name`), version, extension id (in `normalized_name`),
and profile path (`project_path`). `package_manager` records the install
mechanism — `chromium-extension` or `firefox-extension` — not the
browser brand. The brand (Chrome, Brave, Edge, Vivaldi, Arc, Comet,
LibreWolf, Waterfox, ...) can be recovered from `source_file`, which
embeds the per-browser profile path. Every record carries
`source_type=browser-extension` and `root_kind=browser_extension_root`.

Profile coverage on `baseline`: the curated default roots include
`Default` and `Profile 1`..`Profile 9` for each Chromium-family browser,
plus the Firefox-family profile parents. Profiles outside that range
must be passed via `--root`. The deliberately narrow root list keeps the
walker out of every other Chromium / Firefox subtree (cookies, Login
Data, IndexedDB, Local Storage, Cache), which are TCC-protected on
macOS and privacy-sensitive on every host.

Interaction with `--profile deep`: deep accepts a bare home root and
therefore overlaps the baseline browser-extension roots. The walker
still only opens files matched by exact path shape — Chromium
`Extensions/<id>/<version>/manifest.json` and Firefox profile
`extensions.json`. Sibling profile files (`Cookies`, `Cookies-journal`,
`Login Data`, `Login Data For Account`, `Web Data`, `History`, the
`IndexedDB/`, `Local Storage/`, `Session Storage/`, and `Cache/`
subtrees) never match a scanner dispatch and are never read, even when
they fall inside the deep-scan walk. On macOS the curated excludes
additionally drop the entire `Library/Application Support/<browser>`
subtree from a deep walk, so deep on macOS picks up browser extensions
only when the operator passes the per-profile `Extensions/` directory
as an explicit `--root` (the baseline curated entry). On Linux the
deep walk descends into `~/.config/<browser>/<profile>/` but, again,
only opens path-shape-matched manifests.

Example jq filters:

```
# All browser-extension records
jq 'select(.record_type == "package" and .source_type == "browser-extension")' inventory.ndjson

# One row per (install mechanism, extension id, version) — the browser brand
# lives in source_file, since package_manager is chromium-extension/firefox-extension
jq -r 'select(.source_type == "browser-extension")
       | [.package_manager, .normalized_name, .version, .package_name, .source_file] | @tsv' inventory.ndjson
```

References:

- Chromium extension manifest: <https://developer.chrome.com/docs/extensions/reference/manifest>
- Chromium extension on-disk layout: <https://chromium.googlesource.com/chromium/src/+/refs/heads/main/chrome/common/extensions/docs/examples/howto/contentscript_xhr/README.md>
- Firefox profile / `extensions.json`: <https://support.mozilla.org/en-US/kb/profiles-where-firefox-stores-user-data>

## Editor extensions (VS Code, Cursor, Windsurf, VSCodium)

Files read:

- `<extensions-root>/<publisher>.<name>-<version>[-<platform>]/package.json`

Known extensions roots (matched by trailing path segments):

- `~/.vscode/extensions`
- `~/.vscode-server/extensions` (remote dev)
- `~/.vscode-insiders/extensions`
- `~/.cursor/extensions`
- `~/.cursor-server/extensions`
- `~/.windsurf/extensions`
- `~/.windsurf-server/extensions`
- `~/.vscodium/extensions`

Captured fields emitted on the record: `package_name` (the full
`publisher.name` identifier), `version`, and `package_manager` (vscode /
cursor / windsurf / vscodium, inferred from the path).

Extensions frequently ship a vendored `node_modules/` tree and sometimes
a `package-lock.json` / `yarn.lock` / `pnpm-lock.yaml` next to their
`package.json`. v0.1 dispatches by filename, so those vendored files are
parsed by the generic npm/pnpm/yarn/bun parsers and emit `ecosystem=npm`
records whose `source_file` points inside `<extensions-root>/<ext>/...`.
This means an extension that vendors `lodash@4.17.21` shows up both as
an `editor-extension` record (the extension itself) and as `npm` records
(its vendored dependencies). That is intentional package-presence
coverage — a malicious npm release bundled inside an extension is still
an installed-package exposure on the host — but it does inflate npm
counts under baseline on developers with many editor extensions. We do
not scope npm/yarn/pnpm/bun dispatch by parent `root_kind` in v0.1
because the walker dispatches on filename without per-root context;
adding that scoping is a deliberate follow-up rather than a release
blocker.

References:

- VS Code extension `package.json`: <https://code.visualstudio.com/api/references/extension-manifest>
- VS Code extension on-disk layout: <https://code.visualstudio.com/docs/configure/extensions/extension-marketplace#_where-are-extensions-installed>

## Why these ecosystems

Ecosystems beyond npm + PyPI were prioritized by recent reporting on
active supply-chain compromise campaigns:

- **Wiz, *Mini Shai-Hulud strikes again — TanStack & more npm packages
  compromised*** (May 2026). npm and PyPI compromises across TanStack,
  UiPath, Mistral AI, OpenSearch, and others.
  <https://www.wiz.io/blog/mini-shai-hulud-strikes-again-tanstack-more-npm-packages-compromised>
- **Wiz, *Mini Shai-Hulud supply-chain — SAP npm + PyPI***. SAP npm
  packages compromised, `intercom-client@7.0.5` malicious release, PyPI
  `lightning` 2.6.2 / 2.6.3.
  <https://www.wiz.io/blog/mini-shai-hulud-supply-chain-sap-npm>
- **Wiz, *Shai-Hulud 2.0***. Broad npm campaign hitting Zapier, ENS,
  PostHog, Postman, and others.
  <https://www.wiz.io/blog/shai-hulud-2-0-ongoing-supply-chain-attack>
- **Socket, *Malicious Ruby gems and Go modules steal secrets, poison CI***
  (BufferZoneCorp). RubyGems and Go modules targeting CI credential theft.
  <https://socket.dev/blog/malicious-ruby-gems-and-go-modules-steal-secrets-poison-ci>
- **Socket, *Mini Shai-Hulud Packagist — malicious `intercom/intercom-php`
  compromise***. Composer plugin execution as the install-time exec
  primitive.
  <https://socket.dev/blog/mini-shai-hulud-packagist-malicious-intercom-php-package-compromise>
- **Socket, *PyTorch Lightning PyPI package compromised* (`lightning`
  2.6.2, 2.6.3)**.
  <https://socket.dev/blog/lightning-pypi-package-compromised>

MCP and editor extensions are included because both have direct execution
on developer endpoints, both have grown rapidly in 2025–2026, and both lack
strong installed-state correlation tooling today.

## What this collector deliberately does not do

- No package-manager command execution. No `npm ls`, no `pnpm list`, no
  `pip show`, no `go list`, no `bundle list`, no `composer show`.
- No source-file reading. Only the metadata files listed above. The
  walker visits directories; the scanners open only the targeted files.
- No bundled threat intelligence. Bumblebee ships no built-in advisory
  feed and does no automated lookups against npmjs advisories, OSV,
  Socket feeds, GHSA, PyPA advisory DB, or any similar source. Optional
  exact-version correlation is available when the operator supplies an
  exposure catalog via `--exposure-catalog` (see
  [`internal/exposure/exposure.go`](../internal/exposure/exposure.go) for
  the schema and matching rules); without one, the output is pure
  inventory and downstream correlation is the consumer's job.
- No secret extraction. MCP `env` values and key names are both dropped.
  `.env` / `.envrc` are skipped even outside excluded directories.

## Not currently covered

- Cargo (`Cargo.lock`).
- Maven / Gradle (`pom.xml`, lockfiles).
- NuGet (`packages.lock.json`).
- Hex (`mix.lock`).
- Swift PM (`Package.resolved`).
- Yarn PnP (`.pnp.data.json`); the `yarn.lock` parser still covers PnP
  installs because PnP keeps `yarn.lock`.
- Bun binary `bun.lockb` decoder. Bun 1.1+ defaults to text `bun.lock`.
- Safari extensions. Safari's on-disk layout
  (`~/Library/Safari/Extensions/`, `~/Library/Containers/<bundle-id>`)
  is TCC-protected and is not enumerated.
