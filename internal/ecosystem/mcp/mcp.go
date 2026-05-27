// Package mcp scans Model Context Protocol server configuration files.
//
// MCP configs are JSON. Several clients use slightly different envelopes
// but the same per-server shape:
//
//	{ "mcpServers": { "<id>": { "command": "...", "args": [...] } } }
//	{ "servers":    { "<id>": { ... } } }                            // some clients
//	{ "<id>": { "command": "...", "args": [...] } }                  // flat
//
// One record is emitted per configured server. PackageName is the bare
// package spec parsed from the command/args (e.g.
// "@modelcontextprotocol/server-github"); when the configured argument
// includes a selector ("@latest", "@1.2.3"), that selector is preserved
// in RequestedSpec. Version remains empty for npm/PyPI/uv launchers
// because those MCP configs reference packages by spec without resolving
// to an installed version. Docker/OCI launchers are the exception: an
// explicit image tag is split off into Version, since the tag is the
// OCI-equivalent of a pinned version. The configured server id is
// preserved in ServerName so the alias survives even when PackageName
// is derived from the command/args.
//
// Env values are never captured; env key names are not retained either,
// since the slim v0.1 record schema has no free-form notes field.
//
// Remote MCP entries (sse/http transports identified by a url,
// serverUrl, or httpUrl field with no command) are emitted with
// PackageManager="mcp-remote". The configured endpoint is recorded in
// RequestedSpec reduced to "scheme://host" (or "//host" for
// scheme-less network-path references): userinfo, query, fragment,
// and path are all dropped so credentials embedded in any of those
// cannot leak. PackageName falls back to the server id; the URL is
// not treated as a package identity.
package mcp

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/perplexityai/bumblebee/internal/model"
)

const Ecosystem = model.EcosystemMCP

type Scanner struct {
	MaxFileSize int64
	Emit        func(model.Record)
	Diag        func(level, path, msg string)
}

// IsKnownMCPConfig returns true if the basename matches a known MCP config
// file. The walker uses this to dispatch.
func IsKnownMCPConfig(base string) bool {
	switch base {
	case "mcp.json",
		"claude_desktop_config.json",
		"mcp_config.json",
		"mcp_settings.json",
		"cline_mcp_settings.json",
		".mcp.json":
		return true
	}
	return false
}

// IsGeminiSettingsJSON reports whether path is the Gemini CLI / Gemini Code
// Assist user settings file (`<home>/.gemini/settings.json`). Dispatch is
// path-aware rather than basename-aware because `settings.json` is a
// common, ambiguous filename (notably the VS Code user settings file)
// that we must not feed to the MCP parser globally. The file's top-level
// `mcpServers` envelope is already handled by ScanConfig.
func IsGeminiSettingsJSON(path string) bool {
	return filepath.Base(path) == "settings.json" &&
		filepath.Base(filepath.Dir(path)) == ".gemini"
}

type serverEntry struct {
	Command   string                 `json:"command"`
	Args      []string               `json:"args"`
	Env       map[string]interface{} `json:"env"`
	URL       string                 `json:"url"`
	ServerURL string                 `json:"serverUrl"`
	HTTPURL   string                 `json:"httpUrl"`
	Type      string                 `json:"type"`
}

// remoteURL returns the first non-empty remote URL field on the entry.
// Multiple clients use different field names for the same thing; the
// order here mirrors the order they were standardized in. Headers, env,
// and any authorization material are deliberately not surfaced.
func (e serverEntry) remoteURL() string {
	switch {
	case e.URL != "":
		return e.URL
	case e.ServerURL != "":
		return e.ServerURL
	case e.HTTPURL != "":
		return e.HTTPURL
	}
	return ""
}

// sanitizeRemoteURL returns a representation of u safe to record. Only
// scheme + host are preserved so the record remains useful for endpoint
// identity at the host level without leaking secrets: userinfo, query,
// fragment, and path are all dropped. Tokens are commonly embedded in
// any of those four (including path segments like "/mcp/<token>"), so
// the conservative approach is to drop them all.
//
// Scheme-less network-path references ("//host/path") are recognized
// and reduced to "//host" with userinfo stripped. If parsing fails or
// no host can be recovered, the function returns "" rather than
// emitting a raw, potentially secret-bearing string.
func sanitizeRemoteURL(u string) string {
	if u == "" {
		return ""
	}
	parsed, err := url.Parse(u)
	if err != nil {
		return ""
	}
	host := parsed.Host
	if host == "" {
		return ""
	}
	if parsed.Scheme != "" {
		return parsed.Scheme + "://" + host
	}
	// Scheme-less network-path reference ("//host/path"): preserve the
	// "//host" form so the record still identifies a network endpoint
	// without leaking userinfo or path-embedded credentials.
	if strings.HasPrefix(u, "//") {
		return "//" + host
	}
	return ""
}

func (s *Scanner) ScanConfig(path string, base model.Record) error {
	data, err := s.readBounded(path)
	if err != nil {
		return err
	}

	// Try envelope { mcpServers: {...} } first, then { servers: {...} }, then
	// flat object. Malformed JSON is surfaced as a warn diagnostic so the
	// file is not silently skipped.
	var env1 struct {
		MCPServers map[string]serverEntry `json:"mcpServers"`
		Servers    map[string]serverEntry `json:"servers"`
	}
	servers := map[string]serverEntry{}
	envErr := json.Unmarshal(data, &env1)
	if envErr == nil {
		for k, v := range env1.MCPServers {
			servers[k] = v
		}
		for k, v := range env1.Servers {
			if _, ok := servers[k]; !ok {
				servers[k] = v
			}
		}
	}
	var flatErr error
	if len(servers) == 0 {
		// Fall back to a flat map. Conservative widening: accept any entry
		// that carries enough signal to look like an MCP server entry
		// (command, URL, args, or an explicit transport type).
		var flat map[string]serverEntry
		flatErr = json.Unmarshal(data, &flat)
		if flatErr == nil {
			for k, v := range flat {
				if v.Command != "" || v.remoteURL() != "" || len(v.Args) > 0 || v.Type != "" {
					servers[k] = v
				}
			}
		}
	}
	if len(servers) == 0 {
		if envErr != nil && flatErr != nil {
			if s.Diag != nil {
				s.Diag("warn", path, "parse MCP config: "+envErr.Error())
			}
			return nil
		}
		if s.Diag != nil {
			s.Diag("info", path, "no MCP servers parsed")
		}
		return nil
	}

	ids := make([]string, 0, len(servers))
	for k := range servers {
		ids = append(ids, k)
	}
	sort.Strings(ids)
	for _, id := range ids {
		srv := servers[id]
		r := base
		r.Ecosystem = Ecosystem
		r.PackageManager = "mcp"
		r.SourceType = "mcp-config"
		r.SourceFile = path
		r.ProjectPath = filepath.Dir(path)
		r.RootKind = model.RootKindMCPConfig
		r.ServerName = id
		r.Confidence = "low"

		// Remote-URL entries (sse / http transports) have no command to
		// parse. Surface the sanitized endpoint via RequestedSpec and tag
		// the record as a remote MCP reference so receivers can route it
		// without re-parsing the file. Headers, env, and any userinfo or
		// query-string credentials are deliberately not retained.
		if srv.Command == "" {
			if u := sanitizeRemoteURL(srv.remoteURL()); u != "" {
				r.PackageName = id
				r.NormalizedName = strings.ToLower(id)
				r.PackageManager = "mcp-remote"
				r.RequestedSpec = u
				s.Emit(r)
			}
			continue
		}

		spec, launcher := inferPackageFromArgs(srv.Command, srv.Args)
		var name, selector, version string
		// Docker/OCI image refs encode the version as `image:tag`, not
		// as the npm-style `@selector` that splitSpec assumes. Run them
		// through the OCI splitter instead so the tag becomes Version
		// and a digest ref (`name@sha256:...`) is preserved on the name
		// side. Conservative around registry-port refs like
		// `localhost:5000/foo/bar:1.2.3`: only split on the colon after
		// the last slash.
		if launcher == "docker" {
			name, version = splitDockerImageRef(spec)
		} else {
			name, selector = splitSpec(spec)
		}
		// Drop unresolved shell variables — these are not package identities.
		// Example: `${CLAUDE_PLUGIN_ROOT}/foo` left literal by the loader.
		if looksUnresolvedShellVar(name) {
			name = ""
			spec = ""
			selector = ""
		}
		// Reject obvious non-package references (URLs, git refs, local
		// paths, tarballs) so a raw URL/path never round-trips into
		// PackageName or RequestedSpec. npm-style launchers accept these
		// forms, but they carry no package identity and may embed
		// credentials (e.g. a --registry value or a tarball URL with a
		// userinfo segment). Docker image refs are validated separately
		// by splitDockerImageRef and stay on this path.
		if launcher != "docker" && !looksLikePackageSpec(spec) {
			name = ""
			spec = ""
			selector = ""
		}
		if name == "" {
			name = id
		}
		r.PackageName = name
		r.NormalizedName = strings.ToLower(name)
		// Surface non-npm launchers (docker images, python tools) on the
		// record so receivers can tell a container image apart from an npm
		// spec without re-parsing the args.
		if launcher != "" {
			r.PackageManager = launcher
		}
		if version != "" {
			r.Version = version
		}
		if selector != "" {
			r.RequestedSpec = spec
		}
		// Pinned docker image refs are the only MCP shape that ties a
		// configured server to an immutable identity: a tag or digest
		// names a specific image. Bump confidence to "medium" so
		// exposure consumers can distinguish these from the larger pool
		// of spec-only npm/uv launches. Wording elsewhere stays
		// conservative — this is still a configured reference, not a
		// running process.
		if launcher == "docker" && (version != "" || strings.Contains(name, "@sha256:")) {
			r.Confidence = "medium"
		}
		s.Emit(r)
	}
	return nil
}

// looksUnresolvedShellVar reports whether s contains a literal variable
// reference the loader never expanded, in any of the common forms:
// ${VAR}, $VAR (POSIX), or %VAR% (Windows %APPDATA%-style). We treat
// such values as opaque rather than packages.
func looksUnresolvedShellVar(s string) bool {
	if strings.Contains(s, "${") {
		return true
	}
	// $VAR — require a leading "$" followed by an identifier char so a
	// literal "$" elsewhere in a path doesn't trigger.
	for i := 0; i < len(s)-1; i++ {
		if s[i] == '$' {
			c := s[i+1]
			if c == '_' || (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') {
				return true
			}
		}
	}
	// %VAR% — Windows-style with at least one identifier char between
	// the percents.
	if first := strings.Index(s, "%"); first >= 0 {
		if second := strings.Index(s[first+1:], "%"); second > 0 {
			between := s[first+1 : first+1+second]
			ok := true
			for _, c := range between {
				if !(c == '_' || (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9')) {
					ok = false
					break
				}
			}
			if ok {
				return true
			}
		}
	}
	return false
}

// inferPackageFromArgs returns a best-effort package spec for common
// command/args shapes and an optional launcher tag.
//
// Returned launcher is one of "", "docker", "uv". An empty launcher
// preserves the default package_manager ("mcp"). A non-empty launcher
// signals that the value is not an npm/pypi spec — callers should mark
// the record so a docker image or a uv tool is not later interpreted as
// an npm package by exposure matching.
//
// Supported launchers:
//
//	npx / bunx                          -> first non-flag arg
//	pnpm/yarn/bun/npm dlx|exec|x        -> first non-flag arg past sub
//	  (run/bare <script>, create/init   -> no spec; caller uses server id)
//	uvx / pipx                          -> first non-flag arg
//	uv / uv tool run                    -> first non-flag arg past sub,
//	                                       also honors --from <pkg>
//	docker run                          -> last positional non-flag is image
//	python / python3 -m mod             -> "python:<mod>"
func inferPackageFromArgs(cmd string, args []string) (spec, launcher string) {
	bn := filepath.Base(cmd)
	switch bn {
	case "npx", "bunx":
		// npx/bunx accept "--package <pkg>" / "--package=<pkg>" to name the
		// package explicitly when it differs from the entry-point command
		// that follows "--". Honor that first so the flag's value wins over
		// the positional entry-point name.
		//
		// Restrict the scan to the launcher-parsed prefix: stop at "--" and
		// at the first positional (non-flag) token, since anything after
		// either is the child command's own args and is not interpreted by
		// npx/bunx. Otherwise `npx foo --package @npmcli/bar` would be
		// misread as @npmcli/bar instead of foo.
		if spec := scanExplicitPackage(args, nil); spec != "" {
			return spec, ""
		}
		return firstNonFlag(args, nil, npmValueTakingFlags), ""
	case "pnpm", "yarn", "bun", "npm":
		// We read a package identity only from an executor subcommand:
		// dlx/exec/x (or the separate npx/bunx handled above). The positional
		// after it — or --package — is the spec.
		//
		// Any other first token gets no package identity: return an empty
		// spec and let the caller fall back to the server id at low
		// confidence, like "uv run <script>" below. That stops a local-script
		// launcher (`run <script>`, `npm start`, bare `yarn dev`) from leaking
		// its script name as a package — the reported bug where
		// `bun run … start` became the package "start". create/init get the
		// same treatment: they name a create-<name> package we deliberately
		// don't resolve (initializers don't launch servers). See mcp_test.go
		// for these and the flag-ordering edge case.
		//
		// scanExplicitPackage / firstNonFlag honor "npm exec --package=<pkg>"
		// and stop at "--", so `npm exec foo -- --package @npmcli/bar` -> foo.
		execSubcommands := map[string]bool{"dlx": true, "exec": true, "x": true}
		if !execSubcommands[firstNonFlag(args, nil, npmValueTakingFlags)] {
			return "", ""
		}
		if spec := scanExplicitPackage(args, execSubcommands); spec != "" {
			return spec, ""
		}
		return firstNonFlag(args, execSubcommands, npmValueTakingFlags), ""
	case "uvx":
		return firstNonFlag(args, nil, nil), "uv"
	case "uv":
		// Recognize "uv tool run <pkg>" and "uv run <pkg>". Honor "--from <pkg>"
		// when present: uv allows the entry-point name and the package name
		// to differ, and only --from carries the package identity.
		//
		// Without "--from", "uv run <script-or-dir>" invokes a local script
		// or a project in a directory rather than a published package, so
		// the first positional is a path, not a package identity. Detect
		// "uv run" (no "tool" subcommand, no "--from") and return an empty
		// spec so the caller falls back to the server id with low
		// confidence. "uv tool run <pkg>" is a published-tool invocation
		// and is handled below.
		hasTool := false
		for _, a := range args {
			if a == "tool" {
				hasTool = true
				break
			}
		}
		for i := 0; i < len(args); i++ {
			if args[i] == "--from" && i+1 < len(args) {
				return args[i+1], "uv"
			}
		}
		if !hasTool {
			return "", "uv"
		}
		return firstNonFlag(args, map[string]bool{
			"tool": true, "run": true,
		}, nil), "uv"
	case "pipx":
		// pipx is the PyPI-equivalent of npx and uvx. Honor "pipx run --spec <pkg> <entry>"
		// so an explicit --spec wins over the entry-point name when they differ.
		for i := 0; i < len(args); i++ {
			if args[i] == "--spec" && i+1 < len(args) {
				return args[i+1], "pipx"
			}
		}
		return firstNonFlag(args, map[string]bool{"run": true}, nil), "pipx"
	case "docker", "podman":
		// docker run [opts] <image> [cmd...]. Walk args: skip "run" and any
		// flags (with or without `=`). The first positional after that is
		// the image reference. Be conservative about flags that take a
		// separate value argument.
		valueTakingFlags := map[string]bool{
			"-e": true, "--env": true, "--env-file": true,
			"-v": true, "--volume": true, "--mount": true,
			"-p": true, "--publish": true,
			"--name": true, "--network": true, "--user": true, "-u": true,
			"--workdir": true, "-w": true,
			"--entrypoint": true, "--label": true, "-l": true,
			"--add-host": true, "--platform": true,
		}
		started := false
		for i := 0; i < len(args); i++ {
			a := args[i]
			if !started {
				if a == "run" || a == "container" {
					started = true
					continue
				}
				// Some configs omit the explicit subcommand and start with
				// flags before the image. Treat that as already started.
				started = true
			}
			if strings.HasPrefix(a, "-") {
				// Skip "--flag=value" form entirely.
				if strings.Contains(a, "=") {
					continue
				}
				if valueTakingFlags[a] && i+1 < len(args) {
					i++
				}
				continue
			}
			return a, "docker"
		}
		return "", "docker"
	case "python", "python3":
		for i, a := range args {
			if a == "-m" && i+1 < len(args) {
				return "python:" + args[i+1], ""
			}
		}
	}
	return "", ""
}

// firstNonFlag returns the first arg that is neither a flag (leading "-")
// nor a member of skip. When valueTaking is non-nil, flags listed there
// also consume the following argument so a flag's value is not mistaken
// for the package spec. The "--flag=value" form is skipped entirely.
//
// Without value-taking flag consumption, a launcher like
// "npx --registry https://token@reg.example.com/ pkg" would return the
// registry URL as the package, leaking the userinfo into PackageName /
// RequestedSpec downstream.

// scanExplicitPackage looks for "--package <pkg>" / "--package=<pkg>" in
// the launcher-parsed prefix of args. The scan stops at "--" (npm/npx do
// not interpret options past it) and at the first positional non-flag
// token that is not in the skip set of recognized subcommands
// (dlx/exec/x/run). Other value-taking flags are consumed so their values
// are not misread as --package. Returns the explicit package spec when
// found, otherwise "".
func scanExplicitPackage(args []string, skip map[string]bool) string {
	for i := 0; i < len(args); i++ {
		a := args[i]
		if a == "--" {
			return ""
		}
		if strings.HasPrefix(a, "--package=") {
			return strings.TrimPrefix(a, "--package=")
		}
		if a == "--package" && i+1 < len(args) {
			return args[i+1]
		}
		if strings.HasPrefix(a, "-") {
			if strings.Contains(a, "=") {
				continue
			}
			if npmValueTakingFlags[a] && i+1 < len(args) {
				i++
			}
			continue
		}
		if skip[a] {
			continue
		}
		// First positional that is not a recognized subcommand is the
		// entry-point / package spec; anything after it is child-command
		// args and must not be scanned for --package.
		return ""
	}
	return ""
}

func firstNonFlag(args []string, skip map[string]bool, valueTaking map[string]bool) string {
	for i := 0; i < len(args); i++ {
		a := args[i]
		if strings.HasPrefix(a, "-") {
			// "--flag=value" is one token; nothing else to consume.
			if strings.Contains(a, "=") {
				continue
			}
			if valueTaking[a] && i+1 < len(args) {
				i++
			}
			continue
		}
		if skip[a] {
			continue
		}
		return a
	}
	return ""
}

// npmValueTakingFlags lists npm/pnpm/yarn/bun flags that consume a
// separate value argument. Without skipping past these values, a value
// like a registry URL (often credential-bearing) can be misread as the
// package spec. Both short and long forms are included; the
// "--flag=value" form is handled by firstNonFlag itself.
//
// The list is intentionally conservative: it covers the flags that
// actually appear in MCP launcher commands and the obvious credential-
// adjacent ones (registry URLs, auth tokens, cache/prefix paths). Flags
// not listed here are still treated as flags (skipped without consuming
// the next arg); that matches existing behavior for unknown flags.
var npmValueTakingFlags = map[string]bool{
	"--registry":          true,
	"--reg":               true,
	"--cache":             true,
	"--prefix":            true,
	"--userconfig":        true,
	"--globalconfig":      true,
	"--node-options":      true,
	"--node-version":      true,
	"--workspace":         true,
	"-w":                  true,
	"--filter":            true,
	"--otp":               true,
	"--access":            true,
	"--auth-type":         true,
	"--tag":               true,
	"--call":              true,
	"-c":                  true,
	"--package":           true, // also handled explicitly upstream, kept for safety
	"--shell":             true,
	"--script-shell":      true,
	"--cwd":               true,
	"--loglevel":          true,
	"--store":             true,
	"--store-dir":         true,
	"--virtual-store-dir": true,
	"--lockfile-dir":      true,
	"--config":            true,
	"--config-file":       true,
}

// looksLikePackageSpec reports whether s is a plausible
// npm/PyPI/uv-style package spec. It rejects forms that npm-family
// launchers accept but that are not package identities: URLs (http,
// https, ftp, ssh, git+...), VCS shortcuts (github:, gitlab:, etc.),
// file:/path: refs, absolute paths, relative paths, and obvious
// tarball references (.tgz / .tar.gz / .tar.bz2 / .zip suffixes).
// These are the shapes that can carry credentials or local-fs
// information and must never round-trip into PackageName or
// RequestedSpec.
//
// Bare names, scoped names, version selectors (pkg@1.2.3,
// @scope/pkg@latest), and npm alias specs (pkg@npm:other@1.0) are
// accepted. The "python:<module>" pseudo-spec emitted by the python
// launcher branch is also accepted so its existing semantics are
// preserved. Empty input is rejected.
func looksLikePackageSpec(s string) bool {
	if s == "" {
		return false
	}
	if strings.HasPrefix(s, "python:") {
		return true
	}
	// Absolute paths.
	if strings.HasPrefix(s, "/") {
		return false
	}
	// Windows drive-letter absolute paths (C:\... or C:/...).
	if len(s) >= 3 && s[1] == ':' && (s[2] == '\\' || s[2] == '/') {
		c := s[0]
		if (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') {
			return false
		}
	}
	// Relative paths.
	if strings.HasPrefix(s, "./") || strings.HasPrefix(s, "../") || strings.HasPrefix(s, ".\\") || strings.HasPrefix(s, "..\\") {
		return false
	}
	// Backslash anywhere implies a Windows path rather than a package name.
	if strings.Contains(s, "\\") {
		return false
	}
	// URL / VCS / file / git-shortcut prefixes. Match case-insensitively
	// on the scheme prefix only; the rest of the string is left alone.
	lower := strings.ToLower(s)
	urlPrefixes := []string{
		"http://", "https://", "ftp://", "ftps://",
		"ssh://", "git://", "git+", "svn://", "svn+",
		"file://", "file:",
		"github:", "gitlab:", "bitbucket:", "gist:",
		"npm:", // bare "npm:foo" without a host package is not a valid spec
	}
	for _, p := range urlPrefixes {
		if strings.HasPrefix(lower, p) {
			return false
		}
	}
	// Tarball-looking suffixes — these are local or remote archives, not
	// package identities. Even if the prefix did not match a URL scheme
	// (e.g. "pkg.tgz" on its own), npm would resolve it as a file path,
	// so it carries no package-name signal.
	tarballSuffixes := []string{".tgz", ".tar.gz", ".tar.bz2", ".tar", ".zip"}
	for _, suf := range tarballSuffixes {
		if strings.HasSuffix(lower, suf) {
			return false
		}
	}
	// Embedded userinfo is the unambiguous credential leak signal: a "@"
	// before a "/" with no scope-marker leading character. Scoped names
	// like "@scope/pkg" are fine because the "@" is the first byte.
	// Version selectors like "pkg@1.2.3" never contain a slash after the
	// "@". A spec like "user:pass@host/path" would otherwise pass the
	// other checks.
	//
	// npm alias specs are an explicit carve-out: "host@npm:target" and
	// "host@npm:@scope/target@version" are valid even though the alias
	// target may contain a "/". Detect the "@npm:" selector after the
	// first non-leading "@" and validate the alias target with the same
	// package-spec rules so URL/path/userinfo shapes can't slip through
	// via "host@npm:https://user:token@reg.example.com/pkg.tgz" etc.
	if i := strings.Index(s, "@"); i > 0 {
		if strings.HasPrefix(s[i:], "@npm:") {
			target := s[i+len("@npm:"):]
			// Empty target ("host@npm:") is not a valid alias.
			if target == "" {
				return false
			}
			// Recurse: the target must itself look like a package spec.
			// This rejects URLs, file:/path: refs, absolute/relative
			// paths, tarballs, and userinfo shapes.
			return looksLikePackageSpec(target)
		}
		if j := strings.Index(s[i:], "/"); j > 0 {
			// "@" followed later by "/" — looks like an authority part
			// of an unschemed URL, not an npm alias selector.
			return false
		}
	}
	return true
}

// splitSpec splits an npm-style package spec into (name, selector). For
// "@playwright/mcp@latest" it returns ("@playwright/mcp", "@latest"); for
// "left-pad@1.2.3" it returns ("left-pad", "@1.2.3"); for "mcp-server-time"
// (no selector) it returns ("mcp-server-time", ""). The leading "@" of a
// scoped package name is preserved on the name; only a trailing
// "@<selector>" past the scope is treated as the selector.
func splitSpec(spec string) (name, selector string) {
	if spec == "" {
		return "", ""
	}
	// python:<module> has no version selector.
	if strings.HasPrefix(spec, "python:") {
		return spec, ""
	}
	// npm alias form: "pkg@npm:other@version" or "@scope/pkg@npm:other@version".
	// The selector starts at the '@' immediately before "npm:", not at the
	// trailing version '@'. Using LastIndex here would mis-attribute the
	// alias's own version to the host package.
	start := 0
	if strings.HasPrefix(spec, "@") {
		start = 1
	}
	if i := strings.Index(spec[start:], "@npm:"); i >= 0 {
		cut := start + i
		return spec[:cut], spec[cut:]
	}
	// Find the LAST '@' that is not the leading scope marker.
	idx := strings.LastIndex(spec[start:], "@")
	if idx <= 0 {
		return spec, ""
	}
	cut := start + idx
	return spec[:cut], spec[cut:]
}

// splitDockerImageRef splits a docker/OCI image reference into (name, tag).
// Only a colon after the last slash is treated as a tag separator, so a
// registry-port reference like "localhost:5000/foo/bar:1.2.3" splits to
// ("localhost:5000/foo/bar", "1.2.3"), and "localhost:5000/foo/bar" with
// no tag splits to ("localhost:5000/foo/bar", ""). Digest references like
// "name@sha256:..." are returned with the full name and an empty tag —
// the digest is preserved as part of the name so it can still match a
// catalog entry that pins by digest.
func splitDockerImageRef(ref string) (name, tag string) {
	if ref == "" {
		return "", ""
	}
	// tag@digest form: "image:tag@sha256:..." — split the tag off into
	// version and keep the digest on the name so the immutable identity
	// is preserved. Plain digest refs ("image@sha256:...", no ":tag")
	// still return with the digest on the name and an empty tag.
	if at := strings.Index(ref, "@"); at >= 0 {
		head := ref[:at]
		digest := ref[at:]
		lastSlash := strings.LastIndex(head, "/")
		tail := head
		if lastSlash >= 0 {
			tail = head[lastSlash+1:]
		}
		if colon := strings.LastIndex(tail, ":"); colon >= 0 {
			cut := colon
			if lastSlash >= 0 {
				cut = lastSlash + 1 + colon
			}
			return head[:cut] + digest, head[cut+1:]
		}
		return ref, ""
	}
	lastSlash := strings.LastIndex(ref, "/")
	tail := ref
	if lastSlash >= 0 {
		tail = ref[lastSlash+1:]
	}
	colon := strings.LastIndex(tail, ":")
	if colon < 0 {
		return ref, ""
	}
	cut := colon
	if lastSlash >= 0 {
		cut = lastSlash + 1 + colon
	}
	return ref[:cut], ref[cut+1:]
}

func (s *Scanner) readBounded(path string) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() {
		return nil, errors.New("not a regular file")
	}
	if s.MaxFileSize > 0 && info.Size() > s.MaxFileSize {
		if s.Diag != nil {
			s.Diag("warn", path, fmt.Sprintf("skipping: size %d exceeds max %d", info.Size(), s.MaxFileSize))
		}
		return nil, fmt.Errorf("file %s exceeds max size %d", path, s.MaxFileSize)
	}
	return io.ReadAll(f)
}
