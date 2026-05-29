package mcp

import (
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/perplexityai/bumblebee/internal/model"
)

func TestInferPackageFromArgs(t *testing.T) {
	cases := []struct {
		cmd          string
		args         []string
		wantSpec     string
		wantLauncher string
	}{
		{"/usr/bin/npx", []string{"-y", "@modelcontextprotocol/server-github"}, "@modelcontextprotocol/server-github", ""},
		{"uvx", []string{"mcp-server-time"}, "mcp-server-time", "uv"},
		{"python3", []string{"-m", "mypkg.server"}, "python:mypkg.server", ""},
		{"node", []string{"/x/y.js"}, "", ""},
		{"npx", []string{"-y", "@playwright/mcp@latest"}, "@playwright/mcp@latest", ""},
		{"npx", []string{"left-pad@1.2.3"}, "left-pad@1.2.3", ""},
		// pnpm/yarn/bun/npm wrappers take a subcommand before the package;
		// the subcommand must not be returned as the package name.
		{"pnpm", []string{"dlx", "@modelcontextprotocol/server-github"}, "@modelcontextprotocol/server-github", ""},
		{"pnpm", []string{"dlx", "-y", "@playwright/mcp@latest"}, "@playwright/mcp@latest", ""},
		{"yarn", []string{"dlx", "@modelcontextprotocol/server-time"}, "@modelcontextprotocol/server-time", ""},
		{"bun", []string{"x", "left-pad@1.2.3"}, "left-pad@1.2.3", ""},
		{"npm", []string{"exec", "--", "@modelcontextprotocol/server-github"}, "@modelcontextprotocol/server-github", ""},
		{"/usr/local/bin/pnpm", []string{"dlx", "mcp-server-time"}, "mcp-server-time", ""},
		// npm exec --package= / --package <pkg>: package is named via flag, not positional.
		{"npm", []string{"exec", "--package=@modelcontextprotocol/server-time", "--", "server-time"}, "@modelcontextprotocol/server-time", ""},
		{"npm", []string{"exec", "--package", "@modelcontextprotocol/server-time", "--", "server-time"}, "@modelcontextprotocol/server-time", ""},
		// pipx: launcher must be "pipx", not empty or indistinguishable.
		{"pipx", []string{"run", "mcp-server-time"}, "mcp-server-time", "pipx"},
		{"pipx", []string{"run", "--spec", "bugcrowd-mcp", "bugcrowd"}, "bugcrowd-mcp", "pipx"},
		{"/usr/local/bin/pipx", []string{"run", "some-mcp"}, "some-mcp", "pipx"},
		// uv + uv tool run, including --from override.
		{"uv", []string{"tool", "run", "mcp-server-time"}, "mcp-server-time", "uv"},
		// "uv run <path>" invokes a local script or directory project, not
		// a published package — the first positional is not a package
		// identity, so the spec must be empty. The caller falls back to
		// the server id with low confidence.
		{"uv", []string{"run", "--directory", "./backend", "mcps/foo.py"}, "", "uv"},
		{"uv", []string{"run", "mcps/foo.py"}, "", "uv"},
		{"uv", []string{"tool", "run", "--from", "bugcrowd-mcp", "bugcrowd"}, "bugcrowd-mcp", "uv"},
		// "uv run --from <pkg>" is a published-package invocation even
		// without "tool"; honor the --from name.
		{"uv", []string{"run", "--from", "bugcrowd-mcp", "bugcrowd"}, "bugcrowd-mcp", "uv"},
		// docker run with various flags before the image.
		{"docker", []string{"run", "-i", "--rm", "ghcr.io/example-org/example-mcp:latest"}, "ghcr.io/example-org/example-mcp:latest", "docker"},
		{"docker", []string{"run", "-e", "FOO=bar", "--name", "x", "mcp/slack"}, "mcp/slack", "docker"},
		{"docker", []string{"run", "--env-file=.env", "ghcr.io/github/github-mcp-server"}, "ghcr.io/github/github-mcp-server", "docker"},
		{"/usr/local/bin/docker", []string{"run", "mcp/slack"}, "mcp/slack", "docker"},
		// Non-executor first tokens name no published package: the spec is
		// empty and ScanConfig falls back to the server id, like `uv run
		// <script>` below. The case body is identical for npm/pnpm/yarn/bun,
		// so one row per distinct shape suffices.
		//
		// `run <script>` — incl. the reported `bun run … start` from the
		// official Claude messaging plugins, which had leaked package "start".
		{"bun", []string{"run", "--cwd", "/x", "--shell=bun", "--silent", "start"}, "", ""},
		{"npm", []string{"run", "start"}, "", ""},
		// Bare `<script>`: an npm lifecycle alias, a plain script, and one with
		// a trailing flag (which must not be mistaken for the package).
		{"npm", []string{"start"}, "", ""},
		{"yarn", []string{"dev"}, "", ""},
		{"yarn", []string{"build", "--port", "3000"}, "", ""},
		// create/init DO name a published create-<name> package, but resolving
		// that is intentionally out of scope (initializers don't launch MCP
		// servers); pinned so the fallback is deliberate, not an accidental drop.
		{"npm", []string{"create", "vite"}, "", ""},
		{"npm", []string{"init", "foo"}, "", ""},
		// Known limitation: a value-taking global flag NOT in npmValueTakingFlags
		// before the subcommand shifts detection, missing a genuine `exec`
		// package. Does not occur in real MCP configs; documented, not desired.
		{"npm", []string{"--unknownflag", "val", "exec", "real-pkg"}, "", ""},
	}
	for _, c := range cases {
		gotSpec, gotLauncher := inferPackageFromArgs(c.cmd, c.args)
		if gotSpec != c.wantSpec || gotLauncher != c.wantLauncher {
			t.Errorf("inferPackageFromArgs(%q,%v) = (%q,%q), want (%q,%q)",
				c.cmd, c.args, gotSpec, gotLauncher, c.wantSpec, c.wantLauncher)
		}
	}
}

func TestSplitSpec(t *testing.T) {
	cases := []struct {
		in       string
		wantName string
		wantSel  string
	}{
		{"@playwright/mcp@latest", "@playwright/mcp", "@latest"},
		{"@playwright/mcp", "@playwright/mcp", ""},
		{"@scope/name@1.2.3", "@scope/name", "@1.2.3"},
		{"left-pad@1.2.3", "left-pad", "@1.2.3"},
		{"mcp-server-time", "mcp-server-time", ""},
		{"python:mypkg.server", "python:mypkg.server", ""},
		{"", "", ""},
		// npm alias selectors must not be misparsed: the selector starts at
		// the '@' before "npm:", not at the trailing version. Otherwise the
		// alias target's own version is attributed to the host package and
		// name extraction is wrong.
		{"pkg@npm:alias@1.0.0", "pkg", "@npm:alias@1.0.0"},
		{"@scope/pkg@npm:other@2.0", "@scope/pkg", "@npm:other@2.0"},
		{"pkg@npm:alias", "pkg", "@npm:alias"},
		// Alias target may itself be scoped: "host@npm:@scope/other@1.0.0".
		{"host@npm:@scope/other@1.0.0", "host", "@npm:@scope/other@1.0.0"},
	}
	for _, c := range cases {
		gotName, gotSel := splitSpec(c.in)
		if gotName != c.wantName || gotSel != c.wantSel {
			t.Errorf("splitSpec(%q) = (%q,%q), want (%q,%q)", c.in, gotName, gotSel, c.wantName, c.wantSel)
		}
	}
}

func TestScanConfig(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "mcp.json")
	body := `{
  "mcpServers": {
    "github": {
      "command": "npx",
      "args": ["-y", "@modelcontextprotocol/server-github"],
      "env": {"GITHUB_TOKEN":"shouldnotbecaptured"}
    },
    "time": {
      "command": "uvx",
      "args": ["mcp-server-time"]
    }
  }
}`
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	var out []model.Record
	s := &Scanner{MaxFileSize: 1 << 20, Emit: func(r model.Record) { out = append(out, r) }}
	if err := s.ScanConfig(path, model.Record{}); err != nil {
		t.Fatal(err)
	}
	if len(out) != 2 {
		t.Fatalf("want 2 records, got %d", len(out))
	}
	sort.Slice(out, func(i, j int) bool { return out[i].PackageName < out[j].PackageName })
	if out[0].PackageName != "@modelcontextprotocol/server-github" {
		t.Errorf("inferred spec should set PackageName: %+v", out[0])
	}
	if out[0].ServerName != "github" {
		t.Errorf("ServerName not preserved: %+v", out[0])
	}
	if out[0].RootKind != model.RootKindMCPConfig {
		t.Errorf("RootKind = %q, want %q", out[0].RootKind, model.RootKindMCPConfig)
	}
	if out[0].Version != "" {
		t.Errorf("Version should be empty for MCP records: %q", out[0].Version)
	}
	if out[0].RequestedSpec != "" {
		t.Errorf("RequestedSpec should be empty when no selector: %q", out[0].RequestedSpec)
	}
	if out[1].PackageName != "mcp-server-time" {
		t.Errorf("inferred spec should set PackageName: %+v", out[1])
	}
	if out[1].ServerName != "time" {
		t.Errorf("ServerName not preserved: %+v", out[1])
	}
	if out[0].Confidence != "low" {
		t.Errorf("confidence: %q", out[0].Confidence)
	}
}

func TestScanConfig_FlatShape(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, ".mcp.json")
	body := `{
  "linear": {"command":"npx","args":["-y","@modelcontextprotocol/server-linear"]}
}`
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	var out []model.Record
	s := &Scanner{MaxFileSize: 1 << 20, Emit: func(r model.Record) { out = append(out, r) }}
	if err := s.ScanConfig(path, model.Record{}); err != nil {
		t.Fatal(err)
	}
	if len(out) != 1 || out[0].PackageName != "@modelcontextprotocol/server-linear" {
		t.Fatalf("flat shape: %+v", out)
	}
	if out[0].ServerName != "linear" {
		t.Errorf("ServerName not preserved: %+v", out[0])
	}
	if out[0].RootKind != model.RootKindMCPConfig {
		t.Errorf("RootKind = %q, want %q", out[0].RootKind, model.RootKindMCPConfig)
	}
}

// TestScanConfig_DockerAndUV verifies that container/python-tool launchers
// produce records identified by image ref or tool name and tag the
// package_manager so exposure matching does not treat them as npm.
func TestScanConfig_DockerAndUV(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "mcp.json")
	body := `{
  "mcpServers": {
    "example":  {"command":"docker","args":["run","-i","--rm","ghcr.io/example-org/example-mcp:latest"]},
    "github":   {"command":"docker","args":["run","-e","TOKEN","ghcr.io/github/github-mcp-server"]},
    "slack":    {"command":"docker","args":["run","mcp/slack"]},
    "bugcrowd": {"command":"uv","args":["tool","run","--from","bugcrowd-mcp","bugcrowd"]},
    "time":     {"command":"uvx","args":["mcp-server-time"]},
    "plugin":   {"command":"node","args":["${CLAUDE_PLUGIN_ROOT}/dist/index.js"]}
  }
}`
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	var out []model.Record
	s := &Scanner{MaxFileSize: 1 << 20, Emit: func(r model.Record) { out = append(out, r) }}
	if err := s.ScanConfig(path, model.Record{}); err != nil {
		t.Fatal(err)
	}
	if len(out) != 6 {
		t.Fatalf("want 6 records, got %d: %+v", len(out), out)
	}
	byServer := map[string]model.Record{}
	for _, r := range out {
		byServer[r.ServerName] = r
	}
	// Pinned image ref: tag must be split off into Version, leaving
	// PackageName as the bare image name.
	if r := byServer["example"]; r.PackageName != "ghcr.io/example-org/example-mcp" || r.Version != "latest" || r.PackageManager != "docker" {
		t.Errorf("example: %+v", r)
	}
	// No tag in the ref: Version stays empty.
	if r := byServer["github"]; r.PackageName != "ghcr.io/github/github-mcp-server" || r.Version != "" || r.PackageManager != "docker" {
		t.Errorf("github: %+v", r)
	}
	if r := byServer["slack"]; r.PackageName != "mcp/slack" || r.Version != "" || r.PackageManager != "docker" {
		t.Errorf("slack: %+v", r)
	}
	if r := byServer["bugcrowd"]; r.PackageName != "bugcrowd-mcp" || r.PackageManager != "uv" {
		t.Errorf("bugcrowd: %+v", r)
	}
	if r := byServer["time"]; r.PackageName != "mcp-server-time" || r.PackageManager != "uv" {
		t.Errorf("time: %+v", r)
	}
	// Unresolved ${CLAUDE_PLUGIN_ROOT} should fall back to the server id,
	// not be emitted as a literal package name.
	if r := byServer["plugin"]; r.PackageName != "plugin" {
		t.Errorf("plugin (unresolved shell var): %+v", r)
	}
}

// TestSplitDockerImageRef covers the colon-tag splitter for OCI image refs.
// The interesting cases: an unambiguous tag, no tag at all, a
// registry-port reference whose first colon must NOT be treated as the
// tag separator, and a digest reference which should be left intact.
func TestSplitDockerImageRef(t *testing.T) {
	cases := []struct {
		in       string
		wantName string
		wantTag  string
	}{
		{"hashicorp/terraform-mcp-server:0.4.0", "hashicorp/terraform-mcp-server", "0.4.0"},
		{"ghcr.io/example-org/example-mcp:latest", "ghcr.io/example-org/example-mcp", "latest"},
		{"ghcr.io/github/github-mcp-server", "ghcr.io/github/github-mcp-server", ""},
		{"mcp/slack", "mcp/slack", ""},
		// Registry port: the colon before the port lives in the registry
		// segment (before the last slash) and must not be split.
		{"localhost:5000/foo/bar:1.2.3", "localhost:5000/foo/bar", "1.2.3"},
		{"localhost:5000/foo/bar", "localhost:5000/foo/bar", ""},
		{"registry.example.com:443/team/img:v1", "registry.example.com:443/team/img", "v1"},
		// Digest refs are returned with the digest preserved on the name
		// side and an empty tag.
		{"alpine@sha256:abc123", "alpine@sha256:abc123", ""},
		{"ghcr.io/foo/bar@sha256:deadbeef", "ghcr.io/foo/bar@sha256:deadbeef", ""},
		// tag@digest form: preserve the digest on the name and split the
		// tag off into version. The digest is the immutable identity; the
		// tag is the human-readable version pointer.
		{"alpine:3.19@sha256:abc", "alpine@sha256:abc", "3.19"},
		{"ghcr.io/foo/bar:1.2.3@sha256:deadbeef", "ghcr.io/foo/bar@sha256:deadbeef", "1.2.3"},
		// Single-segment image with a tag.
		{"alpine:3.19", "alpine", "3.19"},
		{"", "", ""},
	}
	for _, c := range cases {
		gotName, gotTag := splitDockerImageRef(c.in)
		if gotName != c.wantName || gotTag != c.wantTag {
			t.Errorf("splitDockerImageRef(%q) = (%q,%q), want (%q,%q)", c.in, gotName, gotTag, c.wantName, c.wantTag)
		}
	}
}

// TestScanConfig_DockerPinnedTag exercises the end-to-end record shape
// for a pinned image ref: PackageName must lose the tag, Version must
// carry the tag, PackageManager stays "docker".
func TestScanConfig_DockerPinnedTag(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "mcp.json")
	body := `{
  "mcpServers": {
    "terraform": {"command":"docker","args":["run","-i","--rm","hashicorp/terraform-mcp-server:0.4.0"]},
    "localreg":  {"command":"docker","args":["run","localhost:5000/team/img:1.2.3"]},
    "untagged":  {"command":"docker","args":["run","ghcr.io/example-org/example-mcp"]}
  }
}`
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	var out []model.Record
	s := &Scanner{MaxFileSize: 1 << 20, Emit: func(r model.Record) { out = append(out, r) }}
	if err := s.ScanConfig(path, model.Record{}); err != nil {
		t.Fatal(err)
	}
	byServer := map[string]model.Record{}
	for _, r := range out {
		byServer[r.ServerName] = r
	}
	if r := byServer["terraform"]; r.PackageName != "hashicorp/terraform-mcp-server" || r.NormalizedName != "hashicorp/terraform-mcp-server" || r.Version != "0.4.0" || r.PackageManager != "docker" {
		t.Errorf("terraform: %+v", r)
	}
	if r := byServer["localreg"]; r.PackageName != "localhost:5000/team/img" || r.Version != "1.2.3" || r.PackageManager != "docker" {
		t.Errorf("localreg: %+v", r)
	}
	if r := byServer["untagged"]; r.PackageName != "ghcr.io/example-org/example-mcp" || r.Version != "" || r.PackageManager != "docker" {
		t.Errorf("untagged: %+v", r)
	}
}

// TestScanConfig_UVRunDirectory verifies that "uv run --directory <dir>
// <script>" does not leak the directory path as a package name. The
// record falls back to the server id with low confidence so a literal
// "./backend" cannot drive a catalog hit.
func TestScanConfig_UVRunDirectory(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "mcp.json")
	body := `{
  "mcpServers": {
    "bugcrowd":        {"command":"uv","args":["run","--directory","./backend","mcps/bugcrowd.py"]},
    "github_extended": {"command":"uv","args":["run","--directory","./backend","mcps/github_extended.py"]},
    "from-flag":       {"command":"uv","args":["run","--from","bugcrowd-mcp","bugcrowd"]}
  }
}`
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	var out []model.Record
	s := &Scanner{MaxFileSize: 1 << 20, Emit: func(r model.Record) { out = append(out, r) }}
	if err := s.ScanConfig(path, model.Record{}); err != nil {
		t.Fatal(err)
	}
	byServer := map[string]model.Record{}
	for _, r := range out {
		byServer[r.ServerName] = r
	}
	if r := byServer["bugcrowd"]; r.PackageName != "bugcrowd" || r.PackageManager != "uv" || r.Confidence != "low" {
		t.Errorf("bugcrowd: %+v", r)
	}
	if r := byServer["github_extended"]; r.PackageName != "github_extended" || r.PackageManager != "uv" {
		t.Errorf("github_extended: %+v", r)
	}
	// --from still wins even when "tool" is absent.
	if r := byServer["from-flag"]; r.PackageName != "bugcrowd-mcp" || r.PackageManager != "uv" {
		t.Errorf("from-flag: %+v", r)
	}
}

// TestScanConfig_RealWorldCorpus runs the parser over command/args shapes
// taken from real MCP configurations (the modelcontextprotocol servers, the
// Claude/Cursor setup guides, and the official Claude bundled-server
// plugins). It is the regression guard for the script-runner change: genuine
// package launchers (npx/uvx/docker) must keep their package identity, while
// local-script launchers (`bun run … start`, bare `yarn`/`pnpm`, `node` file,
// `npm create`) must fall back to the server id rather than leak a script or
// initializer-verb token as a package.
func TestScanConfig_RealWorldCorpus(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "mcp.json")
	body := `{
  "mcpServers": {
    "seq-think":  {"command":"npx","args":["-y","@modelcontextprotocol/server-sequential-thinking"]},
    "omnisearch": {"command":"npx","args":["-y","mcp-omnisearch"]},
    "sqlite":     {"command":"uvx","args":["mcp-server-sqlite","--db-path","test.db"]},
    "chronulus":  {"command":"uvx","args":["chronulus-mcp"]},
    "github":     {"command":"docker","args":["run","-i","--rm","ghcr.io/github/github-mcp-server"]},
    "local-node": {"command":"node","args":["/home/u/mcp-tools/build/index.js"]},
    "discord":    {"command":"bun","args":["run","--cwd","/plugins/discord","--shell=bun","--silent","start"]},
    "yarn-dev":   {"command":"yarn","args":["dev"]},
    "scaffold":   {"command":"npm","args":["create","vite"]}
  }
}`
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	var out []model.Record
	s := &Scanner{MaxFileSize: 1 << 20, Emit: func(r model.Record) { out = append(out, r) }}
	if err := s.ScanConfig(path, model.Record{}); err != nil {
		t.Fatal(err)
	}
	byServer := map[string]model.Record{}
	for _, r := range out {
		byServer[r.ServerName] = r
	}
	want := map[string]struct{ pkg, pm string }{
		// Genuine package launchers — identity preserved.
		"seq-think":  {"@modelcontextprotocol/server-sequential-thinking", "mcp"},
		"omnisearch": {"mcp-omnisearch", "mcp"},
		"sqlite":     {"mcp-server-sqlite", "uv"},
		"chronulus":  {"chronulus-mcp", "uv"},
		"github":     {"ghcr.io/github/github-mcp-server", "docker"},
		// Local-script / non-package launchers — fall back to the server id.
		"local-node": {"local-node", "mcp"}, // node <file>
		"discord":    {"discord", "mcp"},    // claude-plugins-official template: bun run … start
		"yarn-dev":   {"yarn-dev", "mcp"},   // bare yarn <script>
		"scaffold":   {"scaffold", "mcp"},   // npm create (initializer, out of scope)
	}
	for id, w := range want {
		r, ok := byServer[id]
		if !ok {
			t.Fatalf("%s: no record emitted", id)
		}
		if r.PackageName != w.pkg || r.PackageManager != w.pm {
			t.Errorf("%s: got package_name=%q package_manager=%q, want %q/%q",
				id, r.PackageName, r.PackageManager, w.pkg, w.pm)
		}
	}
}

// TestScanConfig_MalformedJSONEmitsWarn verifies that a malformed MCP
// config file is surfaced as a warn diagnostic rather than silently
// swallowed. Operators rely on diagnostics to find configs the scanner
// could not parse.
func TestScanConfig_MalformedJSONEmitsWarn(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "mcp.json")
	if err := os.WriteFile(path, []byte(`{this is not json`), 0o644); err != nil {
		t.Fatal(err)
	}
	var out []model.Record
	type diag struct {
		level, path, msg string
	}
	var diags []diag
	s := &Scanner{
		MaxFileSize: 1 << 20,
		Emit:        func(r model.Record) { out = append(out, r) },
		Diag:        func(level, p, msg string) { diags = append(diags, diag{level, p, msg}) },
	}
	if err := s.ScanConfig(path, model.Record{}); err != nil {
		t.Fatalf("ScanConfig returned error: %v", err)
	}
	if len(out) != 0 {
		t.Fatalf("expected no records, got %+v", out)
	}
	foundWarn := false
	for _, d := range diags {
		if d.level == "warn" && d.path == path {
			foundWarn = true
		}
	}
	if !foundWarn {
		t.Fatalf("expected a warn diagnostic for malformed JSON, got %+v", diags)
	}
}

// TestScanConfig_SpecSelector verifies that npm-style version selectors
// ("@latest", "@1.2.3") in MCP args are split off into RequestedSpec
// while PackageName is normalized to the bare package name. The
// installed Version stays empty because MCP configs do not pin to an
// installed version.
func TestScanConfig_SpecSelector(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "mcp.json")
	body := `{
  "mcpServers": {
    "playwright": {"command":"npx","args":["-y","@playwright/mcp@latest"]},
    "pinned":     {"command":"npx","args":["left-pad@1.2.3"]}
  }
}`
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	var out []model.Record
	s := &Scanner{MaxFileSize: 1 << 20, Emit: func(r model.Record) { out = append(out, r) }}
	if err := s.ScanConfig(path, model.Record{}); err != nil {
		t.Fatal(err)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ServerName < out[j].ServerName })
	if len(out) != 2 {
		t.Fatalf("want 2 records, got %+v", out)
	}
	// pinned: left-pad@1.2.3
	if out[0].PackageName != "left-pad" || out[0].RequestedSpec != "left-pad@1.2.3" || out[0].Version != "" {
		t.Errorf("pinned record: %+v", out[0])
	}
	// playwright: @playwright/mcp@latest
	if out[1].PackageName != "@playwright/mcp" || out[1].RequestedSpec != "@playwright/mcp@latest" || out[1].Version != "" {
		t.Errorf("playwright record: %+v", out[1])
	}
}

// TestScanConfig_DockerConfidence verifies that docker MCP records with a
// pinned tag or digest get bumped to "medium" confidence (the only MCP
// shape that ties identity to an immutable reference), while untagged
// images stay at "low".
func TestScanConfig_DockerConfidence(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "mcp.json")
	body := `{
  "mcpServers": {
    "tagged":   {"command":"docker","args":["run","ghcr.io/example/example-mcp:1.2.3"]},
    "digest":   {"command":"docker","args":["run","ghcr.io/example/example-mcp@sha256:abc"]},
    "untagged": {"command":"docker","args":["run","ghcr.io/example/example-mcp"]},
    "npm":      {"command":"npx","args":["-y","@playwright/mcp@latest"]}
  }
}`
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	var out []model.Record
	s := &Scanner{MaxFileSize: 1 << 20, Emit: func(r model.Record) { out = append(out, r) }}
	if err := s.ScanConfig(path, model.Record{}); err != nil {
		t.Fatal(err)
	}
	by := map[string]model.Record{}
	for _, r := range out {
		by[r.ServerName] = r
	}
	if r := by["tagged"]; r.Confidence != "medium" {
		t.Errorf("tagged docker confidence = %q, want medium: %+v", r.Confidence, r)
	}
	if r := by["digest"]; r.Confidence != "medium" {
		t.Errorf("digest docker confidence = %q, want medium: %+v", r.Confidence, r)
	}
	if r := by["untagged"]; r.Confidence != "low" {
		t.Errorf("untagged docker confidence = %q, want low: %+v", r.Confidence, r)
	}
	// Non-docker launchers stay at the conservative "low" — a selector
	// like @latest is not an immutable identity.
	if r := by["npm"]; r.Confidence != "low" {
		t.Errorf("npm confidence = %q, want low: %+v", r.Confidence, r)
	}
}

// TestScanConfig_RemoteURL verifies that remote MCP entries (sse / http
// transports identified by url/serverUrl/httpUrl) are not silently
// dropped: the sanitized endpoint is preserved in requested_spec and
// the record is tagged package_manager=mcp-remote. Headers, env, and
// any userinfo or query-string secrets must never appear.
func TestScanConfig_RemoteURL(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "mcp.json")
	body := `{
  "mcpServers": {
    "sse":  {"type":"sse","url":"https://mcp.example.com/sse"},
    "alt":  {"serverUrl":"https://alt.example.com/api"},
    "http": {"httpUrl":"https://http.example.com/v1"},
    "auth": {"url":"https://user:secret@auth.example.com/mcp?token=shh#frag"}
  }
}`
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	var out []model.Record
	s := &Scanner{MaxFileSize: 1 << 20, Emit: func(r model.Record) { out = append(out, r) }}
	if err := s.ScanConfig(path, model.Record{}); err != nil {
		t.Fatal(err)
	}
	by := map[string]model.Record{}
	for _, r := range out {
		by[r.ServerName] = r
	}
	if len(out) != 4 {
		t.Fatalf("want 4 remote records, got %d: %+v", len(out), out)
	}
	for _, name := range []string{"sse", "alt", "http", "auth"} {
		r, ok := by[name]
		if !ok {
			t.Fatalf("missing remote record %q: %+v", name, out)
		}
		if r.PackageManager != "mcp-remote" {
			t.Errorf("%s: package_manager = %q, want mcp-remote", name, r.PackageManager)
		}
		if r.PackageName != name {
			t.Errorf("%s: package_name = %q, want %q (server id fallback)", name, r.PackageName, name)
		}
		if r.RequestedSpec == "" {
			t.Errorf("%s: RequestedSpec empty, want sanitized URL", name)
		}
	}
	// Userinfo, query string, fragment, and path must all be dropped from
	// the recorded URL — credentials commonly slip in through any of them.
	got := by["auth"].RequestedSpec
	if strings.Contains(got, "secret") || strings.Contains(got, "token") || strings.Contains(got, "user:") || strings.Contains(got, "#") || strings.Contains(got, "?") || strings.Contains(got, "/mcp") {
		t.Errorf("sanitized URL still contains secrets or path: %q", got)
	}
	if got != "https://auth.example.com" {
		t.Errorf("sanitized URL = %q, want https://auth.example.com", got)
	}
}

// TestScanConfig_FlatRemoteURL verifies that flat-shape MCP configs
// (no mcpServers/servers envelope) are admitted when the entry carries
// only a remote URL field — serverUrl or httpUrl — with no command,
// args, or type. Previously the flat admission check only recognized
// the "url" field, so entries using the alternate names were dropped
// silently.
func TestScanConfig_FlatRemoteURL(t *testing.T) {
	dir := t.TempDir()
	cases := []struct {
		name, body, wantHost string
	}{
		{
			name:     "serverUrl",
			body:     `{"alt": {"serverUrl":"https://alt.example.com/api"}}`,
			wantHost: "https://alt.example.com",
		},
		{
			name:     "httpUrl",
			body:     `{"http": {"httpUrl":"https://http.example.com/v1"}}`,
			wantHost: "https://http.example.com",
		},
	}
	for _, c := range cases {
		path := filepath.Join(dir, c.name+".mcp.json")
		if err := os.WriteFile(path, []byte(c.body), 0o644); err != nil {
			t.Fatal(err)
		}
		var out []model.Record
		s := &Scanner{MaxFileSize: 1 << 20, Emit: func(r model.Record) { out = append(out, r) }}
		if err := s.ScanConfig(path, model.Record{}); err != nil {
			t.Fatal(err)
		}
		if len(out) != 1 {
			t.Fatalf("%s: want 1 record, got %d: %+v", c.name, len(out), out)
		}
		r := out[0]
		if r.PackageManager != "mcp-remote" {
			t.Errorf("%s: package_manager = %q, want mcp-remote", c.name, r.PackageManager)
		}
		if r.RequestedSpec != c.wantHost {
			t.Errorf("%s: RequestedSpec = %q, want %q", c.name, r.RequestedSpec, c.wantHost)
		}
	}
}

// TestSanitizeRemoteURL covers the URL sanitizer in isolation. Only
// scheme + host are preserved; userinfo, query, fragment, and path
// are all dropped because credentials commonly hide in path segments
// ("/mcp/<token>") as well as the more obvious userinfo/query slots.
// Scheme-less network-path references collapse to "//host". Anything
// the parser cannot recover a host from returns "" rather than
// echoing a raw, potentially secret-bearing string.
func TestSanitizeRemoteURL(t *testing.T) {
	cases := []struct {
		name, in, want string
	}{
		{"empty", "", ""},
		{"normal", "https://example.com/mcp", "https://example.com"},
		{"query token", "https://example.com/mcp?token=abc", "https://example.com"},
		{"fragment", "https://example.com/mcp#frag", "https://example.com"},
		{"userinfo", "https://user:pass@example.com/mcp", "https://example.com"},
		{"userinfo + query + fragment", "https://user:pass@example.com/mcp?token=abc#frag", "https://example.com"},
		// Path-embedded token: the whole path is dropped, not just query
		// and fragment, since secrets routinely show up as path segments.
		{"path token", "https://example.com/mcp/sk-live-abcdef", "https://example.com"},
		// Scheme-less network-path: //host[/path] keeps the //host form
		// with userinfo stripped.
		{"scheme-less userinfo", "//user:pass@example.com/mcp", "//example.com"},
		{"scheme-less plain", "//example.com/api", "//example.com"},
		// '@' in the path is irrelevant once the entire path is dropped.
		{"path with @", "https://example.com/path/with@symbol", "https://example.com"},
		// A bare token with no host shape must not be echoed back.
		{"bare token", "sk-live-abcdef", ""},
	}
	for _, c := range cases {
		if got := sanitizeRemoteURL(c.in); got != c.want {
			t.Errorf("%s: sanitizeRemoteURL(%q) = %q, want %q", c.name, c.in, got, c.want)
		}
	}
}

// TestIsKnownMCPConfig verifies the basename allowlist covers both the
// historical files and the recently-added cline/mcp_settings forms.
func TestIsKnownMCPConfig(t *testing.T) {
	want := []string{
		"mcp.json",
		".mcp.json",
		"claude_desktop_config.json",
		"mcp_config.json",
		"mcp_settings.json",
		"cline_mcp_settings.json",
	}
	for _, name := range want {
		if !IsKnownMCPConfig(name) {
			t.Errorf("IsKnownMCPConfig(%q) = false, want true", name)
		}
	}
	for _, name := range []string{"package.json", "config.json", "mcp.yaml", ""} {
		if IsKnownMCPConfig(name) {
			t.Errorf("IsKnownMCPConfig(%q) = true, want false", name)
		}
	}
	// settings.json is intentionally NOT in the basename allowlist —
	// it's an ambiguous filename (VS Code user settings, etc.). Gemini
	// CLI's ~/.gemini/settings.json is matched via the path-aware
	// IsGeminiSettingsJSON helper instead.
	if IsKnownMCPConfig("settings.json") {
		t.Errorf("IsKnownMCPConfig(\"settings.json\") = true, want false (use IsGeminiSettingsJSON for path-aware dispatch)")
	}
}

// TestIsGeminiSettingsJSON verifies that path-aware dispatch only matches
// `<...>/.gemini/settings.json` and does not pick up other settings.json
// files (notably VS Code's user settings) under unrelated directories.
func TestIsGeminiSettingsJSON(t *testing.T) {
	match := []string{
		"/home/alice/.gemini/settings.json",
		"/Users/alice/.gemini/settings.json",
		filepath.Join(".gemini", "settings.json"),
	}
	for _, p := range match {
		if !IsGeminiSettingsJSON(p) {
			t.Errorf("IsGeminiSettingsJSON(%q) = false, want true", p)
		}
	}
	noMatch := []string{
		"/home/alice/.vscode/settings.json",
		"/home/alice/.config/Code/User/settings.json",
		"/home/alice/.gemini/other.json",
		"/home/alice/gemini/settings.json", // missing the dot
		"/home/alice/.gemini/sub/settings.json",
		"",
	}
	for _, p := range noMatch {
		if IsGeminiSettingsJSON(p) {
			t.Errorf("IsGeminiSettingsJSON(%q) = true, want false", p)
		}
	}
}

// TestIsClaudeConfigJSON verifies path-aware dispatch for Claude Code's
// `~/.claude.json` user config, which the basename allowlist does not
// route to the generic MCP parser.
func TestIsClaudeConfigJSON(t *testing.T) {
	match := []string{
		"/home/alice/.claude.json",
		"/Users/alice/.claude.json",
		".claude.json",
	}
	for _, p := range match {
		if !IsClaudeConfigJSON(p) {
			t.Errorf("IsClaudeConfigJSON(%q) = false, want true", p)
		}
	}
	noMatch := []string{
		"/home/alice/.claude/mcp.json",
		"/home/alice/claude.json", // missing the dot
		"/home/alice/.claude.jsonc",
		"",
	}
	for _, p := range noMatch {
		if IsClaudeConfigJSON(p) {
			t.Errorf("IsClaudeConfigJSON(%q) = true, want false", p)
		}
	}
}

// TestScanClaudeConfig verifies that both MCP scopes in ~/.claude.json are
// inventoried — the top-level `mcpServers` (user scope) and the
// per-project `projects.<dir>.mcpServers` (local scope) — while the file's
// many unrelated settings are ignored and never misread as servers.
func TestScanClaudeConfig(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, ".claude.json")
	body := `{
  "numStartups": 42,
  "oauthAccount": {"emailAddress": "shouldnotbecaptured"},
  "mcpServers": {
    "github": {
      "command": "npx",
      "args": ["-y", "@modelcontextprotocol/server-github"],
      "env": {"GITHUB_TOKEN": "shouldnotbecaptured"}
    }
  },
  "projects": {
    "/home/alice/proj-a": {
      "allowedTools": [],
      "mcpServers": {
        "local-time": {"command": "uvx", "args": ["mcp-server-time"]}
      }
    },
    "/home/alice/proj-b": {
      "mcpServers": {
        "stripe": {"type": "http", "url": "https://user:secret@mcp.stripe.com/mcp?token=abc"}
      }
    },
    "/home/alice/proj-c": {
      "lastCost": 0.12
    }
  }
}`
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	var out []model.Record
	s := &Scanner{MaxFileSize: 1 << 20, Emit: func(r model.Record) { out = append(out, r) }}
	if err := s.ScanClaudeConfig(path, model.Record{}); err != nil {
		t.Fatal(err)
	}
	if len(out) != 3 {
		t.Fatalf("want 3 records (1 user-scope + 2 local-scope), got %d: %+v", len(out), out)
	}
	byServer := map[string]model.Record{}
	for _, r := range out {
		byServer[r.ServerName] = r
		if r.RootKind != model.RootKindMCPConfig {
			t.Errorf("%s: RootKind = %q, want %q", r.ServerName, r.RootKind, model.RootKindMCPConfig)
		}
		if r.SourceFile != path {
			t.Errorf("%s: SourceFile = %q, want %q", r.ServerName, r.SourceFile, path)
		}
	}
	// User-scope server: top-level mcpServers, ProjectPath is the file's dir.
	if got := byServer["github"]; got.PackageName != "@modelcontextprotocol/server-github" || got.ProjectPath != dir {
		t.Errorf("github user-scope record wrong: %+v", got)
	}
	// Local-scope servers: ProjectPath is the per-project key.
	if got := byServer["local-time"]; got.PackageName != "mcp-server-time" || got.ProjectPath != "/home/alice/proj-a" {
		t.Errorf("local-time local-scope record wrong: %+v", got)
	}
	// Remote entry: sanitized to scheme://host, no userinfo/path/query.
	if got := byServer["stripe"]; got.ProjectPath != "/home/alice/proj-b" || got.PackageManager != "mcp-remote" || got.RequestedSpec != "https://mcp.stripe.com" {
		t.Errorf("stripe remote record wrong: %+v", got)
	}
}

// TestScanClaudeConfig_NoServers verifies that a ~/.claude.json with no
// MCP servers configured (only unrelated settings) emits nothing — the
// generic flat-object fallback must not run over this file and treat
// arbitrary top-level keys as server entries.
func TestScanClaudeConfig_NoServers(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, ".claude.json")
	body := `{"numStartups": 3, "oauthAccount": {"emailAddress": "x"}, "projects": {"/p": {"lastCost": 1}}}`
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	var out []model.Record
	s := &Scanner{MaxFileSize: 1 << 20, Emit: func(r model.Record) { out = append(out, r) }}
	if err := s.ScanClaudeConfig(path, model.Record{}); err != nil {
		t.Fatal(err)
	}
	if len(out) != 0 {
		t.Fatalf("want 0 records, got %d: %+v", len(out), out)
	}
}

// TestLooksLikePackageSpec verifies the package-spec gate that keeps
// non-package launcher arguments — URLs, VCS refs, file/path refs, and
// tarball archives — out of PackageName and RequestedSpec.
func TestLooksLikePackageSpec(t *testing.T) {
	pass := []string{
		"@modelcontextprotocol/server-github",
		"@playwright/mcp@latest",
		"left-pad",
		"left-pad@1.2.3",
		"@scope/pkg",
		"@scope/pkg@1.2.3",
		"pkg@npm:other@1.0",
		"host@npm:@scope/other@1.0.0",
		"@scope/pkg@npm:@other/target@2.0.0",
		"python:mypkg.server",
	}
	reject := []string{
		"",
		"http://reg.example.com/pkg.tgz",
		"https://reg.example.com/pkg.tgz",
		"https://user:token@reg.example.com/",
		"https://reg.example.com/",
		"ftp://example.com/x",
		"git://github.com/owner/repo.git",
		"git+https://github.com/owner/repo.git",
		"git+ssh://git@github.com/owner/repo.git",
		"ssh://git@github.com/owner/repo.git",
		"github:owner/repo",
		"gitlab:owner/repo",
		"bitbucket:owner/repo",
		"file:./local/path",
		"file:///abs/path",
		"/abs/path/to/pkg.tgz",
		"./local/pkg.tgz",
		"../local/pkg",
		"./relative/dir",
		"pkg.tgz",
		"archive.tar.gz",
		"archive.zip",
		"C:\\Users\\me\\pkg",
		"C:/Users/me/pkg",
		`server\path\here`,
		"user:pass@host/path",
		// npm alias targets must be re-validated against the same
		// rules — URL, file:, and path forms after "@npm:" must not
		// slip through the alias carve-out.
		"host@npm:https://user:token@reg.example.com/pkg.tgz",
		"host@npm:http://reg.example.com/pkg.tgz",
		"host@npm:file:./local",
		"host@npm:file:///abs/path",
		"host@npm:../local",
		"host@npm:./local",
		"host@npm:/abs/path",
		"host@npm:pkg.tgz",
		"host@npm:user:pass@host/path",
		"host@npm:", // empty alias target
	}
	for _, s := range pass {
		if !looksLikePackageSpec(s) {
			t.Errorf("looksLikePackageSpec(%q) = false, want true", s)
		}
	}
	for _, s := range reject {
		if looksLikePackageSpec(s) {
			t.Errorf("looksLikePackageSpec(%q) = true, want false", s)
		}
	}
}

// TestInferPackageFromArgs_ValueTakingFlags verifies that npm-family
// launchers consume the value of value-taking flags so a flag's value
// (often a registry URL with embedded credentials) is not returned as
// the package spec.
func TestInferPackageFromArgs_ValueTakingFlags(t *testing.T) {
	cases := []struct {
		name         string
		cmd          string
		args         []string
		wantSpec     string
		wantLauncher string
	}{
		{
			name: "npx --registry URL pkg",
			cmd:  "npx",
			args: []string{"--registry", "https://token@reg.example.com/", "@scope/pkg"},
			// Registry URL must not be returned; the package after it is.
			wantSpec:     "@scope/pkg",
			wantLauncher: "",
		},
		{
			name:         "npx --registry=URL pkg",
			cmd:          "npx",
			args:         []string{"--registry=https://token@reg.example.com/", "@scope/pkg"},
			wantSpec:     "@scope/pkg",
			wantLauncher: "",
		},
		{
			name:         "pnpm dlx --registry URL pkg",
			cmd:          "pnpm",
			args:         []string{"dlx", "--registry", "https://t@reg.example.com/", "@scope/pkg"},
			wantSpec:     "@scope/pkg",
			wantLauncher: "",
		},
		{
			name:         "yarn dlx --cache PATH pkg",
			cmd:          "yarn",
			args:         []string{"dlx", "--cache", "/some/local/cache", "left-pad@1.2.3"},
			wantSpec:     "left-pad@1.2.3",
			wantLauncher: "",
		},
		{
			name:         "bun x --cwd PATH pkg",
			cmd:          "bun",
			args:         []string{"x", "--cwd", "/tmp/work", "left-pad"},
			wantSpec:     "left-pad",
			wantLauncher: "",
		},
		{
			name:         "bunx --registry URL pkg",
			cmd:          "bunx",
			args:         []string{"--registry", "https://t@reg.example.com/", "left-pad"},
			wantSpec:     "left-pad",
			wantLauncher: "",
		},
		{
			name:         "npm exec --registry URL -- pkg",
			cmd:          "npm",
			args:         []string{"exec", "--registry", "https://t@reg.example.com/", "--", "@scope/pkg"},
			wantSpec:     "@scope/pkg",
			wantLauncher: "",
		},
		{
			// npx --package <pkg> -- <cmd>: the explicit --package value is
			// the package identity, not the trailing entry-point command.
			name:         "npx --package <scoped> -- cmd",
			cmd:          "npx",
			args:         []string{"--package", "@scope/pkg", "--", "cmd"},
			wantSpec:     "@scope/pkg",
			wantLauncher: "",
		},
		{
			name:         "npx --package=<scoped> -- cmd",
			cmd:          "npx",
			args:         []string{"--package=@scope/pkg", "--", "cmd"},
			wantSpec:     "@scope/pkg",
			wantLauncher: "",
		},
		{
			name:         "bunx --package <scoped> -- cmd",
			cmd:          "bunx",
			args:         []string{"--package", "@scope/pkg", "--", "cmd"},
			wantSpec:     "@scope/pkg",
			wantLauncher: "",
		},
		{
			// --workspaces is a boolean flag, not value-taking. The positional
			// after it must still be returned as the package spec.
			name:         "npm exec --workspaces <scoped>",
			cmd:          "npm",
			args:         []string{"exec", "--workspaces", "@scope/pkg"},
			wantSpec:     "@scope/pkg",
			wantLauncher: "",
		},
		{
			// npm alias spec with a scoped target must survive intact through
			// inference; the package-spec gate is exercised by ScanConfig.
			name:         "npx host@npm:@scope/other@version",
			cmd:          "npx",
			args:         []string{"-y", "host@npm:@scope/other@1.0.0"},
			wantSpec:     "host@npm:@scope/other@1.0.0",
			wantLauncher: "",
		},
		{
			// Regression: --package after the first positional is a child-command
			// arg for npx, not a launcher flag. Must not be honored.
			name:         "npx <pkg> --package <other>",
			cmd:          "npx",
			args:         []string{"foo", "--package", "@npmcli/bar"},
			wantSpec:     "foo",
			wantLauncher: "",
		},
		{
			// Regression: tokens after "--" are child-command args for npx.
			name:         "npx <pkg> -- --package <other>",
			cmd:          "npx",
			args:         []string{"foo", "--", "--package", "@npmcli/bar"},
			wantSpec:     "foo",
			wantLauncher: "",
		},
		{
			// Regression: npm exec does not parse options past "--".
			name:         "npm exec <pkg> -- --package <other>",
			cmd:          "npm",
			args:         []string{"exec", "foo", "--", "--package", "@npmcli/bar"},
			wantSpec:     "foo",
			wantLauncher: "",
		},
		{
			// Positive: bunx --package before the first positional still wins.
			name:         "bunx --registry URL --package <scoped> -- cmd",
			cmd:          "bunx",
			args:         []string{"--registry", "https://t@reg.example.com/", "--package", "@scope/pkg", "--", "cmd"},
			wantSpec:     "@scope/pkg",
			wantLauncher: "",
		},
		{
			// Positive: pnpm dlx --package= before "--" is honored.
			name:         "pnpm dlx --package=<scoped> -- cmd",
			cmd:          "pnpm",
			args:         []string{"dlx", "--package=@scope/pkg", "--", "cmd"},
			wantSpec:     "@scope/pkg",
			wantLauncher: "",
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			gotSpec, gotLauncher := inferPackageFromArgs(c.cmd, c.args)
			if gotSpec != c.wantSpec || gotLauncher != c.wantLauncher {
				t.Errorf("inferPackageFromArgs(%q,%v) = (%q,%q), want (%q,%q)",
					c.cmd, c.args, gotSpec, gotLauncher, c.wantSpec, c.wantLauncher)
			}
		})
	}
}

// TestScanConfig_NonPackageSpecsDoNotRoundTrip is the end-to-end
// regression that proves raw URLs, paths, git/file refs, tarball
// references, and credential-bearing values never appear in
// PackageName or RequestedSpec. When the parsed spec is not a
// plausible package identity, the record falls back to the server id
// (existing behavior for empty specs) and RequestedSpec stays empty.
func TestScanConfig_NonPackageSpecsDoNotRoundTrip(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "mcp.json")
	body := `{
  "mcpServers": {
    "https-url":      {"command":"npx","args":["-y","https://user:token@reg.example.com/pkg.tgz"]},
    "http-url":       {"command":"npx","args":["http://reg.example.com/pkg"]},
    "git-plus":       {"command":"npx","args":["git+https://github.com/owner/repo.git"]},
    "git-ssh":        {"command":"npx","args":["git+ssh://git@github.com/owner/repo.git"]},
    "github-short":   {"command":"npx","args":["github:owner/repo"]},
    "file-ref":       {"command":"npx","args":["file:./local/pkg"]},
    "abs-path":       {"command":"npx","args":["/abs/path/to/pkg.tgz"]},
    "rel-path":       {"command":"npx","args":["./local/pkg"]},
    "tarball-bare":   {"command":"npx","args":["pkg.tgz"]},
    "tarball-tgz":    {"command":"npx","args":["archive.tar.gz"]},
    "win-path":       {"command":"npx","args":["C:\\\\Users\\\\me\\\\pkg"]},
    "registry-flag":  {"command":"npx","args":["--registry","https://token@reg.example.com/","valid-pkg"]},
    "registry-eq":    {"command":"npx","args":["--registry=https://token@reg.example.com/","@scope/valid"]},
    "pnpm-registry":  {"command":"pnpm","args":["dlx","--registry","https://token@reg.example.com/","@scope/valid"]},
    "yarn-cache":     {"command":"yarn","args":["dlx","--cache","/some/local/cache","left-pad@1.2.3"]},
    "bun-cwd":        {"command":"bun","args":["x","--cwd","/tmp/work","left-pad"]},
    "alias-url":      {"command":"npx","args":["-y","host@npm:https://user:token@reg.example.com/pkg.tgz"]},
    "alias-file":     {"command":"npx","args":["-y","host@npm:file:./local"]},
    "alias-relpath":  {"command":"npx","args":["-y","host@npm:../local"]}
  }
}`
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	var out []model.Record
	s := &Scanner{MaxFileSize: 1 << 20, Emit: func(r model.Record) { out = append(out, r) }}
	if err := s.ScanConfig(path, model.Record{}); err != nil {
		t.Fatal(err)
	}
	by := map[string]model.Record{}
	for _, r := range out {
		by[r.ServerName] = r
	}

	// Each rejected-spec entry must fall back to the server id, never
	// leak the raw arg into PackageName / RequestedSpec, and never echo
	// the embedded credentials anywhere on the record.
	leakySubstrings := []string{
		"://", "token", "user:", "git+", "github:", "file:",
		"/abs/", "./", ".tgz", ".tar.gz", "\\\\", "C:\\", "C:/",
	}
	rejected := []string{
		"https-url", "http-url", "git-plus", "git-ssh", "github-short",
		"file-ref", "abs-path", "rel-path", "tarball-bare", "tarball-tgz",
		"win-path",
		// Malformed npm-alias targets — the alias carve-out must not
		// let URL/file/path/userinfo shapes ride into PackageName or
		// RequestedSpec via "host@npm:<bad target>".
		"alias-url", "alias-file", "alias-relpath",
	}
	for _, id := range rejected {
		r, ok := by[id]
		if !ok {
			t.Fatalf("missing record %q: %+v", id, out)
		}
		if r.PackageName != id {
			t.Errorf("%s: PackageName = %q, want server-id fallback %q (raw arg leaked)", id, r.PackageName, id)
		}
		if r.NormalizedName != strings.ToLower(id) {
			t.Errorf("%s: NormalizedName = %q, want %q", id, r.NormalizedName, strings.ToLower(id))
		}
		if r.RequestedSpec != "" {
			t.Errorf("%s: RequestedSpec = %q, want empty (raw arg must not round-trip)", id, r.RequestedSpec)
		}
		for _, sub := range leakySubstrings {
			if strings.Contains(r.PackageName, sub) || strings.Contains(r.RequestedSpec, sub) {
				t.Errorf("%s: leaked substring %q in record: %+v", id, sub, r)
			}
		}
	}

	// The --registry/--cache/--cwd cases must extract the trailing valid
	// package spec, not the flag's URL/path value. The credential-bearing
	// URL must not appear anywhere on the record.
	if r := by["registry-flag"]; r.PackageName != "valid-pkg" || r.RequestedSpec != "" {
		t.Errorf("registry-flag: %+v", r)
	}
	for _, id := range []string{"registry-flag", "registry-eq", "pnpm-registry", "yarn-cache", "bun-cwd"} {
		r := by[id]
		if strings.Contains(r.PackageName, "token") || strings.Contains(r.RequestedSpec, "token") {
			t.Errorf("%s: leaked registry token: %+v", id, r)
		}
		if strings.Contains(r.PackageName, "://") || strings.Contains(r.RequestedSpec, "://") {
			t.Errorf("%s: leaked URL scheme: %+v", id, r)
		}
		if strings.Contains(r.PackageName, "/some/local") || strings.Contains(r.PackageName, "/tmp/work") {
			t.Errorf("%s: leaked local path: %+v", id, r)
		}
	}
	if r := by["registry-eq"]; r.PackageName != "@scope/valid" {
		t.Errorf("registry-eq: PackageName = %q, want @scope/valid", r.PackageName)
	}
	if r := by["pnpm-registry"]; r.PackageName != "@scope/valid" {
		t.Errorf("pnpm-registry: PackageName = %q, want @scope/valid", r.PackageName)
	}
	if r := by["yarn-cache"]; r.PackageName != "left-pad" || r.RequestedSpec != "left-pad@1.2.3" {
		t.Errorf("yarn-cache: %+v", r)
	}
	if r := by["bun-cwd"]; r.PackageName != "left-pad" {
		t.Errorf("bun-cwd: PackageName = %q, want left-pad", r.PackageName)
	}
}

// TestLooksUnresolvedShellVar exercises the multi-form variable detector
// added to drop literal ${VAR}/$VAR/%VAR% references the loader never
// expanded.
func TestLooksUnresolvedShellVar(t *testing.T) {
	yes := []string{
		"${CLAUDE_PLUGIN_ROOT}/foo",
		"$HOME/bin/x",
		"%APPDATA%\\Claude\\thing",
	}
	no := []string{
		"@scope/pkg",
		"plain-name",
		"price$99",       // $ followed by digit, not an identifier
		"foo % bar % qx", // percents with spaces between are not %VAR%
		"50%",
	}
	for _, s := range yes {
		if !looksUnresolvedShellVar(s) {
			t.Errorf("looksUnresolvedShellVar(%q) = false, want true", s)
		}
	}
	for _, s := range no {
		if looksUnresolvedShellVar(s) {
			t.Errorf("looksUnresolvedShellVar(%q) = true, want false", s)
		}
	}
}
