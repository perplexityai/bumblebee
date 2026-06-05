package scanner

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/perplexityai/bumblebee/internal/model"
	"github.com/perplexityai/bumblebee/internal/output"
)

// TestExpandedEcosystems exercises end-to-end dispatch for every ecosystem
// added in v0.1 beyond npm and PyPI. Each fixture is the minimum that
// produces at least one record from its parser.
func TestExpandedEcosystems(t *testing.T) {
	root := t.TempDir()

	// pnpm lockfile + store layout package.json
	writeFile(t, filepath.Join(root, "p-pnpm", "pnpm-lock.yaml"), `lockfileVersion: '6.0'

packages:

  /lodash@4.17.21:
    resolution: {integrity: sha512-aa}

  /@tanstack/query-core@5.0.0:
    resolution: {integrity: sha512-bb}
`)
	writeFile(t,
		filepath.Join(root, "p-pnpm", "node_modules", ".pnpm", "lodash@4.17.21", "node_modules", "lodash", "package.json"),
		`{"name":"lodash","version":"4.17.21"}`)

	// yarn classic
	writeFile(t, filepath.Join(root, "p-yarn", "yarn.lock"), `# yarn lockfile v1

lodash@^4.17.0:
  version "4.17.21"
  resolved "https://registry.yarnpkg.com/lodash/-/lodash-4.17.21.tgz"
  integrity sha512-y
`)

	// bun text lockfile
	writeFile(t, filepath.Join(root, "p-bun", "bun.lock"), `{
  // bun
  "lockfileVersion": 0,
  "packages": {
    "lodash": ["lodash@4.17.21"],
  }
}`)

	// go.sum + go.mod
	writeFile(t, filepath.Join(root, "p-go", "go.sum"), `github.com/example/foo v1.2.3 h1:abc=
github.com/example/foo v1.2.3/go.mod h1:def=
`)
	writeFile(t, filepath.Join(root, "p-go", "go.mod"), `module example.com/x
go 1.22
require github.com/example/foo v1.2.3
`)

	// Gemfile.lock
	writeFile(t, filepath.Join(root, "p-ruby", "Gemfile.lock"), `GEM
  remote: https://rubygems.org/
  specs:
    intercom-rails (0.4.3)
    rails (7.1.2)

PLATFORMS
  ruby
`)

	// Composer lock + installed.json
	writeFile(t, filepath.Join(root, "p-php", "composer.lock"), `{
  "packages":[{"name":"intercom/intercom-php","version":"5.0.2"}]
}`)
	writeFile(t, filepath.Join(root, "p-php", "vendor", "composer", "installed.json"), `{"packages":[{"name":"intercom/intercom-php","version":"5.0.2"}]}`)

	// MCP config
	writeFile(t, filepath.Join(root, "p-mcp", "mcp.json"), `{
  "mcpServers": {
    "github": {"command":"npx","args":["-y","@modelcontextprotocol/server-github"]}
  }
}`)

	// Gemini CLI / Gemini Code Assist user settings: settings.json sitting
	// under a `.gemini/` directory carries a top-level `mcpServers` map.
	// Dispatch is path-aware (parent dir == ".gemini") so an unrelated
	// settings.json (e.g. VS Code user settings) is not fed to the MCP
	// parser.
	writeFile(t, filepath.Join(root, ".gemini", "settings.json"), `{
  "mcpServers": {
    "gemini-search": {"command":"npx","args":["-y","@example/gemini-search"]}
  }
}`)
	// Same basename outside .gemini: must NOT be dispatched as MCP.
	writeFile(t, filepath.Join(root, ".vscode", "settings.json"), `{
  "mcpServers": {
    "should-not-dispatch": {"command":"npx","args":["-y","@example/should-not-dispatch"]}
  }
}`)

	// Agent-skill lock file: skills.sh / vercel-labs/skills format.
	// One github skill with a ref, one local skill whose on-disk path
	// must not leak into the emitted record.
	writeFile(t, filepath.Join(root, "p-skills", "skills-lock.json"), `{
  "version": 3,
  "skills": {
    "ai-sdk": {
      "source": "vercel/ai",
      "sourceType": "github",
      "ref": "main",
      "skillFolderHash": "deadbeef"
    },
    "my-local": {
      "source": "/Users/alice/secret/path/to/skill",
      "sourceType": "local"
    }
  }
}`)

	// VS Code extension
	writeFile(t,
		filepath.Join(root, ".vscode", "extensions", "ms-python.python-2024.0.0", "package.json"),
		`{"name":"python","version":"2024.0.0","publisher":"ms-python"}`)

	// Homebrew formula receipt + cask metadata marker.
	writeFile(t,
		filepath.Join(root, "Cellar", "wget", "1.21.4", "INSTALL_RECEIPT.json"),
		`{"installed_on_request":true,"source":{"tap":"homebrew/core"}}`)
	writeFile(t,
		filepath.Join(root, "Caskroom", "sample-cask", ".metadata", "2.0.0", "20260523010203.004", "Casks", "sample-cask.json"),
		`{"token":"sample-cask","version":"2.0.0"}`)

	// Chromium-family browser extension (Chrome layout). We create the
	// fixture under a fresh tempdir so the walker's default home-tree
	// excludes (which suffix-match Library/Application Support/Google/Chrome,
	// etc.) do not block enumeration. Operators point at these per-profile
	// Extensions/ roots directly via the curated baseline defaults.
	browserRoot := t.TempDir()
	chromeExtID := "abcdefghijklmnopabcdefghijklmnop"
	chromeExtensionsDir := filepath.Join(browserRoot, "Library", "Application Support", "Google", "Chrome", "Default", "Extensions")
	writeFile(t,
		filepath.Join(chromeExtensionsDir, chromeExtID, "1.4.2_0", "manifest.json"),
		`{"name":"Sample Chrome Extension","version":"1.4.2","manifest_version":3}`)

	// Firefox extensions.json under its own per-profile root.
	firefoxRoot := t.TempDir()
	firefoxProfileParent := filepath.Join(firefoxRoot, "Library", "Application Support", "Firefox", "Profiles")
	writeFile(t,
		filepath.Join(firefoxProfileParent, "abcd.default", "extensions.json"),
		`{"addons":[{"id":"sample@example.com","version":"0.9","type":"extension","active":true,"defaultLocale":{"name":"Sample Firefox Addon"}}]}`)

	stdout := &bytes.Buffer{}
	stderr := &bytes.Buffer{}
	em := output.New(stdout, stderr, "r")
	res, err := Run(context.Background(), Config{
		Roots: []Root{
			{Path: root, Kind: model.RootKindProject},
			{Path: chromeExtensionsDir, Kind: model.RootKindBrowserExtension},
			{Path: firefoxProfileParent, Kind: model.RootKindBrowserExtension},
		},
		Profile:     model.ProfileProject,
		MaxFileSize: 5 * 1024 * 1024,
		Concurrency: 4,
		BaseRecord: model.Record{
			SchemaVersion:  model.SchemaVersion,
			ScannerName:    model.ScannerName,
			ScannerVersion: "test",
			RunID:          "r",
			ScanTime:       time.Now().UTC().Format(time.RFC3339Nano),
		},
		Emitter: em,
	})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if res.RecordsEmitted == 0 {
		t.Fatalf("no records emitted; stderr=%s", stderr.String())
	}

	gotSource := map[string]bool{}
	gotEcosystem := map[string]bool{}
	gotPkg := map[string]bool{}
	gotRootKindByEcosystem := map[string]string{}
	for _, line := range bytes.Split(bytes.TrimSpace(stdout.Bytes()), []byte("\n")) {
		if len(line) == 0 {
			continue
		}
		var r model.Record
		if err := json.Unmarshal(line, &r); err != nil {
			t.Fatalf("bad ndjson: %v: %s", err, line)
		}
		gotSource[r.SourceType] = true
		gotEcosystem[r.Ecosystem] = true
		gotPkg[r.Ecosystem+":"+r.NormalizedName] = true
		gotRootKindByEcosystem[r.Ecosystem] = r.RootKind
	}

	wantSourceTypes := []string{
		"pnpm-lockfile",
		"pnpm-node_modules",
		"yarn-lockfile",
		"bun-lockfile",
		"go-sum",
		"go-mod",
		"rubygems-gemfile-lock",
		"composer-lock",
		"composer-installed",
		"mcp-config",
		"skill-lock",
		"editor-extension",
		"browser-extension",
		"homebrew-formula-receipt",
		"homebrew-cask-metadata",
	}
	for _, st := range wantSourceTypes {
		if !gotSource[st] {
			t.Errorf("missing source_type %q", st)
		}
	}
	wantEcosystems := []string{"npm", "go", "rubygems", "packagist", "mcp", "editor-extension", "browser-extension", "homebrew", "agent-skill"}
	for _, e := range wantEcosystems {
		if !gotEcosystem[e] {
			t.Errorf("missing ecosystem %q", e)
		}
	}

	// Verify a few specific packages we expect to find by name.
	wantPkgs := []string{
		"npm:lodash",
		"npm:@tanstack/query-core",
		"go:github.com/example/foo",
		"rubygems:intercom-rails",
		"packagist:intercom/intercom-php",
		"mcp:@modelcontextprotocol/server-github",
		"mcp:@example/gemini-search",
		"agent-skill:vercel/ai",
		// Local skills fall back to the local alias as PackageName so
		// the on-disk path in `source` does not leak into the record.
		"agent-skill:my-local",
		"editor-extension:ms-python.python",
		"browser-extension:" + chromeExtID,
		"browser-extension:sample@example.com",
		"homebrew:wget",
		"homebrew:sample-cask",
	}
	for _, p := range wantPkgs {
		if !gotPkg[p] {
			t.Errorf("missing pkg %q", p)
		}
	}

	// Path-aware dispatch must not pick up an unrelated settings.json
	// (e.g. VS Code user settings) even when its contents happen to
	// look like an MCP envelope. The fixture above places one under
	// .vscode/ with a sentinel server id.
	if gotPkg["mcp:@example/should-not-dispatch"] {
		t.Errorf("unexpected MCP dispatch of non-Gemini settings.json — basename match must be path-aware")
	}

	if got := gotRootKindByEcosystem["browser-extension"]; got != model.RootKindBrowserExtension {
		t.Errorf("browser-extension root_kind=%q, want %q", got, model.RootKindBrowserExtension)
	}
	// MCP record sits under the project root in this fixture, so it
	// inherits project_root from the configured Roots lookup. The MCP
	// scanner's RootKindMCPConfig fallback only fires when the source
	// path is outside any configured root.
	if got := gotRootKindByEcosystem["mcp"]; got != model.RootKindProject {
		t.Errorf("mcp root_kind=%q, want %q", got, model.RootKindProject)
	}
	// Same inheritance applies to agent-skill records under the project
	// root: the configured root_kind wins over the scanner's
	// RootKindAgentSkill fallback.
	if got := gotRootKindByEcosystem["agent-skill"]; got != model.RootKindProject {
		t.Errorf("agent-skill root_kind=%q, want %q", got, model.RootKindProject)
	}

	// Belt-and-braces: verify the local-skill `source` path string never
	// appears anywhere in stdout. The fixture used a /Users/alice path
	// that does not collide with any other field, so any occurrence is
	// a leak.
	if bytes.Contains(stdout.Bytes(), []byte("/Users/alice/secret/path/to/skill")) {
		t.Errorf("local skill on-disk path leaked into emitted records")
	}

	// stderr should be NDJSON diagnostics only.
	for _, line := range bytes.Split(bytes.TrimSpace(stderr.Bytes()), []byte("\n")) {
		if len(line) == 0 {
			continue
		}
		var d model.Diagnostic
		if err := json.Unmarshal(line, &d); err != nil {
			t.Fatalf("stderr not a diagnostic: %v: %s", err, line)
		}
	}
}

func TestBunBinaryDiagnostic(t *testing.T) {
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "bun.lockb"), []byte("\x00\x01\x02"), 0o644); err != nil {
		t.Fatal(err)
	}
	stdout := &bytes.Buffer{}
	stderr := &bytes.Buffer{}
	em := output.New(stdout, stderr, "r")
	_, err := Run(context.Background(), Config{
		Roots:       []Root{{Path: root, Kind: model.RootKindProject}},
		Profile:     model.ProfileProject,
		MaxFileSize: 1 << 20,
		Concurrency: 1,
		Emitter:     em,
	})
	if err != nil {
		t.Fatal(err)
	}
	if stdout.Len() != 0 {
		t.Errorf("bun.lockb should emit no records, got %s", stdout.String())
	}
	if !bytes.Contains(stderr.Bytes(), []byte("bun.lockb detected")) {
		t.Errorf("expected diagnostic for bun.lockb; got %s", stderr.String())
	}
}

func TestEcosystemFilterPrunesDispatch(t *testing.T) {
	root := t.TempDir()
	writeFile(t, filepath.Join(root, "proj", "package-lock.json"), `{
  "lockfileVersion": 3,
  "packages": {"node_modules/lodash": {"version":"4.17.21"}}
}`)
	writeFile(t, filepath.Join(root, "proj", "go.mod"), `module example.com/x
go 1.22
require github.com/example/foo v1.2.3
`)

	stdout := &bytes.Buffer{}
	stderr := &bytes.Buffer{}
	em := output.New(stdout, stderr, "r")
	res, err := Run(context.Background(), Config{
		Roots:       []Root{{Path: root, Kind: model.RootKindProject}},
		Profile:     model.ProfileProject,
		Ecosystems:  map[string]bool{model.EcosystemGo: true},
		MaxFileSize: 5 * 1024 * 1024,
		Concurrency: 2,
		BaseRecord: model.Record{
			SchemaVersion:  model.SchemaVersion,
			ScannerName:    model.ScannerName,
			ScannerVersion: "test",
			RunID:          "r",
			ScanTime:       time.Now().UTC().Format(time.RFC3339Nano),
		},
		Emitter: em,
	})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if res.RecordsEmitted == 0 {
		t.Fatalf("expected at least one record, stderr=%s", stderr.String())
	}
	if bytes.Contains(stdout.Bytes(), []byte(`"ecosystem":"npm"`)) {
		t.Fatalf("npm record emitted despite go-only filter: %s", stdout.String())
	}
	if !bytes.Contains(stdout.Bytes(), []byte(`"ecosystem":"go"`)) {
		t.Fatalf("go record missing under go-only filter: %s", stdout.String())
	}
}
