package yarn

import (
	"os"
	"path/filepath"
	"sort"
	"testing"

	"github.com/perplexityai/bumblebee/internal/model"
)

func TestNameFromYarnHeader(t *testing.T) {
	cases := []struct{ in, want string }{
		{`"lodash@^4.17.0"`, "lodash"},
		{`lodash@^4.17.0`, "lodash"},
		{`"@scope/pkg@^1.0.0"`, "@scope/pkg"},
		{`"@scope/pkg@^1.0.0, @scope/pkg@^1.1.0"`, "@scope/pkg"},
		{`"lodash@npm:^4.17.0"`, "lodash"},
		{`"@tanstack/query-core@npm:5.0.0"`, "@tanstack/query-core"},
		// Berry spec with an embedded comma in the version range. The
		// descriptor list separator is ", " (comma+space), so a bare
		// comma inside the spec must not truncate the descriptor.
		{`"foo@npm:>=1, <2"`, "foo"},
	}
	for _, c := range cases {
		if g := nameFromYarnHeader(c.in); g != c.want {
			t.Errorf("nameFromYarnHeader(%q) = %q, want %q", c.in, g, c.want)
		}
	}
}

func TestScanLockfile_Classic(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "yarn.lock")
	body := `# yarn lockfile v1

lodash@^4.17.0:
  version "4.17.21"
  resolved "https://registry.yarnpkg.com/lodash/-/lodash-4.17.21.tgz"
  integrity sha512-xyz

"@tanstack/query-core@^5.0.0":
  version "5.0.0"
  resolved "https://registry.yarnpkg.com/@tanstack/query-core/-/query-core-5.0.0.tgz"
  integrity sha512-tan

chalk@^5.0.0, chalk@^5.3.0:
  version "5.3.0"
  resolved "https://registry.yarnpkg.com/chalk/-/chalk-5.3.0.tgz"
  integrity sha512-chalk
`
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	var out []model.Record
	s := &Scanner{MaxFileSize: 1 << 20, Emit: func(r model.Record) { out = append(out, r) }}
	if err := s.ScanLockfile(path, model.Record{}); err != nil {
		t.Fatal(err)
	}
	if len(out) != 3 {
		t.Fatalf("want 3 records, got %d", len(out))
	}
	sort.Slice(out, func(i, j int) bool { return out[i].PackageName < out[j].PackageName })
	if out[0].PackageName != "@tanstack/query-core" || out[0].Version != "5.0.0" {
		t.Errorf("first: %+v", out[0])
	}
	if out[1].PackageName != "chalk" || out[1].Version != "5.3.0" {
		t.Errorf("chalk: %+v", out[1])
	}
	if out[2].PackageName != "lodash" || out[2].Version != "4.17.21" {
		t.Errorf("lodash: %+v", out[2])
	}
}

func TestScanLockfile_DirectFromPackageJSON(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "package.json"), []byte(`{
  "name": "demo",
  "dependencies": {"lodash": "^4.17.0"},
  "devDependencies": {"chalk": "^5.0.0"}
}`), 0o644); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "yarn.lock")
	body := `# yarn lockfile v1

lodash@^4.17.0:
  version "4.17.21"

chalk@^5.0.0:
  version "5.3.0"

ms@^2.0.0:
  version "2.1.3"
`
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	var out []model.Record
	s := &Scanner{MaxFileSize: 1 << 20, Emit: func(r model.Record) { out = append(out, r) }}
	if err := s.ScanLockfile(path, model.Record{}); err != nil {
		t.Fatal(err)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].PackageName < out[j].PackageName })
	expect := map[string]bool{
		"chalk":  true,
		"lodash": true,
		"ms":     false,
	}
	for _, r := range out {
		want, ok := expect[r.PackageName]
		if !ok {
			t.Fatalf("unexpected pkg %q", r.PackageName)
		}
		if r.DirectDependency == nil {
			t.Errorf("%s: DirectDependency=nil, want %v", r.PackageName, want)
			continue
		}
		if *r.DirectDependency != want {
			t.Errorf("%s: DirectDependency=%v, want %v", r.PackageName, *r.DirectDependency, want)
		}
	}
}

func TestScanLockfile_NoPackageJSONLeavesDirectUnset(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "yarn.lock")
	body := `lodash@^4.17.0:
  version "4.17.21"
`
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	var out []model.Record
	s := &Scanner{MaxFileSize: 1 << 20, Emit: func(r model.Record) { out = append(out, r) }}
	if err := s.ScanLockfile(path, model.Record{}); err != nil {
		t.Fatal(err)
	}
	if len(out) != 1 {
		t.Fatalf("want 1, got %d", len(out))
	}
	if out[0].DirectDependency != nil {
		t.Errorf("expected DirectDependency nil, got %v", *out[0].DirectDependency)
	}
}

// TestScanLockfile_MalformedPackageJSONEmitsDiag verifies that an
// unparseable sibling package.json surfaces a warn diagnostic rather
// than silently leaving DirectDependency unset. A missing package.json
// remains silent — that is the common case.
func TestScanLockfile_MalformedPackageJSONEmitsDiag(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "package.json"), []byte(`{not valid`), 0o644); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "yarn.lock")
	body := `lodash@^4.17.0:
  version "4.17.21"
`
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	type diag struct{ level, path, msg string }
	var diags []diag
	s := &Scanner{
		MaxFileSize: 1 << 20,
		Emit:        func(r model.Record) {},
		Diag:        func(level, p, msg string) { diags = append(diags, diag{level, p, msg}) },
	}
	if err := s.ScanLockfile(path, model.Record{}); err != nil {
		t.Fatal(err)
	}
	found := false
	for _, d := range diags {
		if d.level == "warn" && d.path == filepath.Join(dir, "package.json") {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected warn diag for malformed package.json, got %+v", diags)
	}
}

func TestScanLockfile_Berry(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "yarn.lock")
	body := `# This file is generated by running "yarn install" inside your project.

__metadata:
  version: 6
  cacheKey: 8

"lodash@npm:^4.17.0":
  version: 4.17.21
  resolution: "lodash@npm:4.17.21"
  checksum: 10/abc
  languageName: node
  linkType: hard
`
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	var out []model.Record
	s := &Scanner{MaxFileSize: 1 << 20, Emit: func(r model.Record) { out = append(out, r) }}
	if err := s.ScanLockfile(path, model.Record{}); err != nil {
		t.Fatal(err)
	}
	if len(out) != 1 {
		t.Fatalf("want 1 record, got %d", len(out))
	}
	if out[0].PackageName != "lodash" || out[0].Version != "4.17.21" {
		t.Errorf("lodash: %+v", out[0])
	}
}

// TestScanLockfile_DependencyNamedVersion guards against a dependency
// literally named "version" (a real npm package) inside a
// dependencies:/peerDependencies: block overwriting the entry's own
// version, which yarn always emits as the first field.
func TestScanLockfile_DependencyNamedVersion(t *testing.T) {
	cases := []struct {
		name string
		body string
	}{
		{
			name: "classic",
			body: `# yarn lockfile v1

board2d@^1.0.0:
  version "1.0.0"
  resolved "https://registry.yarnpkg.com/board2d/-/board2d-1.0.0.tgz"
  integrity sha512-xyz
  dependencies:
    version "^0.1.0"
`,
		},
		{
			name: "berry",
			body: `# This file is generated by running "yarn install" inside your project.

__metadata:
  version: 6
  cacheKey: 8

"board2d@npm:^1.0.0":
  version: 1.0.0
  resolution: "board2d@npm:1.0.0"
  dependencies:
    version: "npm:^0.1.0"
  checksum: 10/abc
  languageName: node
  linkType: hard
`,
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			dir := t.TempDir()
			path := filepath.Join(dir, "yarn.lock")
			if err := os.WriteFile(path, []byte(c.body), 0o644); err != nil {
				t.Fatal(err)
			}
			var out []model.Record
			s := &Scanner{MaxFileSize: 1 << 20, Emit: func(r model.Record) { out = append(out, r) }}
			if err := s.ScanLockfile(path, model.Record{}); err != nil {
				t.Fatal(err)
			}
			if len(out) != 1 {
				t.Fatalf("want 1 record, got %d", len(out))
			}
			if out[0].PackageName != "board2d" || out[0].Version != "1.0.0" {
				t.Errorf("board2d: got name=%q version=%q, want name=%q version=%q",
					out[0].PackageName, out[0].Version, "board2d", "1.0.0")
			}
		})
	}
}
