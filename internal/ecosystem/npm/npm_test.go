package npm

import (
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/perplexityai/bumblebee/internal/model"
)

func newCollector() (*Scanner, *[]model.Record, *[]string) {
	var got []model.Record
	var diags []string
	s := &Scanner{
		MaxFileSize: 5 * 1024 * 1024,
		Emit:        func(r model.Record) { got = append(got, r) },
		Diag:        func(level, path, msg string) { diags = append(diags, level+":"+path+":"+msg) },
	}
	return s, &got, &diags
}

func writeFile(t *testing.T, path, body string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
}

func TestScanLockfileV3ScopedAndUnscoped(t *testing.T) {
	dir := t.TempDir()
	lock := filepath.Join(dir, "package-lock.json")
	writeFile(t, lock, `{
  "name": "demo",
  "version": "1.0.0",
  "lockfileVersion": 3,
  "packages": {
    "": { "name": "demo", "version": "1.0.0" },
    "node_modules/lodash": {
      "version": "4.17.21",
      "resolved": "https://registry.npmjs.org/lodash/-/lodash-4.17.21.tgz",
      "integrity": "sha512-abc"
    },
    "node_modules/@tanstack/query-core": {
      "version": "5.0.0",
      "resolved": "https://registry.npmjs.org/@tanstack/query-core/-/query-core-5.0.0.tgz",
      "integrity": "sha512-xyz",
      "dev": true
    },
    "node_modules/@tanstack/query-core/node_modules/lodash": {
      "version": "4.17.20"
    }
  }
}`)

	s, got, _ := newCollector()
	if err := s.ScanLockfile(lock, model.Record{}); err != nil {
		t.Fatalf("ScanLockfile: %v", err)
	}
	names := map[string]model.Record{}
	for _, r := range *got {
		names[r.NormalizedName+"@"+r.Version] = r
	}
	if r, ok := names["lodash@4.17.21"]; !ok {
		t.Fatal("missing lodash@4.17.21")
	} else {
		if r.DirectDependency == nil || !*r.DirectDependency {
			t.Errorf("lodash should be direct")
		}
		if r.PackageName != "lodash" || r.NormalizedName != "lodash" {
			t.Errorf("name/normalized = %q/%q", r.PackageName, r.NormalizedName)
		}
		if r.SourceType != "npm-lockfile" {
			t.Errorf("source_type = %q", r.SourceType)
		}
	}
	if r, ok := names["@tanstack/query-core@5.0.0"]; !ok {
		t.Fatal("missing @tanstack/query-core@5.0.0")
	} else {
		if r.InstallScope != "dev" {
			t.Errorf("install_scope = %q, want dev", r.InstallScope)
		}
		if r.NormalizedName != "@tanstack/query-core" {
			t.Errorf("normalized = %q", r.NormalizedName)
		}
	}
	if r, ok := names["lodash@4.17.20"]; !ok {
		t.Fatal("missing nested lodash@4.17.20")
	} else if r.DirectDependency == nil || *r.DirectDependency {
		t.Errorf("nested lodash should not be direct")
	}
}

func TestScanLockfileV1(t *testing.T) {
	dir := t.TempDir()
	lock := filepath.Join(dir, "npm-shrinkwrap.json")
	writeFile(t, lock, `{
  "name": "demo",
  "version": "1.0.0",
  "lockfileVersion": 1,
  "dependencies": {
    "react": {
      "version": "18.2.0",
      "resolved": "https://registry.npmjs.org/react/-/react-18.2.0.tgz",
      "integrity": "sha512-rrr",
      "requires": { "loose-envify": "^1.1.0" },
      "dependencies": {
        "loose-envify": { "version": "1.4.0" }
      }
    }
  }
}`)
	s, got, _ := newCollector()
	if err := s.ScanLockfile(lock, model.Record{}); err != nil {
		t.Fatalf("ScanLockfile: %v", err)
	}
	var have []string
	for _, r := range *got {
		have = append(have, r.NormalizedName+"@"+r.Version)
	}
	sort.Strings(have)
	if len(have) != 2 || have[0] != "loose-envify@1.4.0" || have[1] != "react@18.2.0" {
		t.Fatalf("got %v", have)
	}
}

func TestScanNodeModulesPackageJSONLifecycleScripts(t *testing.T) {
	dir := t.TempDir()
	pj := filepath.Join(dir, "node_modules", "evil", "package.json")
	writeFile(t, pj, `{
  "name": "evil",
  "version": "0.1.0",
  "scripts": {
    "preinstall": "node ./bad.js",
    "test": "jest"
  },
  "_resolved": "https://registry.npmjs.org/evil/-/evil-0.1.0.tgz",
  "_integrity": "sha512-xx"
}`)
	ok, proj := IsNodeModulesPackageJSON(pj)
	if !ok || proj == "" {
		t.Fatalf("IsNodeModulesPackageJSON failed: %v %q", ok, proj)
	}
	if filepath.Clean(proj) != filepath.Clean(dir) {
		t.Fatalf("projectPath = %q, want %q", proj, dir)
	}
	s, got, _ := newCollector()
	if err := s.ScanNodeModulesPackageJSON(pj, proj, model.Record{}); err != nil {
		t.Fatalf("scan: %v", err)
	}
	if len(*got) != 1 {
		t.Fatalf("expected 1 record, got %d", len(*got))
	}
	r := (*got)[0]
	if !r.HasLifecycleScripts {
		t.Errorf("expected lifecycle scripts flag")
	}
	if len(r.LifecycleScripts) != 1 || r.LifecycleScripts[0] != "preinstall" {
		t.Errorf("lifecycle = %v", r.LifecycleScripts)
	}
}

func TestIsNodeModulesPackageJSONShapes(t *testing.T) {
	cases := map[string]bool{
		"/home/u/proj/node_modules/foo/package.json":                  true,
		"/home/u/proj/node_modules/@scope/pkg/package.json":           true,
		"/home/u/proj/node_modules/foo/node_modules/bar/package.json": true,
		"/home/u/proj/node_modules/@scope/pkg/lib/package.json":       false,
		"/home/u/proj/package.json":                                   false,
		"/home/u/proj/node_modules/@scope/package.json":               false,
	}
	for in, want := range cases {
		got, _ := IsNodeModulesPackageJSON(in)
		if got != want {
			t.Errorf("IsNodeModulesPackageJSON(%q) = %v, want %v", in, got, want)
		}
	}
}

// TestIsNodeModulesPackageJSONRelativeRoot verifies a lockfile-relative
// path like "node_modules/foo/package.json" reports projectPath="."
// rather than the misleading absolute root "/".
func TestIsNodeModulesPackageJSONRelativeRoot(t *testing.T) {
	ok, proj := IsNodeModulesPackageJSON("node_modules/foo/package.json")
	if !ok {
		t.Fatal("expected recognition of a relative node_modules path")
	}
	if proj != "." {
		t.Errorf("projectPath = %q, want %q", proj, ".")
	}
}

func TestMaxFileSizeSkip(t *testing.T) {
	dir := t.TempDir()
	lock := filepath.Join(dir, "package-lock.json")
	writeFile(t, lock, `{"lockfileVersion":3,"packages":{}}`)
	s, got, diags := newCollector()
	s.MaxFileSize = 4
	err := s.ScanLockfile(lock, model.Record{})
	if err == nil {
		t.Fatal("expected error for oversize file")
	}
	if !strings.Contains(err.Error(), "exceeds max size") {
		t.Errorf("error = %v", err)
	}
	if len(*got) != 0 {
		t.Errorf("no records expected")
	}
	if len(*diags) == 0 {
		t.Errorf("expected a diagnostic")
	}
}

func TestMalformedLockfile(t *testing.T) {
	dir := t.TempDir()
	lock := filepath.Join(dir, "package-lock.json")
	writeFile(t, lock, `{not valid json`)
	s, got, _ := newCollector()
	if err := s.ScanLockfile(lock, model.Record{}); err == nil {
		t.Fatal("expected parse error")
	}
	if len(*got) != 0 {
		t.Errorf("no records expected")
	}
}
