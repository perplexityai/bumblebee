package pnpm

import (
	"os"
	"path/filepath"
	"sort"
	"testing"

	"github.com/perplexityai/bumblebee/internal/model"
)

func TestSplitPnpmLockKey(t *testing.T) {
	cases := []struct {
		in      string
		name    string
		version string
	}{
		{"/lodash@4.17.21", "lodash", "4.17.21"},
		{"/@tanstack/query-core@5.0.0", "@tanstack/query-core", "5.0.0"},
		{"/lodash@4.17.21(peer@1.0.0)", "lodash", "4.17.21"},
		{"lodash@4.17.21", "lodash", "4.17.21"},
		{"@scope/pkg@1.2.3", "@scope/pkg", "1.2.3"},
		{"/lodash/4.17.21", "lodash", "4.17.21"},
		{"/@scope/pkg/1.2.3", "@scope/pkg", "1.2.3"},
		{"", "", ""},
	}
	for _, c := range cases {
		n, v := splitPnpmLockKey(c.in)
		if n != c.name || v != c.version {
			t.Errorf("splitPnpmLockKey(%q) = (%q,%q), want (%q,%q)", c.in, n, v, c.name, c.version)
		}
	}
}

func TestSplitPnpmStoreDir(t *testing.T) {
	cases := []struct {
		in      string
		name    string
		version string
	}{
		{"lodash@4.17.21", "lodash", "4.17.21"},
		{"lodash@4.17.21_react@18.0.0", "lodash", "4.17.21"},
		{"@tanstack+query-core@5.0.0", "@tanstack/query-core", "5.0.0"},
		// Regression: package names containing '_' must keep their version.
		// See release review B1: the previous implementation split on the
		// first '_' in the entire string, which eats the version when the
		// name itself contains '_' (e.g. string_decoder, @types/babel__core).
		{"string_decoder@1.1.1", "string_decoder", "1.1.1"},
		{"@types+babel__core@7.20.5", "@types/babel__core", "7.20.5"},
		{"@scope+pkg@1.2.3_peer@4.5.6", "@scope/pkg", "1.2.3"},
		{"string_decoder@1.3.0_react@18.2.0", "string_decoder", "1.3.0"},
	}
	for _, c := range cases {
		n, v := splitPnpmStoreDir(c.in)
		if n != c.name || v != c.version {
			t.Errorf("splitPnpmStoreDir(%q) = (%q,%q), want (%q,%q)", c.in, n, v, c.name, c.version)
		}
	}
}

func TestIsPnpmStorePackageJSON(t *testing.T) {
	ok, proj, name, ver := IsPnpmStorePackageJSON("/x/proj/node_modules/.pnpm/lodash@4.17.21/node_modules/lodash/package.json")
	if !ok || filepath.ToSlash(proj) != "/x/proj" || name != "lodash" || ver != "4.17.21" {
		t.Errorf("got ok=%v proj=%q name=%q ver=%q", ok, proj, name, ver)
	}
	ok, proj, name, ver = IsPnpmStorePackageJSON("/x/proj/node_modules/.pnpm/@tanstack+query-core@5.0.0/node_modules/@tanstack/query-core/package.json")
	if !ok || name != "@tanstack/query-core" || ver != "5.0.0" || filepath.ToSlash(proj) != "/x/proj" {
		t.Errorf("scoped: got ok=%v proj=%q name=%q ver=%q", ok, proj, name, ver)
	}
	if ok, _, _, _ := IsPnpmStorePackageJSON("/x/proj/node_modules/lodash/package.json"); ok {
		t.Errorf("non-pnpm path should not match")
	}
}

// TestIsPnpmStorePackageJSONRelativeRoot verifies a lockfile-relative
// path with no parent segments reports projectPath="." rather than the
// misleading absolute root "/".
func TestIsPnpmStorePackageJSONRelativeRoot(t *testing.T) {
	ok, proj, name, ver := IsPnpmStorePackageJSON("node_modules/.pnpm/lodash@4.17.21/node_modules/lodash/package.json")
	if !ok {
		t.Fatal("expected recognition of a relative pnpm store path")
	}
	if proj != "." {
		t.Errorf("projectPath = %q, want %q", proj, ".")
	}
	if name != "lodash" || ver != "4.17.21" {
		t.Errorf("name=%q ver=%q", name, ver)
	}
}

func TestScanLockfile(t *testing.T) {
	dir := t.TempDir()
	lock := filepath.Join(dir, "pnpm-lock.yaml")
	body := `lockfileVersion: '6.0'

settings:
  autoInstallPeers: true

importers:

  .:
    dependencies:
      lodash:
        specifier: ^4.17.0
        version: 4.17.21
      '@tanstack/query-core':
        specifier: ^5.0.0
        version: 5.0.0
    devDependencies:
      chalk:
        specifier: ^5.3.0
        version: 5.3.0(peer@1.0.0)

  packages/inner:
    dependencies:
      ms:
        specifier: ^2
        version: 2.1.3

packages:

  /lodash@4.17.21:
    resolution: {integrity: sha512-aaa, tarball: https://r/npm/lodash/-/lodash-4.17.21.tgz}
    dev: false

  /@tanstack/query-core@5.0.0:
    resolution:
      integrity: sha512-bbb
      tarball: https://r/npm/tan.tgz
    requiresBuild: true

  /chalk@5.3.0(peer@1.0.0):
    resolution: {integrity: sha512-ccc}
    dev: true

  /ms@2.1.3:
    resolution: {integrity: sha512-mmm}
    dev: false

  /tslib@2.6.2:
    resolution: {integrity: sha512-ttt}
    dev: false

snapshots:
  thisShouldNotBeParsed: {}
`
	if err := os.WriteFile(lock, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	var out []model.Record
	s := &Scanner{
		MaxFileSize: 1 << 20,
		Emit:        func(r model.Record) { out = append(out, r) },
	}
	if err := s.ScanLockfile(lock, model.Record{}); err != nil {
		t.Fatal(err)
	}
	if len(out) != 5 {
		t.Fatalf("want 5 records, got %d: %+v", len(out), out)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].PackageName < out[j].PackageName })
	want := map[string]string{
		"@tanstack/query-core": "5.0.0",
		"chalk":                "5.3.0",
		"lodash":               "4.17.21",
		"ms":                   "2.1.3",
		"tslib":                "2.6.2",
	}
	wantDirect := map[string]*bool{
		"lodash":               ptrTrue(),
		"@tanstack/query-core": ptrTrue(),
		"chalk":                ptrTrue(),
		// ms is declared only by a workspace importer, not by ".".
		// tslib is purely transitive (not in any importer block).
		// Both are non-direct: the importers parse produced hits, so the
		// field is set to false rather than absent.
		"ms":    ptrFalse(),
		"tslib": ptrFalse(),
	}
	for _, r := range out {
		if want[r.PackageName] != r.Version {
			t.Errorf("%s: got version %q", r.PackageName, r.Version)
		}
		if r.SourceType != "pnpm-lockfile" {
			t.Errorf("source_type=%q", r.SourceType)
		}
		if r.PackageManager != "pnpm" {
			t.Errorf("package_manager=%q", r.PackageManager)
		}
		exp := wantDirect[r.PackageName]
		switch {
		case exp == nil && r.DirectDependency != nil:
			t.Errorf("%s: expected DirectDependency absent, got %v", r.PackageName, *r.DirectDependency)
		case exp != nil && r.DirectDependency == nil:
			t.Errorf("%s: expected DirectDependency=%v, got nil", r.PackageName, *exp)
		case exp != nil && r.DirectDependency != nil && *exp != *r.DirectDependency:
			t.Errorf("%s: DirectDependency=%v want %v", r.PackageName, *r.DirectDependency, *exp)
		}
	}
	for _, r := range out {
		if r.PackageName == "@tanstack/query-core" && !r.HasLifecycleScripts {
			t.Errorf("requiresBuild should set HasLifecycleScripts")
		}
		if r.PackageName == "chalk" && r.InstallScope != "dev" {
			t.Errorf("chalk install_scope=%q", r.InstallScope)
		}
		if r.PackageName == "lodash" && r.Version != "4.17.21" {
			t.Errorf("lodash version=%q", r.Version)
		}
	}
}

func ptrTrue() *bool  { b := true; return &b }
func ptrFalse() *bool { b := false; return &b }

func TestPnpmDirectsV5Layout(t *testing.T) {
	body := []byte(`lockfileVersion: '5.4'

dependencies:
  lodash: 4.17.21
  '@scope/foo': 1.2.3

devDependencies:
  chalk: 5.3.0

packages:
  /lodash/4.17.21:
    resolution: {integrity: sha512-x}
`)
	got := parsePnpmImporterDirects(body)
	wantKeys := []string{
		directKey("lodash", "4.17.21"),
		directKey("@scope/foo", "1.2.3"),
		directKey("chalk", "5.3.0"),
	}
	for _, k := range wantKeys {
		if _, ok := got[k]; !ok {
			t.Errorf("v5 direct missing: %q", k)
		}
	}
}

func TestPnpmDirectsIgnoresWorkspaceImporters(t *testing.T) {
	body := []byte(`importers:

  .:
    dependencies:
      lodash:
        specifier: ^4
        version: 4.17.21

  packages/sub:
    dependencies:
      ms:
        specifier: ^2
        version: 2.1.3

packages:
  /lodash@4.17.21:
    resolution: {integrity: x}
`)
	got := parsePnpmImporterDirects(body)
	if _, ok := got[directKey("lodash", "4.17.21")]; !ok {
		t.Error("expected lodash@4.17.21 to be direct")
	}
	if _, ok := got[directKey("ms", "2.1.3")]; ok {
		t.Error("workspace importer ms@2.1.3 must not be direct")
	}
}

func TestScanLockfile_NoImportersLeavesDirectUnset(t *testing.T) {
	dir := t.TempDir()
	lock := filepath.Join(dir, "pnpm-lock.yaml")
	// No importers block and no v5-layout dep sections. DirectDependency
	// must be absent on every emitted record.
	body := `lockfileVersion: '6.0'

packages:

  /lodash@4.17.21:
    resolution: {integrity: sha512-aaa}
`
	if err := os.WriteFile(lock, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	var out []model.Record
	s := &Scanner{MaxFileSize: 1 << 20, Emit: func(r model.Record) { out = append(out, r) }}
	if err := s.ScanLockfile(lock, model.Record{}); err != nil {
		t.Fatal(err)
	}
	if len(out) != 1 {
		t.Fatalf("want 1, got %d", len(out))
	}
	if out[0].DirectDependency != nil {
		t.Errorf("expected DirectDependency nil, got %v", *out[0].DirectDependency)
	}
}
