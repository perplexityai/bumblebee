package exposure

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/perplexityai/bumblebee/internal/model"
)

func TestParseWrappedForm(t *testing.T) {
	wrapped := []byte(`{
  "schema_version": "0.1.0",
  "entries": [
    {"id":"adv-1","ecosystem":"npm","package":"left-pad","versions":["1.3.0"]}
  ]
}`)
	c, err := Parse(wrapped)
	if err != nil {
		t.Fatalf("parse wrapped: %v", err)
	}
	if c.Len() != 1 {
		t.Fatalf("wrapped len=%d", c.Len())
	}
}

func TestParseBareArrayRejected(t *testing.T) {
	bare := []byte(`[{"id":"adv-2","ecosystem":"pypi","package":"Requests","versions":["2.31.0"]}]`)
	if _, err := Parse(bare); err == nil {
		t.Fatal("expected bare array to be rejected")
	}
}

func TestParseEmptyIsNoop(t *testing.T) {
	c, err := Parse([]byte("   "))
	if err != nil {
		t.Fatalf("empty parse: %v", err)
	}
	if c.Len() != 0 {
		t.Fatalf("expected empty catalog")
	}
	r := model.Record{Ecosystem: "npm", NormalizedName: "anything", Version: "1.0.0"}
	if e, _ := c.Match(r); e != nil {
		t.Fatalf("expected no match against empty catalog")
	}
}

// TestParseValidEmptyEntriesCatalog accepts the explicit zero-entry shape
// (both required fields present, entries is an empty array) as a no-op.
func TestParseValidEmptyEntriesCatalog(t *testing.T) {
	c, err := Parse([]byte(`{"schema_version":"0.1.0","entries":[]}`))
	if err != nil {
		t.Fatalf("expected zero-entry catalog to parse: %v", err)
	}
	if c.Len() != 0 {
		t.Fatalf("expected len=0, got %d", c.Len())
	}
}

// TestParseRejectsObjectsMissingRequiredFields enforces the published
// JSON schema: schema_version and entries are required on any object
// root. Objects that omit either are rejected.
func TestParseRejectsObjectsMissingRequiredFields(t *testing.T) {
	cases := map[string][]byte{
		"empty object":              []byte(`{}`),
		"missing schema_version":    []byte(`{"entries":[]}`),
		"missing entries":           []byte(`{"schema_version":"0.1.0"}`),
		"object with unknown shape": []byte(`{"packages":[]}`),
	}
	for name, body := range cases {
		if _, err := Parse(body); err == nil {
			t.Errorf("%s: expected error, got nil", name)
		}
	}
}

func TestParseRejectsMissingFields(t *testing.T) {
	cases := [][]byte{
		[]byte(`{"schema_version":"0.1.0","entries":[{"ecosystem":"npm","package":"x","versions":["1.0.0"]}]}`),   // missing id
		[]byte(`{"schema_version":"0.1.0","entries":[{"id":"a","package":"x","versions":["1.0.0"]}]}`),            // missing ecosystem
		[]byte(`{"schema_version":"0.1.0","entries":[{"id":"a","ecosystem":"npm","versions":["1.0.0"]}]}`),        // missing package
		[]byte(`{"schema_version":"0.1.0","entries":[{"id":"a","ecosystem":"npm","package":"x","versions":[]}]}`), // empty versions
	}
	for i, in := range cases {
		if _, err := Parse(in); err == nil {
			t.Errorf("case %d: expected error on incomplete entry: %s", i, in)
		}
	}
}

func TestMatchExactNameAndVersion(t *testing.T) {
	c, err := Parse([]byte(`{"schema_version":"0.1.0","entries":[
		{"id":"npm-1","name":"left-pad CVE","ecosystem":"npm","package":"left-pad","versions":["1.3.0","1.3.1"],"severity":"high"},
		{"id":"pypi-1","ecosystem":"pypi","package":"Requests","versions":["2.31.0"]}
	]}`))
	if err != nil {
		t.Fatal(err)
	}

	// Hit
	r := model.Record{Ecosystem: "npm", NormalizedName: "left-pad", Version: "1.3.0"}
	e, v := c.Match(r)
	if e == nil || e.ID != "npm-1" {
		t.Fatalf("expected npm-1 hit, got %v", e)
	}
	if v != "1.3.0" {
		t.Errorf("matched version=%q", v)
	}
	if e.Severity != "high" {
		t.Errorf("severity=%q", e.Severity)
	}

	// PyPI normalization: catalog has "Requests" but match should hit normalized "requests"
	r = model.Record{Ecosystem: "pypi", NormalizedName: "requests", Version: "2.31.0"}
	if e, _ := c.Match(r); e == nil || e.ID != "pypi-1" {
		t.Fatalf("expected pypi-1 hit after normalization")
	}

	// Miss: wrong version
	r = model.Record{Ecosystem: "npm", NormalizedName: "left-pad", Version: "1.4.0"}
	if e, _ := c.Match(r); e != nil {
		t.Fatalf("expected miss for wrong version, got %v", e)
	}

	// Miss: wrong ecosystem
	r = model.Record{Ecosystem: "pypi", NormalizedName: "left-pad", Version: "1.3.0"}
	if e, _ := c.Match(r); e != nil {
		t.Fatalf("expected miss for wrong ecosystem")
	}
}

func TestLoadFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "catalog.json")
	body := []byte(`{"schema_version":"0.1.0","entries":[{"id":"x","ecosystem":"npm","package":"foo","versions":["1.0.0"]}]}`)
	if err := os.WriteFile(path, body, 0o644); err != nil {
		t.Fatal(err)
	}
	c, err := LoadFile(path, 0)
	if err != nil {
		t.Fatal(err)
	}
	if c.Len() != 1 {
		t.Fatalf("len=%d", c.Len())
	}
}

func TestLoadDispatchesFileVsDir(t *testing.T) {
	dir := t.TempDir()
	file := filepath.Join(dir, "single.json")
	if err := os.WriteFile(file, []byte(`{"schema_version":"0.1.0","entries":[{"id":"a","ecosystem":"npm","package":"left-pad","versions":["1.3.0"]}]}`), 0o644); err != nil {
		t.Fatal(err)
	}

	// file mode
	c, err := Load(file, 0)
	if err != nil {
		t.Fatalf("file load: %v", err)
	}
	if c.Len() != 1 {
		t.Fatalf("file len=%d", c.Len())
	}

	// directory mode — same file, picked up by walking the parent
	c, err = Load(dir, 0)
	if err != nil {
		t.Fatalf("dir load: %v", err)
	}
	if c.Len() != 1 {
		t.Fatalf("dir len=%d", c.Len())
	}
}

func TestLoadDirAggregatesAndSortsByName(t *testing.T) {
	dir := t.TempDir()
	// Write in non-alphabetical order to verify alphabetical merge order.
	cases := []struct {
		name, body string
	}{
		{"zeta.json", `{"schema_version":"0.1.0","entries":[{"id":"z","ecosystem":"npm","package":"zlib","versions":["1.0.0"]}]}`},
		{"alpha.json", `{"schema_version":"0.1.0","entries":[{"id":"a","ecosystem":"npm","package":"alpha","versions":["1.0.0"]}]}`},
		{"beta.json", `{"schema_version":"0.1.0","entries":[{"id":"b","ecosystem":"pypi","package":"beta","versions":["2.0.0"]}]}`},
	}
	for _, c := range cases {
		if err := os.WriteFile(filepath.Join(dir, c.name), []byte(c.body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	cat, err := Load(dir, 0)
	if err != nil {
		t.Fatalf("dir load: %v", err)
	}
	if cat.Len() != 3 {
		t.Fatalf("len=%d, want 3", cat.Len())
	}
	// Verify the alpha entry parses and matches.
	r := model.Record{Ecosystem: "npm", NormalizedName: "alpha", Version: "1.0.0"}
	if e, _ := cat.Match(r); e == nil || e.ID != "a" {
		t.Fatalf("expected alpha hit, got %v", e)
	}
}

func TestLoadDirSkipsNonJSONAndSubdirs(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "good.json"),
		[]byte(`{"schema_version":"0.1.0","entries":[{"id":"a","ecosystem":"npm","package":"x","versions":["1.0.0"]}]}`),
		0o644); err != nil {
		t.Fatal(err)
	}
	// Non-.json file — must be skipped.
	if err := os.WriteFile(filepath.Join(dir, "README.md"), []byte("# notes\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	// Subdirectory with another catalog inside — must NOT be loaded (non-recursive).
	subdir := filepath.Join(dir, "nested")
	if err := os.Mkdir(subdir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(subdir, "deep.json"),
		[]byte(`{"schema_version":"0.1.0","entries":[{"id":"deep","ecosystem":"npm","package":"deep","versions":["1.0.0"]}]}`),
		0o644); err != nil {
		t.Fatal(err)
	}
	cat, err := Load(dir, 0)
	if err != nil {
		t.Fatalf("dir load: %v", err)
	}
	if cat.Len() != 1 {
		t.Fatalf("len=%d, want 1 (only good.json)", cat.Len())
	}
}

// TestLoadDirSkipsSymlinkToDir verifies that a symlink whose name ends
// in `.json` but whose target is a directory is treated like a
// subdirectory and skipped, rather than handed to LoadFile (which would
// reject it as "not a regular file" and fail the entire load).
func TestLoadDirSkipsSymlinkToDir(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "good.json"),
		[]byte(`{"schema_version":"0.1.0","entries":[{"id":"a","ecosystem":"npm","package":"x","versions":["1.0.0"]}]}`),
		0o644); err != nil {
		t.Fatal(err)
	}
	targetDir := filepath.Join(dir, "nested-target")
	if err := os.Mkdir(targetDir, 0o755); err != nil {
		t.Fatal(err)
	}
	linkPath := filepath.Join(dir, "linked.json")
	if err := os.Symlink(targetDir, linkPath); err != nil {
		t.Skipf("symlink unsupported: %v", err)
	}
	cat, err := Load(dir, 0)
	if err != nil {
		t.Fatalf("dir load: %v", err)
	}
	if cat.Len() != 1 {
		t.Fatalf("len=%d, want 1 (symlink-to-dir must be skipped)", cat.Len())
	}
}

func TestLoadDirEmptyIsNoop(t *testing.T) {
	dir := t.TempDir()
	cat, err := Load(dir, 0)
	if err != nil {
		t.Fatalf("empty dir: %v", err)
	}
	if cat.Len() != 0 {
		t.Fatalf("expected empty catalog from empty dir")
	}
}

func TestLoadDirRejectsSchemaVersionConflict(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "a.json"),
		[]byte(`{"schema_version":"0.1.0","entries":[{"id":"a","ecosystem":"npm","package":"x","versions":["1.0.0"]}]}`),
		0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "b.json"),
		[]byte(`{"schema_version":"9.9.9","entries":[{"id":"b","ecosystem":"npm","package":"y","versions":["1.0.0"]}]}`),
		0o644); err != nil {
		t.Fatal(err)
	}
	// The 9.9.9 file is rejected by Parse before we even get to merge,
	// so the error here is "unsupported schema_version" rather than
	// "schema_version conflict" — still a reject, still correct.
	if _, err := Load(dir, 0); err == nil {
		t.Fatal("expected conflicting / unsupported schema_version to error")
	}
}

func TestLoadDirSurfacesPerFileError(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "good.json"),
		[]byte(`{"schema_version":"0.1.0","entries":[{"id":"a","ecosystem":"npm","package":"x","versions":["1.0.0"]}]}`),
		0o644); err != nil {
		t.Fatal(err)
	}
	// Bare array — rejected by Parse since PR #8.
	if err := os.WriteFile(filepath.Join(dir, "bad.json"),
		[]byte(`[{"id":"b","ecosystem":"npm","package":"y","versions":["1.0.0"]}]`),
		0o644); err != nil {
		t.Fatal(err)
	}
	_, err := Load(dir, 0)
	if err == nil {
		t.Fatal("expected dir load to surface per-file error")
	}
	if !strings.Contains(err.Error(), "bad.json") {
		t.Errorf("error should name the offending file, got %v", err)
	}
}

func TestLoadFileSizeLimit(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "catalog.json")
	body := []byte(`{"schema_version":"0.1.0","entries":[{"id":"x","ecosystem":"npm","package":"foo","versions":["1.0.0"]}]}`)
	if err := os.WriteFile(path, body, 0o644); err != nil {
		t.Fatal(err)
	}

	// maxSize=1 -> exceeds; should error before parse.
	if _, err := LoadFile(path, 1); err == nil {
		t.Fatal("expected error when catalog exceeds max size")
	}

	// maxSize comfortably above file size -> parses normally.
	c, err := LoadFile(path, int64(len(body))+1)
	if err != nil {
		t.Fatalf("expected success when under limit: %v", err)
	}
	if c.Len() != 1 {
		t.Fatalf("len=%d", c.Len())
	}

	// maxSize=0 -> unbounded.
	if _, err := LoadFile(path, 0); err != nil {
		t.Fatalf("expected unbounded read to succeed: %v", err)
	}
}

// TestMatchAllReturnsOverlappingEntries verifies that when two catalog
// files (e.g. two separate advisories) both cover the same
// (ecosystem, name, version), MatchAll returns both. The scanner relies
// on this to emit one finding per advisory rather than silently masking
// the second.
func TestMatchAllReturnsOverlappingEntries(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "adv-a.json"),
		[]byte(`{"schema_version":"0.1.0","entries":[{"id":"adv-a","ecosystem":"npm","package":"evil","versions":["1.2.3"],"severity":"critical"}]}`),
		0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "adv-b.json"),
		[]byte(`{"schema_version":"0.1.0","entries":[{"id":"adv-b","ecosystem":"npm","package":"evil","versions":["1.2.3"],"severity":"high"}]}`),
		0o644); err != nil {
		t.Fatal(err)
	}
	cat, err := Load(dir, 0)
	if err != nil {
		t.Fatalf("load: %v", err)
	}

	r := model.Record{Ecosystem: "npm", NormalizedName: "evil", Version: "1.2.3"}
	hits := cat.MatchAll(r)
	if len(hits) != 2 {
		t.Fatalf("MatchAll hits=%d, want 2", len(hits))
	}
	ids := map[string]bool{}
	for _, h := range hits {
		if h.Entry == nil {
			t.Fatalf("nil entry in MatchAll result")
		}
		if h.Version != "1.2.3" {
			t.Errorf("matched version=%q, want 1.2.3", h.Version)
		}
		ids[h.Entry.ID] = true
	}
	if !ids["adv-a"] || !ids["adv-b"] {
		t.Errorf("expected both adv-a and adv-b, got %v", ids)
	}

	// Match (the single-hit convenience wrapper) still returns the first
	// matching entry — load order is alphabetical, so adv-a wins.
	e, v := cat.Match(r)
	if e == nil || e.ID != "adv-a" || v != "1.2.3" {
		t.Errorf("Match returned %v, %q; want adv-a, 1.2.3", e, v)
	}
}

func TestParseCatalogSchemaVersion(t *testing.T) {
	for _, v := range supportedSchemaVersions {
		c, err := Parse([]byte(`{"schema_version":"` + v + `","entries":[{"id":"x","ecosystem":"npm","package":"foo","versions":["1.0.0"]}]}`))
		if err != nil {
			t.Fatalf("parse %s catalog: %v", v, err)
		}
		if c.SchemaVersion != v {
			t.Fatalf("schema_version=%q, want %q", c.SchemaVersion, v)
		}
	}
}

func TestParseCatalogRejectsUnsupportedSchemaVersion(t *testing.T) {
	if _, err := Parse([]byte(`{"schema_version":"9.9.9","entries":[]}`)); err == nil {
		t.Fatal("expected unsupported schema_version error")
	}
}

func TestMatchAnyVersion(t *testing.T) {
	c, err := Parse([]byte(`{"schema_version":"0.2.0","entries":[
		{"id":"mal-1","ecosystem":"npm","package":"evil","versions":["*"],"severity":"critical"}
	]}`))
	if err != nil {
		t.Fatal(err)
	}
	e, v := c.Match(model.Record{Ecosystem: "npm", NormalizedName: "evil", Version: "1.2.3"})
	if e == nil || e.ID != "mal-1" || !e.AnyVersion() {
		t.Fatalf("expected any-version hit, got %v", e)
	}
	if v != "1.2.3" {
		t.Errorf("matched version=%q, want record version", v)
	}

	// Records without a version (e.g. MCP servers) match too.
	if e, v := c.Match(model.Record{Ecosystem: "npm", NormalizedName: "evil"}); e == nil || v != "" {
		t.Fatalf("expected empty-version hit, got %v, %q", e, v)
	}

	if e, _ := c.Match(model.Record{Ecosystem: "npm", NormalizedName: "good", Version: "1.2.3"}); e != nil {
		t.Fatal("expected miss for other package")
	}
}

func TestParseRejectsAnyVersionMixedWithExact(t *testing.T) {
	if _, err := Parse([]byte(`{"schema_version":"0.2.0","entries":[{"id":"a","ecosystem":"npm","package":"x","versions":["*","1.0.0"]}]}`)); err == nil {
		t.Fatal(`expected error for "*" mixed with exact versions`)
	}
}

func TestParseRejectsAnyVersionInOldSchema(t *testing.T) {
	if _, err := Parse([]byte(`{"schema_version":"0.1.0","entries":[{"id":"a","ecosystem":"npm","package":"x","versions":["*"]}]}`)); err == nil {
		t.Fatal(`expected error for "*" under schema_version 0.1.0`)
	}
}

func TestAllowlistSuppressesMatch(t *testing.T) {
	c, err := Parse([]byte(`{"schema_version":"0.2.0","entries":[
		{"id":"mal-1","ecosystem":"npm","package":"true","versions":["0.0.3","0.0.4"]},
		{"id":"mal-2","ecosystem":"npm","package":"Evil","versions":["*"]}
	],"allowlist":[
		{"id":"allow-1","name":"false positive","ecosystem":"npm","package":"true","versions":["0.0.4"]},
		{"id":"allow-2","ecosystem":"npm","package":"evil","versions":["*"]},
		{"id":"allow-3","ecosystem":"npm","package":"harmless","versions":["*"]}
	]}`))
	if err != nil {
		t.Fatal(err)
	}
	if len(c.Allowlist) != 3 {
		t.Fatalf("allowlist len=%d, want 3", len(c.Allowlist))
	}
	// Exact-version allow-list item: only that version is suppressed.
	allowed := model.Record{Ecosystem: "npm", NormalizedName: "true", Version: "0.0.4"}
	if hits := c.MatchAll(allowed); len(hits) != 0 {
		t.Fatalf("expected allow-listed record to produce no match, got %+v", hits)
	}
	if e, _ := c.Match(allowed); e != nil {
		t.Fatalf("Match must honour the allow-list, got %v", e)
	}
	if sup := c.Allowlisted(allowed); len(sup) != 1 || sup[0].Entry.ID != "mal-1" {
		t.Fatalf("Allowlisted=%+v, want the suppressed mal-1 hit", sup)
	}
	if e, _ := c.Match(model.Record{Ecosystem: "npm", NormalizedName: "true", Version: "0.0.3"}); e == nil || e.ID != "mal-1" {
		t.Fatalf("sibling version must still match, got %v", e)
	}
	// Any-version allow-list item covers an any-version catalog entry.
	if hits := c.MatchAll(model.Record{Ecosystem: "npm", NormalizedName: "evil", Version: "9.9.9"}); len(hits) != 0 {
		t.Fatalf("expected any-version allow-list to suppress, got %+v", hits)
	}
	// Allow-listed but never a catalog hit: nothing to report as suppressed.
	if sup := c.Allowlisted(model.Record{Ecosystem: "npm", NormalizedName: "harmless", Version: "1.0.0"}); len(sup) != 0 {
		t.Fatalf("expected no suppression without a catalog hit, got %+v", sup)
	}
	// Allow-list is scoped by ecosystem like the catalog.
	if sup := c.Allowlisted(model.Record{Ecosystem: "pypi", NormalizedName: "true", Version: "0.0.4"}); len(sup) != 0 {
		t.Fatalf("expected no suppression for a different ecosystem, got %+v", sup)
	}
}

func TestAllowlistAppliesAcrossDirectory(t *testing.T) {
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "a-advisory.json"), []byte(`{"schema_version":"0.2.0","entries":[
		{"id":"mal-1","ecosystem":"npm","package":"true","versions":["0.0.4"]}
	]}`), 0o644)
	os.WriteFile(filepath.Join(dir, "z-allowlist.json"), []byte(`{"schema_version":"0.2.0","entries":[],"allowlist":[
		{"id":"allow-1","ecosystem":"npm","package":"true","versions":["0.0.4"]}
	]}`), 0o644)
	c, err := Load(dir, 0)
	if err != nil {
		t.Fatal(err)
	}
	if c.Len() != 1 || len(c.Allowlist) != 1 {
		t.Fatalf("len=%d allowlist=%d", c.Len(), len(c.Allowlist))
	}
	if e, _ := c.Match(model.Record{Ecosystem: "npm", NormalizedName: "true", Version: "0.0.4"}); e != nil {
		t.Fatalf("allow-list in another file must suppress, got %v", e)
	}
}

func TestParseRejectsAllowlistInOldSchema(t *testing.T) {
	if _, err := Parse([]byte(`{"schema_version":"0.1.0","entries":[],"allowlist":[{"id":"a","ecosystem":"npm","package":"x","versions":["1.0.0"]}]}`)); err == nil {
		t.Fatal("expected error for allowlist under schema_version 0.1.0")
	}
}

func TestParseValidatesAllowlistEntries(t *testing.T) {
	if _, err := Parse([]byte(`{"schema_version":"0.2.0","entries":[],"allowlist":[{"id":"a","ecosystem":"npm","package":"x","versions":[]}]}`)); err == nil {
		t.Fatal("expected error for allowlist entry without versions")
	}
	if _, err := Parse([]byte(`{"schema_version":"0.2.0","entries":[],"allowlist":[{"ecosystem":"npm","package":"x","versions":["1.0.0"]}]}`)); err == nil {
		t.Fatal("expected error for allowlist entry without id")
	}
}
