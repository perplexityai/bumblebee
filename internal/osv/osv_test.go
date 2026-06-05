package osv

import (
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/perplexityai/bumblebee/internal/exposure"
	"github.com/perplexityai/bumblebee/internal/model"
)

func TestConvertMaliciousOnlyByDefault(t *testing.T) {
	records := []Record{
		{
			ID:       "MAL-2024-1",
			Summary:  "Malicious code in evil-pkg (npm)",
			Affected: []Affected{{Package: Package{Ecosystem: "npm", Name: "evil-pkg"}, Versions: []string{"1.0.0", "1.0.1"}}},
		},
		{
			ID:       "GHSA-xxxx-yyyy-zzzz",
			Summary:  "Regular vuln in left-pad",
			Affected: []Affected{{Package: Package{Ecosystem: "npm", Name: "left-pad"}, Versions: []string{"0.0.1"}}},
		},
	}
	entries, st := Convert(records, Options{})
	if len(entries) != 1 {
		t.Fatalf("want 1 entry (malicious only), got %d: %+v", len(entries), entries)
	}
	e := entries[0]
	if e.ID != "MAL-2024-1" || e.Ecosystem != "npm" || e.Package != "evil-pkg" {
		t.Errorf("unexpected entry: %+v", e)
	}
	if e.Source != "https://osv.dev/vulnerability/MAL-2024-1" {
		t.Errorf("source = %q", e.Source)
	}
	if !reflect.DeepEqual(e.Versions, []string{"1.0.0", "1.0.1"}) {
		t.Errorf("versions = %v", e.Versions)
	}
	if st.SkippedNotMalicious != 1 {
		t.Errorf("SkippedNotMalicious = %d, want 1", st.SkippedNotMalicious)
	}
}

func TestMapEcosystem(t *testing.T) {
	supported := map[string]string{
		"npm":          "npm",
		"PyPI":         "pypi",
		"Go":           "go",
		"RubyGems":     "rubygems",
		"Packagist":    "packagist",
		"VSCode":       "editor-extension",
		"Go:something": "go", // suffix after ':' is ignored
	}
	for osvEco, want := range supported {
		got, ok := mapEcosystem(osvEco)
		if !ok || got != want {
			t.Errorf("mapEcosystem(%q) = (%q, %v), want (%q, true)", osvEco, got, ok, want)
		}
	}
	// OSV identifiers are case-sensitive and several ecosystems have no
	// Bumblebee equivalent; none of these must map.
	for _, osvEco := range []string{"pypi", "NPM", "crates.io", "NuGet", "Maven", "vscode", "Debian:11", ""} {
		if got, ok := mapEcosystem(osvEco); ok {
			t.Errorf("mapEcosystem(%q) = (%q, true), want no mapping", osvEco, got)
		}
	}
}

// TestConvertDropsNonMaliciousVuln confirms CVE-style advisories are
// never emitted: the catalog format targets supply-chain compromise
// response, not vulnerability tracking.
func TestConvertDropsNonMaliciousVuln(t *testing.T) {
	records := []Record{
		{ID: "GHSA-aaaa", Affected: []Affected{{Package: Package{Ecosystem: "PyPI", Name: "Requests"}, Versions: []string{"2.0.0"}}}},
	}
	entries, st := Convert(records, Options{})
	if len(entries) != 0 {
		t.Fatalf("want 0 entries, got %d: %+v", len(entries), entries)
	}
	if st.SkippedNotMalicious != 1 {
		t.Errorf("SkippedNotMalicious = %d, want 1", st.SkippedNotMalicious)
	}
}

func TestConvertSkipsWithdrawnUnsupportedAndRangeOnly(t *testing.T) {
	records := []Record{
		{ID: "MAL-withdrawn", Withdrawn: "2026-01-01T00:00:00Z", Affected: []Affected{{Package: Package{Ecosystem: "npm", Name: "x"}, Versions: []string{"1.0.0"}}}},
		{ID: "MAL-cargo", Affected: []Affected{{Package: Package{Ecosystem: "crates.io", Name: "y"}, Versions: []string{"1.0.0"}}}},
		{ID: "MAL-rangeonly", Affected: []Affected{{Package: Package{Ecosystem: "npm", Name: "z"}}}},
		// Empty package name must be dropped: an entry with an empty
		// package would make exposure.Load reject the whole catalog.
		{ID: "MAL-noname", Affected: []Affected{{Package: Package{Ecosystem: "npm", Name: ""}, Versions: []string{"1.0.0"}}}},
	}
	entries, st := Convert(records, Options{})
	if len(entries) != 0 {
		t.Fatalf("want 0 entries, got %d: %+v", len(entries), entries)
	}
	if st.SkippedWithdrawn != 1 {
		t.Errorf("SkippedWithdrawn = %d, want 1", st.SkippedWithdrawn)
	}
	if st.SkippedEcosystem != 1 {
		t.Errorf("SkippedEcosystem = %d, want 1", st.SkippedEcosystem)
	}
	if st.SkippedNoVersions != 1 {
		t.Errorf("SkippedNoVersions = %d, want 1", st.SkippedNoVersions)
	}
}

func TestConvertMultiPackageUniqueIDsAndAliasMalicious(t *testing.T) {
	records := []Record{
		{
			// Surfaced under a GHSA id but aliased to a MAL- id: still malicious.
			ID:      "GHSA-multi",
			Aliases: []string{"MAL-2024-99"},
			Summary: "campaign",
			Affected: []Affected{
				{Package: Package{Ecosystem: "npm", Name: "pkg-b"}, Versions: []string{"2.0.0"}},
				{Package: Package{Ecosystem: "PyPI", Name: "pkg-a"}, Versions: []string{"1.0.0"}},
			},
		},
	}
	entries, _ := Convert(records, Options{})
	if len(entries) != 2 {
		t.Fatalf("want 2 entries, got %d", len(entries))
	}
	// Sorted by ecosystem then package: npm/pkg-b, pypi/pkg-a.
	if entries[0].Ecosystem != "npm" || entries[0].Package != "pkg-b" {
		t.Errorf("entry[0] = %+v", entries[0])
	}
	if entries[1].Ecosystem != "pypi" || entries[1].Package != "pkg-a" {
		t.Errorf("entry[1] = %+v", entries[1])
	}
	if entries[0].ID == entries[1].ID {
		t.Errorf("multi-package entries must have unique ids: %q == %q", entries[0].ID, entries[1].ID)
	}
	// Both entries were emitted under the malicious-only default, which
	// only happens if the MAL- alias was recognized as malicious.
}

func TestConvertEcosystemFilterAndVersionDedupe(t *testing.T) {
	records := []Record{
		{ID: "MAL-1", Affected: []Affected{{Package: Package{Ecosystem: "npm", Name: "a"}, Versions: []string{"1.0.0"}}}},
		{ID: "MAL-2", Affected: []Affected{{Package: Package{Ecosystem: "Go", Name: "b"}, Versions: []string{"1.0.0"}}}},
		{ID: "MAL-3", Affected: []Affected{
			{Package: Package{Ecosystem: "npm", Name: "c"}, Versions: []string{"2.0.0", "1.0.0"}},
			{Package: Package{Ecosystem: "npm", Name: "c"}, Versions: []string{"1.0.0"}}, // duplicate version across ranges
		}},
	}
	entries, _ := Convert(records, Options{Ecosystems: map[string]bool{"npm": true}})
	if len(entries) != 2 {
		t.Fatalf("want 2 npm entries, got %d: %+v", len(entries), entries)
	}
	// Find pkg "c": versions deduped and sorted.
	var c CatalogEntry
	for _, e := range entries {
		if e.Package == "c" {
			c = e
		}
	}
	if !reflect.DeepEqual(c.Versions, []string{"1.0.0", "2.0.0"}) {
		t.Errorf("pkg c versions = %v, want deduped+sorted [1.0.0 2.0.0]", c.Versions)
	}
}

// TestRoundTripLoadsAndMatches is the end-to-end contract: a catalog
// generated by this package must validate as a Bumblebee exposure catalog
// and actually match a discovered package record.
func TestRoundTripLoadsAndMatches(t *testing.T) {
	records := []Record{
		{ID: "MAL-2024-1", Summary: "Malicious code in evil-pkg", Affected: []Affected{{Package: Package{Ecosystem: "npm", Name: "evil-pkg"}, Versions: []string{"6.6.6"}}}},
	}
	entries, st := Convert(records, Options{})
	catalog := BuildCatalog(entries, Options{}, st)
	if catalog.SchemaVersion != model.SchemaVersion {
		t.Fatalf("schema_version = %q", catalog.SchemaVersion)
	}

	data, err := json.MarshalIndent(catalog, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "osv.json")
	if err := os.WriteFile(path, data, 0o644); err != nil {
		t.Fatal(err)
	}

	cat, err := exposure.LoadFile(path, 1<<20)
	if err != nil {
		t.Fatalf("exposure.LoadFile rejected generated catalog: %v", err)
	}
	hit, ver := cat.Match(model.Record{Ecosystem: "npm", NormalizedName: "evil-pkg", Version: "6.6.6"})
	if hit == nil || ver != "6.6.6" {
		t.Fatalf("generated catalog did not match the planted record (hit=%v ver=%q)", hit, ver)
	}
	if hit.ID != "MAL-2024-1" {
		t.Errorf("matched entry id = %q, want MAL-2024-1", hit.ID)
	}
}

func TestBuildCatalogCommentDeterministic(t *testing.T) {
	records := []Record{
		{ID: "MAL-1", Affected: []Affected{{Package: Package{Ecosystem: "npm", Name: "a"}, Versions: []string{"1.0.0"}}}},
		// Non-malicious + unsupported eco + withdrawn + bad id so all
		// skip counters are exercised in the comment.
		{ID: "GHSA-vuln", Affected: []Affected{{Package: Package{Ecosystem: "npm", Name: "b"}, Versions: []string{"1.0.0"}}}},
		{ID: "MAL-crates", Affected: []Affected{{Package: Package{Ecosystem: "crates.io", Name: "c"}, Versions: []string{"1.0.0"}}}},
		{ID: "MAL-withdrawn", Withdrawn: "2026-01-01T00:00:00Z", Affected: []Affected{{Package: Package{Ecosystem: "npm", Name: "d"}, Versions: []string{"1.0.0"}}}},
		{ID: "", Affected: []Affected{{Package: Package{Ecosystem: "npm", Name: "e"}, Versions: []string{"1.0.0"}}}}, // bad-id (empty)
	}
	entries, st := Convert(records, Options{})
	c1 := BuildCatalog(entries, Options{}, st)
	c2 := BuildCatalog(entries, Options{}, st)
	if c1.Comment != c2.Comment {
		t.Fatalf("comment not deterministic:\n%q\n%q", c1.Comment, c2.Comment)
	}
	if c1.Comment == "" {
		t.Fatal("expected a provenance comment")
	}
	// Skip-reason breakdown must surface every non-zero bucket, in the
	// fixed documented order.
	for _, sub := range []string{
		"1 non-malicious",
		"1 unsupported-ecosystem",
		"1 withdrawn",
		"1 bad-id",
	} {
		if !strings.Contains(c1.Comment, sub) {
			t.Errorf("comment missing %q:\n%s", sub, c1.Comment)
		}
	}
	// And the optional source label must appear only when set.
	cWithSrc := BuildCatalog(entries, Options{Source: "https://example/repo@abc"}, st)
	if !strings.Contains(cWithSrc.Comment, "Source: https://example/repo@abc") {
		t.Errorf("comment missing source stamp:\n%s", cWithSrc.Comment)
	}
	if strings.Contains(c1.Comment, "Source: ") {
		t.Errorf("comment should not stamp source when unset:\n%s", c1.Comment)
	}
}

// TestSeverityCritical verifies generated entries carry severity="critical",
// matching hand-curated malicious-package catalogs in threat_intel/.
func TestSeverityCritical(t *testing.T) {
	recs := []Record{{ID: "MAL-sev", Affected: []Affected{{Package: Package{Ecosystem: "npm", Name: "x"}, Versions: []string{"1.0.0"}}}}}
	entries, _ := Convert(recs, Options{})
	if len(entries) != 1 || entries[0].Severity != "critical" {
		t.Fatalf("severity = critical, got entries: %+v", entries)
	}
}

// TestVSCodeMapsToEditorExtension confirms VSCode advisories (17 in the
// current OSSF corpus) now produce editor-extension entries instead of
// being silently skipped.
func TestVSCodeMapsToEditorExtension(t *testing.T) {
	recs := []Record{{ID: "MAL-vsce", Affected: []Affected{{Package: Package{Ecosystem: "VSCode", Name: "publisher.ext"}, Versions: []string{"1.0.0"}}}}}
	entries, st := Convert(recs, Options{})
	if len(entries) != 1 {
		t.Fatalf("want 1 entry, got %d (skipped-eco=%d)", len(entries), st.SkippedEcosystem)
	}
	if entries[0].Ecosystem != "editor-extension" || entries[0].Package != "publisher.ext" {
		t.Errorf("unexpected entry: %+v", entries[0])
	}
}

// TestSkipBadIDShape ensures ids that could smuggle URL syntax into the
// generated source are rejected before reaching the catalog.
func TestSkipBadIDShape(t *testing.T) {
	recs := []Record{
		{ID: "MAL-good-1", Affected: []Affected{{Package: Package{Ecosystem: "npm", Name: "ok"}, Versions: []string{"1.0.0"}}}},
		{ID: "MAL-bad id with spaces", Affected: []Affected{{Package: Package{Ecosystem: "npm", Name: "x"}, Versions: []string{"1.0.0"}}}},
		{ID: "MAL-bad?q=1", Affected: []Affected{{Package: Package{Ecosystem: "npm", Name: "y"}, Versions: []string{"1.0.0"}}}},
		{ID: "MAL-bad#frag", Affected: []Affected{{Package: Package{Ecosystem: "npm", Name: "z"}, Versions: []string{"1.0.0"}}}},
	}
	entries, st := Convert(recs, Options{})
	if len(entries) != 1 || entries[0].ID != "MAL-good-1" {
		t.Fatalf("want only MAL-good-1, got %+v", entries)
	}
	if st.SkippedBadID != 3 {
		t.Errorf("SkippedBadID = %d, want 3", st.SkippedBadID)
	}
}
