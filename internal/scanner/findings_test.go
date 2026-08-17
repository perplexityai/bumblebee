package scanner

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/perplexityai/bumblebee/internal/exposure"
	"github.com/perplexityai/bumblebee/internal/model"
	"github.com/perplexityai/bumblebee/internal/output"
)

// TestFindingEmittedOnCatalogMatch verifies that an exposure catalog
// entry whose (ecosystem, name, version) matches a discovered package
// produces a record_type=finding record alongside the package record.
func TestFindingEmittedOnCatalogMatch(t *testing.T) {
	root := t.TempDir()
	// One npm lockfile with a "compromised" version that the catalog targets.
	writeFile(t, filepath.Join(root, "proj", "package-lock.json"), `{
  "lockfileVersion": 3,
  "packages": {
    "node_modules/evil": {"version":"1.2.3"},
    "node_modules/safe": {"version":"9.9.9"}
  }
}`)

	cat, err := exposure.Parse([]byte(`{"schema_version":"0.1.0","entries":[
		{"id":"adv-evil","name":"evil@1.2.3 backdoor","ecosystem":"npm","package":"evil","versions":["1.2.3"],"severity":"critical"}
	]}`))
	if err != nil {
		t.Fatal(err)
	}

	stdout := &bytes.Buffer{}
	stderr := &bytes.Buffer{}
	em := output.New(stdout, stderr, "run-find")
	res, err := Run(context.Background(), Config{
		Profile:     model.ProfileDeep,
		Roots:       []Root{{Path: root, Kind: model.RootKindDeepHome}},
		MaxFileSize: 1 << 20,
		Concurrency: 2,
		Catalog:     cat,
		BaseRecord: model.Record{
			SchemaVersion:  model.SchemaVersion,
			ScannerName:    model.ScannerName,
			ScannerVersion: "test",
			RunID:          "run-find",
			ScanTime:       time.Now().UTC().Format(time.RFC3339Nano),
		},
		Emitter: em,
	})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}

	if res.FindingsEmitted != 1 {
		t.Fatalf("findings=%d, want 1", res.FindingsEmitted)
	}

	var findings []model.Finding
	var pkgs int
	for _, line := range bytes.Split(bytes.TrimSpace(stdout.Bytes()), []byte("\n")) {
		if len(line) == 0 {
			continue
		}
		var probe map[string]any
		if err := json.Unmarshal(line, &probe); err != nil {
			t.Fatalf("bad ndjson: %v: %s", err, line)
		}
		switch probe["record_type"] {
		case model.RecordTypeFinding:
			var f model.Finding
			if err := json.Unmarshal(line, &f); err != nil {
				t.Fatalf("decode finding: %v", err)
			}
			findings = append(findings, f)
		case model.RecordTypePackage:
			pkgs++
		}
	}
	if len(findings) != 1 {
		t.Fatalf("findings on the wire = %d, want 1", len(findings))
	}
	f := findings[0]
	if f.RecordID == "" {
		t.Fatalf("finding missing record_id: %+v", f)
	}
	if f.CatalogID != "adv-evil" {
		t.Errorf("catalog_id=%q", f.CatalogID)
	}
	if f.NormalizedName != "evil" || f.Version != "1.2.3" {
		t.Errorf("matched fields wrong: %+v", f)
	}
	if f.Severity != "critical" {
		t.Errorf("severity=%q", f.Severity)
	}
	if f.FindingType != model.FindingTypePackageExposure {
		t.Errorf("finding_type=%q", f.FindingType)
	}
	if f.Profile != model.ProfileDeep {
		t.Errorf("profile=%q", f.Profile)
	}
	if !strings.Contains(f.Evidence, "exact name+version") {
		t.Errorf("evidence=%q", f.Evidence)
	}
	if pkgs < 2 {
		t.Errorf("expected at least 2 package records, got %d", pkgs)
	}
}

func TestFindingsOnlySuppressesPackagesButKeepsFindings(t *testing.T) {
	root := t.TempDir()
	writeFile(t, filepath.Join(root, "proj", "package-lock.json"), `{
  "lockfileVersion": 3,
  "packages": {
    "node_modules/evil": {"version":"1.2.3"},
    "node_modules/safe": {"version":"9.9.9"}
  }
}`)

	cat, err := exposure.Parse([]byte(`{
  "schema_version":"0.1.0",
  "entries":[
    {"id":"adv-evil","ecosystem":"npm","package":"evil","versions":["1.2.3"]}
  ]
}`))
	if err != nil {
		t.Fatal(err)
	}

	stdout := &bytes.Buffer{}
	stderr := &bytes.Buffer{}
	em := output.New(stdout, stderr, "run-find")
	res, err := Run(context.Background(), Config{
		Profile:      model.ProfileDeep,
		Roots:        []Root{{Path: root, Kind: model.RootKindDeepHome}},
		MaxFileSize:  1 << 20,
		Concurrency:  2,
		Catalog:      cat,
		FindingsOnly: true,
		BaseRecord: model.Record{
			SchemaVersion:  model.SchemaVersion,
			ScannerName:    model.ScannerName,
			ScannerVersion: "test",
			RunID:          "run-find",
			ScanTime:       time.Now().UTC().Format(time.RFC3339Nano),
		},
		Emitter: em,
	})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if res.RecordsEmitted != 0 {
		t.Fatalf("package records emitted = %d, want 0", res.RecordsEmitted)
	}
	if res.PackageRecordsSuppressed == 0 {
		t.Fatalf("expected suppressed package count, got %+v", res)
	}
	if res.FindingsEmitted != 1 {
		t.Fatalf("findings=%d, want 1", res.FindingsEmitted)
	}
	if bytes.Contains(stdout.Bytes(), []byte(`"record_type":"package"`)) {
		t.Fatalf("package record leaked under findings-only: %s", stdout.String())
	}
	if !bytes.Contains(stdout.Bytes(), []byte(`"record_type":"finding"`)) {
		t.Fatalf("finding missing under findings-only: %s", stdout.String())
	}
}

// TestFindingEmittedPerCatalogEntryWhenOverlapping verifies that when a
// directory catalog merges two files that both cover the same
// (ecosystem, name, version), the scanner emits one finding per matching
// entry rather than silently masking the second advisory. Each finding
// carries a distinct catalog_id and a distinct record_id.
func TestFindingEmittedPerCatalogEntryWhenOverlapping(t *testing.T) {
	root := t.TempDir()
	writeFile(t, filepath.Join(root, "proj", "package-lock.json"), `{
  "lockfileVersion": 3,
  "packages": {
    "node_modules/evil": {"version":"1.2.3"}
  }
}`)

	catDir := t.TempDir()
	if err := os.WriteFile(filepath.Join(catDir, "adv-a.json"),
		[]byte(`{"schema_version":"0.1.0","entries":[{"id":"adv-a","name":"campaign A","ecosystem":"npm","package":"evil","versions":["1.2.3"],"severity":"critical"}]}`),
		0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(catDir, "adv-b.json"),
		[]byte(`{"schema_version":"0.1.0","entries":[{"id":"adv-b","name":"campaign B","ecosystem":"npm","package":"evil","versions":["1.2.3"],"severity":"high"}]}`),
		0o644); err != nil {
		t.Fatal(err)
	}
	cat, err := exposure.Load(catDir, 0)
	if err != nil {
		t.Fatalf("load catalog dir: %v", err)
	}

	stdout := &bytes.Buffer{}
	stderr := &bytes.Buffer{}
	em := output.New(stdout, stderr, "run-overlap")
	res, err := Run(context.Background(), Config{
		Profile:     model.ProfileDeep,
		Roots:       []Root{{Path: root, Kind: model.RootKindDeepHome}},
		MaxFileSize: 1 << 20,
		Concurrency: 2,
		Catalog:     cat,
		BaseRecord: model.Record{
			SchemaVersion:  model.SchemaVersion,
			ScannerName:    model.ScannerName,
			ScannerVersion: "test",
			RunID:          "run-overlap",
			ScanTime:       time.Now().UTC().Format(time.RFC3339Nano),
		},
		Emitter: em,
	})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if res.FindingsEmitted != 2 {
		t.Fatalf("findings=%d, want 2 (one per overlapping catalog entry)", res.FindingsEmitted)
	}

	var findings []model.Finding
	for _, line := range bytes.Split(bytes.TrimSpace(stdout.Bytes()), []byte("\n")) {
		if len(line) == 0 {
			continue
		}
		var probe map[string]any
		if err := json.Unmarshal(line, &probe); err != nil {
			t.Fatalf("bad ndjson: %v: %s", err, line)
		}
		if probe["record_type"] == model.RecordTypeFinding {
			var f model.Finding
			if err := json.Unmarshal(line, &f); err != nil {
				t.Fatalf("decode finding: %v", err)
			}
			findings = append(findings, f)
		}
	}
	if len(findings) != 2 {
		t.Fatalf("findings on the wire = %d, want 2", len(findings))
	}
	ids := map[string]model.Finding{}
	for _, f := range findings {
		if f.RecordID == "" {
			t.Errorf("finding missing record_id: %+v", f)
		}
		if _, dup := ids[f.RecordID]; dup {
			t.Errorf("two findings share record_id %q — catalog_id must distinguish them", f.RecordID)
		}
		ids[f.RecordID] = f
	}
	gotCatalogIDs := map[string]bool{}
	for _, f := range findings {
		gotCatalogIDs[f.CatalogID] = true
	}
	if !gotCatalogIDs["adv-a"] || !gotCatalogIDs["adv-b"] {
		t.Errorf("expected findings for both adv-a and adv-b, got %v", gotCatalogIDs)
	}
}

// TestFindingEvidenceForAnyVersionEntry verifies a versions ["*"] entry
// matches whatever version is installed and says so in the evidence.
func TestFindingEvidenceForAnyVersionEntry(t *testing.T) {
	root := t.TempDir()
	writeFile(t, filepath.Join(root, "proj", "package-lock.json"),
		`{"lockfileVersion":3,"packages":{"node_modules/evil":{"version":"4.5.6"}}}`)

	cat, err := exposure.Parse([]byte(`{"schema_version":"0.2.0","entries":[
		{"id":"adv-any","ecosystem":"npm","package":"evil","versions":["*"],"severity":"critical"}
	]}`))
	if err != nil {
		t.Fatal(err)
	}

	stdout := &bytes.Buffer{}
	em := output.New(stdout, &bytes.Buffer{}, "run-any")
	res, err := Run(context.Background(), Config{
		Profile:     model.ProfileDeep,
		Roots:       []Root{{Path: root, Kind: model.RootKindDeepHome}},
		MaxFileSize: 1 << 20,
		Concurrency: 1,
		Catalog:     cat,
		BaseRecord: model.Record{
			SchemaVersion:  model.SchemaVersion,
			ScannerName:    model.ScannerName,
			ScannerVersion: "test",
			RunID:          "run-any",
			ScanTime:       time.Now().UTC().Format(time.RFC3339Nano),
		},
		Emitter: em,
	})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if res.FindingsEmitted != 1 {
		t.Fatalf("findings=%d, want 1", res.FindingsEmitted)
	}
	var f model.Finding
	for _, line := range bytes.Split(bytes.TrimSpace(stdout.Bytes()), []byte("\n")) {
		var probe map[string]any
		if err := json.Unmarshal(line, &probe); err != nil {
			t.Fatalf("bad ndjson: %v: %s", err, line)
		}
		if probe["record_type"] == model.RecordTypeFinding {
			if err := json.Unmarshal(line, &f); err != nil {
				t.Fatalf("decode finding: %v", err)
			}
		}
	}
	if f.CatalogID != "adv-any" || f.Version != "4.5.6" {
		t.Fatalf("matched fields wrong: %+v", f)
	}
	if !strings.Contains(f.Evidence, "matches any version (version=4.5.6)") {
		t.Errorf("evidence=%q", f.Evidence)
	}
}

// TestNoFindingWithoutCatalog verifies that with no catalog wired up,
// the scanner emits no finding records at all.
func TestNoFindingWithoutCatalog(t *testing.T) {
	root := t.TempDir()
	writeFile(t, filepath.Join(root, "proj", "package-lock.json"),
		`{"lockfileVersion":3,"packages":{"node_modules/evil":{"version":"1.2.3"}}}`)
	stdout := &bytes.Buffer{}
	em := output.New(stdout, &bytes.Buffer{}, "r")
	res, err := Run(context.Background(), Config{
		Profile:     model.ProfileProject,
		Roots:       []Root{{Path: root, Kind: model.RootKindProject}},
		MaxFileSize: 1 << 20,
		Concurrency: 1,
		Emitter:     em,
	})
	if err != nil {
		t.Fatal(err)
	}
	if res.FindingsEmitted != 0 {
		t.Errorf("findings=%d without catalog, want 0", res.FindingsEmitted)
	}
	if bytes.Contains(stdout.Bytes(), []byte(`"record_type":"finding"`)) {
		t.Errorf("finding record on the wire without a catalog: %s", stdout.String())
	}
}

// TestRootKindStampedOnRecords verifies that records emitted from a
// configured root carry that root's kind.
func TestRootKindStampedOnRecords(t *testing.T) {
	root := t.TempDir()
	writeFile(t, filepath.Join(root, "proj", "package-lock.json"),
		`{"lockfileVersion":3,"packages":{"node_modules/foo":{"version":"1.0.0"}}}`)
	stdout := &bytes.Buffer{}
	em := output.New(stdout, &bytes.Buffer{}, "r")
	_, err := Run(context.Background(), Config{
		Profile:     model.ProfileBaseline,
		Roots:       []Root{{Path: root, Kind: model.RootKindUserPackage}},
		MaxFileSize: 1 << 20,
		Concurrency: 1,
		Emitter:     em,
	})
	if err != nil {
		t.Fatal(err)
	}
	saw := false
	for _, line := range bytes.Split(bytes.TrimSpace(stdout.Bytes()), []byte("\n")) {
		if len(line) == 0 {
			continue
		}
		var r model.Record
		if err := json.Unmarshal(line, &r); err != nil {
			t.Fatalf("decode: %v", err)
		}
		if r.RootKind != model.RootKindUserPackage {
			t.Errorf("root_kind=%q, want %q", r.RootKind, model.RootKindUserPackage)
		}
		if r.Profile != model.ProfileBaseline {
			t.Errorf("profile=%q, want %q", r.Profile, model.ProfileBaseline)
		}
		if r.RecordID == "" {
			t.Errorf("record_id missing on package record: %+v", r)
		}
		saw = true
	}
	if !saw {
		t.Fatal("expected at least one record")
	}
}

// TestAllowlistedHitEmitsNoFinding verifies that a catalog hit covered by
// the catalog allow-list produces no finding record, is counted in
// Result.FindingsSuppressed, and does not affect other hits.
func TestAllowlistedHitEmitsNoFinding(t *testing.T) {
	root := t.TempDir()
	writeFile(t, filepath.Join(root, "proj", "package-lock.json"), `{
  "lockfileVersion": 3,
  "packages": {
    "node_modules/true": {"version":"0.0.4"},
    "node_modules/evil": {"version":"1.2.3"}
  }
}`)

	cat, err := exposure.Parse([]byte(`{"schema_version":"0.2.0","entries":[
		{"id":"adv-true","ecosystem":"npm","package":"true","versions":["0.0.4"],"severity":"critical"},
		{"id":"adv-evil","ecosystem":"npm","package":"evil","versions":["1.2.3"],"severity":"critical"}
	],"allowlist":[
		{"id":"allow-true","name":"false positive","ecosystem":"npm","package":"true","versions":["0.0.4"]}
	]}`))
	if err != nil {
		t.Fatal(err)
	}

	stdout := &bytes.Buffer{}
	em := output.New(stdout, &bytes.Buffer{}, "run-allow")
	res, err := Run(context.Background(), Config{
		Profile:      model.ProfileDeep,
		Roots:        []Root{{Path: root, Kind: model.RootKindDeepHome}},
		MaxFileSize:  1 << 20,
		Concurrency:  2,
		Catalog:      cat,
		FindingsOnly: true,
		BaseRecord: model.Record{
			SchemaVersion:  model.SchemaVersion,
			ScannerName:    model.ScannerName,
			ScannerVersion: "test",
			RunID:          "run-allow",
			ScanTime:       time.Now().UTC().Format(time.RFC3339Nano),
		},
		Emitter: em,
	})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if res.FindingsEmitted != 1 {
		t.Fatalf("findings=%d, want 1 (evil only)", res.FindingsEmitted)
	}
	if res.FindingsSuppressed != 1 {
		t.Fatalf("findings_suppressed=%d, want 1", res.FindingsSuppressed)
	}
	out := stdout.String()
	if !strings.Contains(out, `"catalog_id":"adv-evil"`) {
		t.Fatalf("expected finding for evil on the wire:\n%s", out)
	}
	if strings.Contains(out, `"catalog_id":"adv-true"`) || strings.Contains(out, `"package_name":"true"`) {
		t.Fatalf("allow-listed hit leaked onto the wire:\n%s", out)
	}
}
