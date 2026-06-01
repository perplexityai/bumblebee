package main

import (
	"archive/zip"
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// writeZip creates a zip at path containing name->body entries.
func writeZip(t *testing.T, path string, files map[string]string) {
	t.Helper()
	f, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	zw := zip.NewWriter(f)
	for name, body := range files {
		w, err := zw.Create(name)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := w.Write([]byte(body)); err != nil {
			t.Fatal(err)
		}
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestRunFromZip(t *testing.T) {
	dir := t.TempDir()
	zipPath := filepath.Join(dir, "all.zip")
	writeZip(t, zipPath, map[string]string{
		"MAL-2024-1.json":  `{"id":"MAL-2024-1","summary":"bad","affected":[{"package":{"ecosystem":"npm","name":"evil"},"versions":["1.0.0"]}]}`,
		"GHSA-normal.json": `{"id":"GHSA-normal","affected":[{"package":{"ecosystem":"npm","name":"left-pad"},"versions":["0.0.1"]}]}`,
		"not-osv.json":     `{"hello":"world"}`,
	})
	outPath := filepath.Join(dir, "catalog.json")

	var stdout, stderr bytes.Buffer
	if err := run([]string{"-o", outPath, zipPath}, &stdout, &stderr); err != nil {
		t.Fatalf("run: %v (stderr=%s)", err, stderr.String())
	}

	data, err := os.ReadFile(outPath)
	if err != nil {
		t.Fatal(err)
	}
	var cat struct {
		SchemaVersion string `json:"schema_version"`
		Comment       string `json:"_comment"`
		Entries       []struct {
			ID        string   `json:"id"`
			Ecosystem string   `json:"ecosystem"`
			Package   string   `json:"package"`
			Versions  []string `json:"versions"`
		} `json:"entries"`
	}
	if err := json.Unmarshal(data, &cat); err != nil {
		t.Fatalf("output is not valid JSON: %v", err)
	}
	if cat.SchemaVersion != "0.1.0" {
		t.Errorf("schema_version = %q", cat.SchemaVersion)
	}
	// Malicious-only by default: only MAL-2024-1, not the GHSA vuln.
	if len(cat.Entries) != 1 {
		t.Fatalf("want 1 entry (malicious only), got %d", len(cat.Entries))
	}
	e := cat.Entries[0]
	if e.ID != "MAL-2024-1" || e.Package != "evil" {
		t.Errorf("unexpected entry: %+v", e)
	}
}

func TestRunEcosystemFilter(t *testing.T) {
	dir := t.TempDir()
	zipPath := filepath.Join(dir, "all.zip")
	writeZip(t, zipPath, map[string]string{
		"MAL-npm.json": `{"id":"MAL-npm","affected":[{"package":{"ecosystem":"npm","name":"a"},"versions":["1.0.0"]}]}`,
		"MAL-py.json":  `{"id":"MAL-py","affected":[{"package":{"ecosystem":"PyPI","name":"b"},"versions":["2.0.0"]}]}`,
	})

	var stdout, stderr bytes.Buffer
	if err := run([]string{"-ecosystem", "pypi", zipPath}, &stdout, &stderr); err != nil {
		t.Fatalf("run: %v", err)
	}
	var cat struct {
		Entries []struct {
			Ecosystem string `json:"ecosystem"`
			Package   string `json:"package"`
		} `json:"entries"`
	}
	if err := json.Unmarshal(stdout.Bytes(), &cat); err != nil {
		t.Fatal(err)
	}
	if len(cat.Entries) != 1 || cat.Entries[0].Ecosystem != "pypi" || cat.Entries[0].Package != "b" {
		t.Fatalf("ecosystem filter failed: %+v", cat.Entries)
	}
}

func TestRunRequiresInput(t *testing.T) {
	var stdout, stderr bytes.Buffer
	if err := run(nil, &stdout, &stderr); err == nil {
		t.Fatal("expected error when no input paths given")
	}
}

// TestMaxFileSizeZeroIsUnbounded confirms -max-file-size 0 means
// "unbounded" (matching internal/exposure.LoadFile semantics), not
// "reject everything". Without this, every record would silently be
// dropped as "not a valid OSV record" after a 1-byte truncated read.
func TestMaxFileSizeZeroIsUnbounded(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "MAL-1.json")
	if err := os.WriteFile(path, []byte(`{"id":"MAL-1","affected":[{"package":{"ecosystem":"npm","name":"x"},"versions":["1.0.0"]}]}`), 0o644); err != nil {
		t.Fatal(err)
	}
	var stdout, stderr bytes.Buffer
	if err := run([]string{"-max-file-size", "0", path}, &stdout, &stderr); err != nil {
		t.Fatalf("run: %v (stderr=%s)", err, stderr.String())
	}
	var cat struct {
		Entries []struct{ ID string } `json:"entries"`
	}
	if err := json.Unmarshal(stdout.Bytes(), &cat); err != nil {
		t.Fatalf("output not valid JSON: %v", err)
	}
	if len(cat.Entries) != 1 || cat.Entries[0].ID != "MAL-1" {
		t.Fatalf("want 1 entry MAL-1 with unbounded max size, got %+v (stderr=%s)", cat.Entries, stderr.String())
	}
}

// TestLoadZipRejectsOversizedEntry verifies the M1 size guard end-to-end:
// a zip entry whose uncompressed size exceeds -max-file-size is skipped
// (caught by the pre-read central-directory check) while a small entry
// alongside it still imports. The defensive post-read length check in
// loadZip is belt-and-suspenders for malformed archives where the
// central directory under-reports size; archive/zip normally surfaces
// that as a read error before it can be reached.
func TestLoadZipRejectsOversizedEntry(t *testing.T) {
	dir := t.TempDir()
	zipPath := filepath.Join(dir, "all.zip")
	big := strings.Repeat("a", 4096)
	writeZip(t, zipPath, map[string]string{
		"MAL-small.json": `{"id":"MAL-small","affected":[{"package":{"ecosystem":"npm","name":"ok"},"versions":["1.0.0"]}]}`,
		"MAL-big.json":   `{"id":"MAL-big","summary":"` + big + `","affected":[{"package":{"ecosystem":"npm","name":"big"},"versions":["1.0.0"]}]}`,
	})
	var stdout, stderr bytes.Buffer
	if err := run([]string{"-max-file-size", "512", zipPath}, &stdout, &stderr); err != nil {
		t.Fatalf("run: %v (stderr=%s)", err, stderr.String())
	}
	if !strings.Contains(stderr.String(), "MAL-big.json") {
		t.Errorf("expected stderr to mention oversized MAL-big.json, got: %s", stderr.String())
	}
	var cat struct {
		Entries []struct{ ID string } `json:"entries"`
	}
	if err := json.Unmarshal(stdout.Bytes(), &cat); err != nil {
		t.Fatalf("output not valid JSON: %v", err)
	}
	if len(cat.Entries) != 1 || cat.Entries[0].ID != "MAL-small" {
		t.Fatalf("want only MAL-small after size guard, got %+v", cat.Entries)
	}
}

// TestRunSourceFlag confirms the optional -source flag is stamped into
// the generated catalog's _comment for provenance.
func TestRunSourceFlag(t *testing.T) {
	dir := t.TempDir()
	zipPath := filepath.Join(dir, "all.zip")
	writeZip(t, zipPath, map[string]string{
		"MAL-1.json": `{"id":"MAL-1","affected":[{"package":{"ecosystem":"npm","name":"x"},"versions":["1.0.0"]}]}`,
	})
	var stdout, stderr bytes.Buffer
	if err := run([]string{"-source", "https://github.com/ossf/malicious-packages@deadbeef", zipPath}, &stdout, &stderr); err != nil {
		t.Fatalf("run: %v", err)
	}
	var cat struct {
		Comment string `json:"_comment"`
	}
	if err := json.Unmarshal(stdout.Bytes(), &cat); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(cat.Comment, "Source: https://github.com/ossf/malicious-packages@deadbeef") {
		t.Errorf("comment missing -source stamp: %s", cat.Comment)
	}
}
