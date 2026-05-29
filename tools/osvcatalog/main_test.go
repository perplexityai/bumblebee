package main

import (
	"archive/zip"
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
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

func TestRunIncludeVulnsAndEcosystemFilter(t *testing.T) {
	dir := t.TempDir()
	zipPath := filepath.Join(dir, "all.zip")
	writeZip(t, zipPath, map[string]string{
		"GHSA-npm.json": `{"id":"GHSA-npm","affected":[{"package":{"ecosystem":"npm","name":"a"},"versions":["1.0.0"]}]}`,
		"GHSA-py.json":  `{"id":"GHSA-py","affected":[{"package":{"ecosystem":"PyPI","name":"b"},"versions":["2.0.0"]}]}`,
	})

	var stdout, stderr bytes.Buffer
	if err := run([]string{"-include-vulns", "-ecosystem", "pypi", zipPath}, &stdout, &stderr); err != nil {
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
