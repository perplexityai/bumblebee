package exposure

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/perplexityai/bumblebee/internal/model"
)

func TestShippedThreatIntelCatalogsLoad(t *testing.T) {
	dir := shippedThreatIntelDir(t)
	paths := shippedThreatIntelCatalogs(t, dir)

	combined, err := Load(dir, 0)
	if err != nil {
		t.Fatalf("Load(threat_intel): %v", err)
	}

	totalEntries := 0
	for _, path := range paths {
		t.Run(filepath.Base(path), func(t *testing.T) {
			cat, err := LoadFile(path, 0)
			if err != nil {
				t.Fatalf("LoadFile: %v", err)
			}
			if cat.SchemaVersion != model.SchemaVersion {
				t.Fatalf("schema_version=%q, want %q", cat.SchemaVersion, model.SchemaVersion)
			}
			if cat.Len() == 0 {
				t.Fatal("catalog has no entries")
			}
			for _, entry := range cat.Entries {
				if !model.IsSupportedEcosystem(entry.Ecosystem) {
					t.Fatalf("entry %s uses unsupported ecosystem %q", entry.ID, entry.Ecosystem)
				}
			}
			totalEntries += cat.Len()
		})
	}

	if combined.Len() != totalEntries {
		t.Fatalf("combined catalog len=%d, want sum of shipped catalogs %d", combined.Len(), totalEntries)
	}
}

func TestThreatIntelReadmeMentionsShippedCatalogs(t *testing.T) {
	dir := shippedThreatIntelDir(t)
	paths := shippedThreatIntelCatalogs(t, dir)

	readmeBytes, err := os.ReadFile(filepath.Join(dir, "README.md"))
	if err != nil {
		t.Fatal(err)
	}
	readme := string(readmeBytes)

	for _, path := range paths {
		name := filepath.Base(path)
		if !strings.Contains(readme, name) {
			t.Fatalf("threat_intel/README.md does not mention %s", name)
		}
	}
}

func shippedThreatIntelCatalogs(t *testing.T, dir string) []string {
	t.Helper()
	paths, err := filepath.Glob(filepath.Join(dir, "*.json"))
	if err != nil {
		t.Fatal(err)
	}
	if len(paths) == 0 {
		t.Fatal("no shipped threat_intel catalogs found")
	}
	return paths
}

func shippedThreatIntelDir(t *testing.T) string {
	t.Helper()
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller failed")
	}
	dir := filepath.Clean(filepath.Join(filepath.Dir(file), "..", "..", "threat_intel"))
	if info, err := os.Stat(dir); err != nil {
		t.Fatalf("stat threat_intel dir: %v", err)
	} else if !info.IsDir() {
		t.Fatalf("threat_intel path is not a directory: %s", dir)
	}
	return dir
}
