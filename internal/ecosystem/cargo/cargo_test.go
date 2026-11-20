package cargo

import (
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/perplexityai/bumblebee/internal/model"
)

func TestIsCrates2JSON(t *testing.T) {
	cases := []struct {
		path string
		want bool
	}{
		{filepath.Join("home", ".cargo", ".crates2.json"), true},
		{filepath.Join("home", ".cargo", ".crates.json"), false},
		{filepath.Join("home", "elsewhere", ".crates2.json"), false},
		{filepath.Join("home", ".cargo", "registry", ".crates2.json"), false},
	}
	for _, c := range cases {
		got := IsCrates2JSON(c.path)
		if got != c.want {
			t.Errorf("IsCrates2JSON(%q) = %v, want %v", c.path, got, c.want)
		}
	}
}

func TestIsCargoLock(t *testing.T) {
	if !IsCargoLock("Cargo.lock") {
		t.Errorf("IsCargoLock(Cargo.lock) = false")
	}
	if IsCargoLock("cargo.lock") {
		t.Errorf("IsCargoLock should be case-sensitive")
	}
	if IsCargoLock("Cargo.toml") {
		t.Errorf("IsCargoLock matched Cargo.toml")
	}
}

func TestParseCrates2InstallKey(t *testing.T) {
	cases := []struct {
		key          string
		wantName     string
		wantVersion  string
		wantOK       bool
	}{
		{
			"cargo-auditable 0.7.4 (registry+https://github.com/rust-lang/crates.io-index)",
			"cargo-auditable", "0.7.4", true,
		},
		{
			"ripgrep 13.0.0 (registry+https://github.com/rust-lang/crates.io-index)",
			"ripgrep", "13.0.0", true,
		},
		{
			"depsguard 0.1.33",
			"depsguard", "0.1.33", true,
		},
		{"", "", "", false},
		{"single-token", "", "", false},
	}
	for _, c := range cases {
		name, version, ok := parseCrates2InstallKey(c.key)
		if ok != c.wantOK || name != c.wantName || version != c.wantVersion {
			t.Errorf("parseCrates2InstallKey(%q) = (%q, %q, %v), want (%q, %q, %v)",
				c.key, name, version, ok, c.wantName, c.wantVersion, c.wantOK)
		}
	}
}

func TestScanCrates2JSON(t *testing.T) {
	dir := t.TempDir()
	cargoDir := filepath.Join(dir, ".cargo")
	if err := os.MkdirAll(cargoDir, 0o755); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(cargoDir, ".crates2.json")
	body := `{
		"installs": {
			"cargo-auditable 0.7.4 (registry+https://github.com/rust-lang/crates.io-index)": {
				"bins": ["cargo-auditable"]
			},
			"ripgrep 13.0.0 (registry+https://github.com/rust-lang/crates.io-index)": {
				"bins": ["rg"]
			}
		}
	}`
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	if !IsCrates2JSON(path) {
		t.Fatalf("IsCrates2JSON(%q) = false", path)
	}

	var out []model.Record
	s := &Scanner{
		MaxFileSize: 1 << 20,
		Emit:        func(r model.Record) { out = append(out, r) },
		Diag:        func(string, string, string) {},
	}
	if err := s.ScanCrates2JSON(path, model.Record{}); err != nil {
		t.Fatalf("ScanCrates2JSON: %v", err)
	}
	if len(out) != 2 {
		t.Fatalf("records = %d, want 2", len(out))
	}
	sort.Slice(out, func(i, j int) bool { return out[i].PackageName < out[j].PackageName })
	if out[0].PackageName != "cargo-auditable" || out[0].Version != "0.7.4" {
		t.Errorf("cargo-auditable record: %+v", out[0])
	}
	if out[1].PackageName != "ripgrep" || out[1].Version != "13.0.0" {
		t.Errorf("ripgrep record: %+v", out[1])
	}
	for _, r := range out {
		if r.Ecosystem != model.EcosystemCargo {
			t.Errorf("ecosystem = %q, want %q", r.Ecosystem, model.EcosystemCargo)
		}
		if r.SourceType != "cargo-crates2-installs" {
			t.Errorf("source_type = %q", r.SourceType)
		}
		if r.PackageManager != "cargo" {
			t.Errorf("package_manager = %q", r.PackageManager)
		}
		if r.Confidence != "high" {
			t.Errorf("confidence = %q", r.Confidence)
		}
		if r.DirectDependency == nil || !*r.DirectDependency {
			t.Errorf("direct_dependency = %v, want true", r.DirectDependency)
		}
	}
}

func TestScanCrates2JSONMalformed(t *testing.T) {
	dir := t.TempDir()
	cargoDir := filepath.Join(dir, ".cargo")
	if err := os.MkdirAll(cargoDir, 0o755); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(cargoDir, ".crates2.json")
	if err := os.WriteFile(path, []byte("not json"), 0o644); err != nil {
		t.Fatal(err)
	}
	var diagnostics []string
	s := &Scanner{
		MaxFileSize: 1 << 20,
		Emit:        func(model.Record) { t.Fatal("Emit should not be called on malformed input") },
		Diag:        func(_, _, msg string) { diagnostics = append(diagnostics, msg) },
	}
	if err := s.ScanCrates2JSON(path, model.Record{}); err != nil {
		t.Fatalf("ScanCrates2JSON returned error for malformed input: %v", err)
	}
	if len(diagnostics) == 0 || !strings.Contains(diagnostics[0], "malformed") {
		t.Fatalf("expected malformed diagnostic, got %v", diagnostics)
	}
}

func TestScanCargoLock(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "Cargo.lock")
	body := `# Auto-generated
version = 4

[[package]]
name = "addr2line"
version = "0.25.1"
source = "registry+https://github.com/rust-lang/crates.io-index"
checksum = "1b5d307320b3181d6d7954e663bd7c774a838b8220fe0593c86d9fb09f498b4b"
dependencies = [
 "gimli",
]

[[package]]
name = "adler2"
version = "2.0.1"
source = "registry+https://github.com/rust-lang/crates.io-index"
checksum = "320119579fcad9c21884f5c4861d16174d0e06250625266f50fe6898340abefa"

[[package]]
name = "myworkspace-local"
version = "0.0.0"
dependencies = [
 "core",
]
`
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	var out []model.Record
	s := &Scanner{
		MaxFileSize: 1 << 20,
		Emit:        func(r model.Record) { out = append(out, r) },
	}
	if err := s.ScanCargoLock(path, model.Record{}); err != nil {
		t.Fatalf("ScanCargoLock: %v", err)
	}
	if len(out) != 2 {
		t.Fatalf("records = %d, want 2 (workspace-local must be dropped): %+v", len(out), out)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].PackageName < out[j].PackageName })
	if out[0].PackageName != "addr2line" || out[0].Version != "0.25.1" {
		t.Errorf("addr2line record: %+v", out[0])
	}
	if out[1].PackageName != "adler2" || out[1].Version != "2.0.1" {
		t.Errorf("adler2 record: %+v", out[1])
	}
	for _, r := range out {
		if r.Ecosystem != model.EcosystemCargo {
			t.Errorf("ecosystem = %q", r.Ecosystem)
		}
		if r.SourceType != "cargo-lock" {
			t.Errorf("source_type = %q", r.SourceType)
		}
		if r.ProjectPath != dir {
			t.Errorf("project_path = %q, want %q", r.ProjectPath, dir)
		}
		if r.Confidence != "high" {
			t.Errorf("confidence = %q", r.Confidence)
		}
	}
}

func TestScanCargoLockDedupesDuplicateEntries(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "Cargo.lock")
	body := `[[package]]
name = "same"
version = "1.0.0"
source = "registry+https://github.com/rust-lang/crates.io-index"

[[package]]
name = "same"
version = "1.0.0"
source = "registry+https://github.com/rust-lang/crates.io-index"
`
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	var out []model.Record
	s := &Scanner{
		MaxFileSize: 1 << 20,
		Emit:        func(r model.Record) { out = append(out, r) },
	}
	if err := s.ScanCargoLock(path, model.Record{}); err != nil {
		t.Fatalf("ScanCargoLock: %v", err)
	}
	if len(out) != 1 {
		t.Fatalf("records = %d, want 1 after dedup", len(out))
	}
}
