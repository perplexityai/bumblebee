package homebrew

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/perplexityai/bumblebee/internal/model"
)

func TestScanFormulaReceipt(t *testing.T) {
	root := t.TempDir()
	receipt := filepath.Join(root, "Cellar", "wget", "1.21.4", receiptFile)
	writeFile(t, receipt, `{"installed_on_request":true,"source":{"tap":"homebrew/core"}}`)

	ok, name, version, cellarDir := IsFormulaReceipt(receipt)
	if !ok {
		t.Fatalf("IsFormulaReceipt(%q) = false", receipt)
	}
	var out []model.Record
	s := &Scanner{
		MaxFileSize: 1024,
		Emit:        func(r model.Record) { out = append(out, r) },
		Diag:        func(string, string, string) {},
	}
	if err := s.ScanFormulaReceipt(receipt, name, version, cellarDir, model.Record{}); err != nil {
		t.Fatalf("ScanFormulaReceipt: %v", err)
	}
	if len(out) != 1 {
		t.Fatalf("records = %d, want 1", len(out))
	}
	r := out[0]
	if r.Ecosystem != model.EcosystemHomebrew || r.PackageName != "wget" || r.NormalizedName != "wget" || r.Version != "1.21.4" {
		t.Fatalf("unexpected record identity: %+v", r)
	}
	if r.ProjectPath != filepath.Join(root, "Cellar") {
		t.Errorf("ProjectPath = %q, want Cellar dir", r.ProjectPath)
	}
	if r.PackageManager != "homebrew" || r.SourceType != "homebrew-formula-receipt" || r.Confidence != "high" {
		t.Errorf("unexpected source fields: %+v", r)
	}
	if r.DirectDependency == nil || !*r.DirectDependency {
		t.Fatalf("DirectDependency = %v, want true", r.DirectDependency)
	}
}

func TestScanFormulaReceiptWarnsOnMalformedReceiptFields(t *testing.T) {
	root := t.TempDir()
	receipt := filepath.Join(root, "Cellar", "broken", "1.0.0", receiptFile)
	writeFile(t, receipt, `{"installed_on_request":"not-a-bool"}`)

	ok, name, version, cellarDir := IsFormulaReceipt(receipt)
	if !ok {
		t.Fatalf("IsFormulaReceipt(%q) = false", receipt)
	}
	var out []model.Record
	var diagnostics []string
	s := &Scanner{
		MaxFileSize: 1024,
		Emit:        func(r model.Record) { out = append(out, r) },
		Diag:        func(_, _, msg string) { diagnostics = append(diagnostics, msg) },
	}
	if err := s.ScanFormulaReceipt(receipt, name, version, cellarDir, model.Record{}); err != nil {
		t.Fatalf("ScanFormulaReceipt: %v", err)
	}
	if len(out) != 1 {
		t.Fatalf("records = %d, want 1", len(out))
	}
	if out[0].DirectDependency != nil {
		t.Fatalf("DirectDependency = %v, want nil", out[0].DirectDependency)
	}
	if len(diagnostics) == 0 || !strings.Contains(diagnostics[0], "skipping receipt fields") {
		t.Fatalf("expected malformed receipt diagnostic, got %v", diagnostics)
	}
}

func TestCaskMetadataMarkerPreference(t *testing.T) {
	root := t.TempDir()
	casksDir := filepath.Join(root, "Caskroom", "foo", ".metadata", "1.2.3", "20260523010203.004", "Casks")
	internalPath := filepath.Join(casksDir, "foo.internal.json")
	jsonPath := filepath.Join(casksDir, "foo.json")
	rbPath := filepath.Join(casksDir, "foo.rb")
	writeFile(t, internalPath, `{"token":"foo","version":"1.2.3"}`)
	writeFile(t, jsonPath, `{"token":"foo","version":"1.2.3"}`)
	writeFile(t, rbPath, `cask "foo" do`)

	if ok, token, version, caskroomDir := IsCaskMetadataMarker(internalPath); !ok || token != "foo" || version != "1.2.3" || caskroomDir != filepath.Join(root, "Caskroom") {
		t.Fatalf("internal marker = (%v,%q,%q,%q), want foo 1.2.3 Caskroom", ok, token, version, caskroomDir)
	}
	for _, p := range []string{jsonPath, rbPath} {
		if !LooksLikeCaskMetadataMarker(p) {
			t.Errorf("LooksLikeCaskMetadataMarker(%q) = false, want true", p)
		}
		if ok, _, _, _ := IsCaskMetadataMarker(p); ok {
			t.Fatalf("IsCaskMetadataMarker(%q) = true, want false because internal.json is preferred", p)
		}
	}
}

func TestScanCaskMetadataFromJSONAndRubyMarkers(t *testing.T) {
	root := t.TempDir()
	caskroom := filepath.Join(root, "Caskroom")
	jsonMarker := filepath.Join(caskroom, "json-only", ".metadata", "2.0.0", "20260523010203.004", "Casks", "json-only.json")
	rbMarker := filepath.Join(caskroom, "ruby-only", ".metadata", "latest", "20260523010203.004", "Casks", "ruby-only.rb")
	writeFile(t, jsonMarker, `{"token":"json-only","version":"2.0.0"}`)
	writeFile(t, rbMarker, `cask "ruby-only" do`)
	writeFile(t, filepath.Join(caskroom, "ruby-only", ".metadata", receiptFile), `{"installed_on_request":false}`)

	var out []model.Record
	s := &Scanner{
		MaxFileSize: 1024,
		Emit:        func(r model.Record) { out = append(out, r) },
		Diag:        func(string, string, string) {},
	}
	for _, path := range []string{jsonMarker, rbMarker} {
		ok, token, version, caskroomDir := IsCaskMetadataMarker(path)
		if !ok {
			t.Fatalf("IsCaskMetadataMarker(%q) = false", path)
		}
		if err := s.ScanCaskMetadata(path, token, version, caskroomDir, model.Record{}); err != nil {
			t.Fatalf("ScanCaskMetadata(%q): %v", path, err)
		}
	}
	if len(out) != 2 {
		t.Fatalf("records = %d, want 2", len(out))
	}
	got := map[string]model.Record{}
	for _, r := range out {
		got[r.PackageName] = r
		if r.Ecosystem != model.EcosystemHomebrew || r.PackageManager != "homebrew" || r.SourceType != "homebrew-cask-metadata" {
			t.Errorf("unexpected cask record: %+v", r)
		}
	}
	if got["json-only"].Version != "2.0.0" {
		t.Errorf("json-only version = %q", got["json-only"].Version)
	}
	if got["json-only"].DirectDependency != nil {
		t.Errorf("json-only DirectDependency = %v, want nil", got["json-only"].DirectDependency)
	}
	ruby := got["ruby-only"]
	if ruby.Version != "latest" {
		t.Errorf("ruby-only version = %q", ruby.Version)
	}
	if ruby.DirectDependency == nil || *ruby.DirectDependency {
		t.Fatalf("ruby-only DirectDependency = %v, want false", ruby.DirectDependency)
	}
}

func TestCaskMetadataMarkerWithoutTimestampIsNotPreferred(t *testing.T) {
	root := t.TempDir()
	versionDir := filepath.Join(root, "Caskroom", "foo", ".metadata", "1.2.3")
	if err := os.MkdirAll(versionDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if _, ok := preferredCaskMarker(filepath.Join(root, "Caskroom", "foo"), "1.2.3", "foo"); ok {
		t.Fatal("preferredCaskMarker found a marker without timestamp subdirs")
	}
}

func TestRejectsUnrelatedHomebrewPaths(t *testing.T) {
	root := t.TempDir()
	if ok, _, _, _ := IsFormulaReceipt(filepath.Join(root, "not-cellar", "pkg", "1.0.0", receiptFile)); ok {
		t.Fatal("unrelated INSTALL_RECEIPT.json matched as formula")
	}
	unrelated := filepath.Join(root, "Caskroom", "foo", ".metadata", "1.0.0", "Casks", "foo.json")
	writeFile(t, unrelated, `{}`)
	if ok, _, _, _ := IsCaskMetadataMarker(unrelated); ok {
		t.Fatal("metadata path without timestamp matched as cask")
	}
}

func TestFormulaReceiptMaxFileSize(t *testing.T) {
	root := t.TempDir()
	receipt := filepath.Join(root, "Cellar", "big", "1.0.0", receiptFile)
	writeFile(t, receipt, strings.Repeat("x", 64))

	ok, name, version, cellarDir := IsFormulaReceipt(receipt)
	if !ok {
		t.Fatalf("IsFormulaReceipt(%q) = false", receipt)
	}
	var emitted bool
	var diagnostics []string
	s := &Scanner{
		MaxFileSize: 8,
		Emit:        func(model.Record) { emitted = true },
		Diag:        func(_, _, msg string) { diagnostics = append(diagnostics, msg) },
	}
	if err := s.ScanFormulaReceipt(receipt, name, version, cellarDir, model.Record{}); err == nil {
		t.Fatal("expected max-size error")
	}
	if emitted {
		t.Fatal("oversized receipt emitted a record")
	}
	if len(diagnostics) == 0 || !strings.Contains(diagnostics[0], "exceeds max") {
		t.Fatalf("expected max-size diagnostic, got %v", diagnostics)
	}
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
