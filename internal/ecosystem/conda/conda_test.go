package conda

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/perplexityai/bumblebee/internal/model"
)

func TestIsCondaMetaRecord(t *testing.T) {
	cases := []struct {
		path        string
		wantOK      bool
		wantEnvRoot string
	}{
		{"/home/u/miniconda3/conda-meta/numpy-1.26.0-py311h64a7726_0.json", true, "/home/u/miniconda3"},
		{"/home/u/miniconda3/envs/data/conda-meta/python-3.11.7-h1a0b9d8_0.json", true, "/home/u/miniconda3/envs/data"},
		{"/proj/.pixi/envs/default/conda-meta/openssl-3.2.1-hd590300_0.json", true, "/proj/.pixi/envs/default"},
		{"/home/u/miniconda3/conda-meta/history", false, ""},
		{"/home/u/miniconda3/pkgs/numpy-1.26.0/info/index.json", false, ""},
		{"/proj/package.json", false, ""},
	}
	for _, c := range cases {
		ok, env := IsCondaMetaRecord(c.path)
		if ok != c.wantOK || env != c.wantEnvRoot {
			t.Errorf("IsCondaMetaRecord(%q) = (%v, %q), want (%v, %q)",
				c.path, ok, env, c.wantOK, c.wantEnvRoot)
		}
	}
}

func TestScanCondaMetaRecord_CondaForge(t *testing.T) {
	dir := t.TempDir()
	env := filepath.Join(dir, "miniconda3")
	meta := filepath.Join(env, "conda-meta")
	if err := os.MkdirAll(meta, 0o755); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(meta, "numpy-1.26.0-py311h64a7726_0.json")
	body := `{
  "name": "numpy",
  "version": "1.26.0",
  "build": "py311h64a7726_0",
  "build_number": 0,
  "channel": "https://conda.anaconda.org/conda-forge/osx-arm64",
  "schannel": "conda-forge",
  "subdir": "osx-arm64",
  "depends": ["libcxx >=15.0.7", "python >=3.11,<3.12.0a0"]
}`
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	var out []model.Record
	s := &Scanner{MaxFileSize: 1 << 20, Emit: func(r model.Record) { out = append(out, r) }}
	if err := s.ScanCondaMetaRecord(path, env, model.Record{}); err != nil {
		t.Fatal(err)
	}
	if len(out) != 1 {
		t.Fatalf("want 1 record, got %d", len(out))
	}
	r := out[0]
	if r.Ecosystem != model.EcosystemConda || r.PackageName != "numpy" || r.NormalizedName != "numpy" {
		t.Errorf("identity: %+v", r)
	}
	if r.Version != "1.26.0" || r.SourceType != "conda-meta" || r.Confidence != "high" {
		t.Errorf("metadata: %+v", r)
	}
	if r.ProjectPath != env {
		t.Errorf("ProjectPath = %q, want %q", r.ProjectPath, env)
	}
	if r.PackageManager != "conda" {
		t.Errorf("PackageManager = %q, want %q", r.PackageManager, "conda")
	}
}

// TestScanCondaMetaRecord_PypiChannel verifies that a pip-installed
// package recorded in conda-meta (schannel="pypi") surfaces as
// package_manager=pip rather than conda, so receivers can tell pip and
// conda installs apart even when they share the same env prefix.
func TestScanCondaMetaRecord_PypiChannel(t *testing.T) {
	dir := t.TempDir()
	env := filepath.Join(dir, "envs", "data")
	meta := filepath.Join(env, "conda-meta")
	if err := os.MkdirAll(meta, 0o755); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(meta, "rich-13.7.0-pyhd8ed1ab_0.json")
	body := `{"name": "rich", "version": "13.7.0", "channel": "pypi", "schannel": "pypi"}`
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	var out []model.Record
	s := &Scanner{MaxFileSize: 1 << 20, Emit: func(r model.Record) { out = append(out, r) }}
	if err := s.ScanCondaMetaRecord(path, env, model.Record{}); err != nil {
		t.Fatal(err)
	}
	if len(out) != 1 {
		t.Fatalf("want 1 record, got %d", len(out))
	}
	if out[0].PackageManager != "pip" {
		t.Errorf("PackageManager = %q, want %q", out[0].PackageManager, "pip")
	}
	if out[0].Ecosystem != model.EcosystemConda {
		t.Errorf("Ecosystem = %q, want %q", out[0].Ecosystem, model.EcosystemConda)
	}
}

// TestScanCondaMetaRecord_ChannelFromURL covers the fallback path where
// schannel is absent and we have to derive the short channel name from
// the channel URL.
func TestScanCondaMetaRecord_ChannelFromURL(t *testing.T) {
	dir := t.TempDir()
	env := filepath.Join(dir, "miniforge3")
	meta := filepath.Join(env, "conda-meta")
	if err := os.MkdirAll(meta, 0o755); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(meta, "samtools-1.18-h50ea8bc_1.json")
	// Bioconda URL, no schannel — exercises channelFromURL fallback.
	body := `{"name": "samtools", "version": "1.18", "channel": "https://conda.anaconda.org/bioconda/linux-64"}`
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	var out []model.Record
	s := &Scanner{MaxFileSize: 1 << 20, Emit: func(r model.Record) { out = append(out, r) }}
	if err := s.ScanCondaMetaRecord(path, env, model.Record{}); err != nil {
		t.Fatal(err)
	}
	if len(out) != 1 {
		t.Fatalf("want 1 record, got %d", len(out))
	}
	// Bioconda is still a conda channel — package_manager should be "conda".
	if out[0].PackageManager != "conda" {
		t.Errorf("PackageManager = %q, want %q", out[0].PackageManager, "conda")
	}
}

// TestChannelFromURL covers the real-world channel-field shapes observed
// across pixi/mamba/micromamba/conda installs. Earlier revisions used a
// "second-to-last segment" heuristic that mis-attributed URLs without a
// trailing subdir (the common pixi shape) to the hostname.
func TestChannelFromURL(t *testing.T) {
	cases := []struct {
		in, want string
	}{
		// URL with subdir suffix (canonical anaconda.org-hosted channel).
		{"https://conda.anaconda.org/conda-forge/osx-arm64", "conda-forge"},
		{"https://conda.anaconda.org/bioconda/linux-64", "bioconda"},
		// URL with trailing slash, no subdir (what pixi writes on this host).
		{"https://conda.anaconda.org/conda-forge/", "conda-forge"},
		// URL with no subdir and no trailing slash.
		{"https://conda.anaconda.org/conda-forge", "conda-forge"},
		// Non-anaconda.org host.
		{"https://prefix.dev/my-channel", "my-channel"},
		// Bare-string channels (mamba/micromamba write these for pip-installed
		// packages and for the "<unknown>" sentinel).
		{"pypi", "pypi"},
		{"<unknown>", "<unknown>"},
		// Empty and whitespace.
		{"", ""},
		{"   ", ""},
		// URL with no path component (no channel to extract).
		{"https://conda.anaconda.org", ""},
		{"https://conda.anaconda.org/", ""},
	}
	for _, c := range cases {
		if got := channelFromURL(c.in); got != c.want {
			t.Errorf("channelFromURL(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

// TestScanCondaMetaRecord_PipInstalledBareChannel verifies the
// pip-vs-conda attribution still works when `schannel` is missing and
// `channel` is the bare string "pypi" rather than a URL. Older
// mamba/micromamba records use this shape.
func TestScanCondaMetaRecord_PipInstalledBareChannel(t *testing.T) {
	dir := t.TempDir()
	env := filepath.Join(dir, "envs", "data")
	meta := filepath.Join(env, "conda-meta")
	if err := os.MkdirAll(meta, 0o755); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(meta, "rich-13.7.0-pyhd8ed1ab_0.json")
	body := `{"name": "rich", "version": "13.7.0", "channel": "pypi"}`
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	var out []model.Record
	s := &Scanner{MaxFileSize: 1 << 20, Emit: func(r model.Record) { out = append(out, r) }}
	if err := s.ScanCondaMetaRecord(path, env, model.Record{}); err != nil {
		t.Fatal(err)
	}
	if len(out) != 1 || out[0].PackageManager != "pip" {
		t.Fatalf("expected package_manager=pip from bare 'pypi' channel, got %+v", out)
	}
}

func TestScanCondaMetaRecord_MissingFields(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "broken-0.0.0-foo.json")
	// No name or version — should warn and skip without erroring.
	if err := os.WriteFile(path, []byte(`{"channel": "conda-forge"}`), 0o644); err != nil {
		t.Fatal(err)
	}
	var out []model.Record
	var diagMessages []string
	s := &Scanner{
		MaxFileSize: 1 << 20,
		Emit:        func(r model.Record) { out = append(out, r) },
		Diag:        func(level, p, m string) { diagMessages = append(diagMessages, m) },
	}
	if err := s.ScanCondaMetaRecord(path, dir, model.Record{}); err != nil {
		t.Fatalf("expected nil error for record with missing fields, got %v", err)
	}
	if len(out) != 0 {
		t.Fatalf("expected no records, got %d", len(out))
	}
	if len(diagMessages) == 0 || !strings.Contains(diagMessages[0], "missing name") {
		t.Errorf("expected diagnostic about missing name/version, got %v", diagMessages)
	}
}

func TestScanCondaMetaRecord_MalformedJSON(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "junk-1.0-0.json")
	if err := os.WriteFile(path, []byte(`{"name": "junk", "version":`), 0o644); err != nil {
		t.Fatal(err)
	}
	s := &Scanner{MaxFileSize: 1 << 20, Emit: func(model.Record) { t.Fatal("should not emit") }}
	err := s.ScanCondaMetaRecord(path, dir, model.Record{})
	if err == nil {
		t.Fatalf("expected error on malformed JSON, got nil")
	}
	// Lock in the error-wrapping contract: the returned error must
	// reference the offending file path so the scanner orchestrator's
	// downstream Diag(\"error\", path, err.Error()) yields a useful
	// message. A future refactor that swallows the parse error or
	// drops the path wrap would silently break operator diagnostics.
	if !strings.Contains(err.Error(), path) {
		t.Errorf("error message %q does not reference path %q", err.Error(), path)
	}
}

func TestScanCondaMetaRecord_OversizeSkipped(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "huge-1.0-0.json")
	if err := os.WriteFile(path, []byte(`{"name":"huge","version":"1.0"}`), 0o644); err != nil {
		t.Fatal(err)
	}
	var diagged bool
	s := &Scanner{
		MaxFileSize: 4, // smaller than file contents — must skip
		Emit:        func(model.Record) { t.Fatal("should not emit") },
		Diag:        func(level, p, m string) { diagged = true },
	}
	if err := s.ScanCondaMetaRecord(path, dir, model.Record{}); err == nil {
		t.Fatalf("expected error when file exceeds MaxFileSize")
	}
	if !diagged {
		t.Errorf("expected oversize diagnostic")
	}
}
