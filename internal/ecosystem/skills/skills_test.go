package skills

import (
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/perplexityai/bumblebee/internal/model"
)

func writeFile(t *testing.T, path, content string) {
	t.Helper()
	if dir := filepath.Dir(path); dir != "" {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}

func TestIsKnownLockFile(t *testing.T) {
	cases := map[string]bool{
		".skill-lock.json": true,
		"skills-lock.json": true,
		"skill-lock.json":  false,
		".skill-lock":      false,
		"skills.json":      false,
		"package.json":     false,
		"":                 false,
	}
	for base, want := range cases {
		if got := IsKnownLockFile(base); got != want {
			t.Errorf("IsKnownLockFile(%q) = %v, want %v", base, got, want)
		}
	}
}

func TestScanLockFile_GitHubV3(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "skills-lock.json")
	writeFile(t, path, `{
  "version": 3,
  "skills": {
    "ai-sdk": {
      "source": "vercel/ai",
      "sourceType": "github",
      "skillFolderHash": "abc",
      "ref": "main"
    },
    "vercel-react-best-practices": {
      "source": "vercel-labs/agent-skills",
      "sourceType": "github",
      "skillFolderHash": "def",
      "skillPath": "react"
    }
  }
}`)

	got := runScan(t, path)
	if len(got) != 2 {
		t.Fatalf("got %d records, want 2", len(got))
	}

	sort.Slice(got, func(i, j int) bool { return got[i].ServerName < got[j].ServerName })

	r := got[0] // ai-sdk
	if r.ServerName != "ai-sdk" {
		t.Errorf("ServerName=%q", r.ServerName)
	}
	if r.PackageName != "vercel/ai" || r.NormalizedName != "vercel/ai" {
		t.Errorf("PackageName=%q NormalizedName=%q", r.PackageName, r.NormalizedName)
	}
	if r.Ecosystem != model.EcosystemAgentSkill {
		t.Errorf("Ecosystem=%q", r.Ecosystem)
	}
	if r.PackageManager != "skills.sh" {
		t.Errorf("PackageManager=%q", r.PackageManager)
	}
	if r.SourceType != "skill-lock" {
		t.Errorf("SourceType=%q", r.SourceType)
	}
	if r.SourceFile != path {
		t.Errorf("SourceFile=%q", r.SourceFile)
	}
	if r.RootKind != model.RootKindAgentSkill {
		t.Errorf("RootKind=%q", r.RootKind)
	}
	if r.Confidence != "low" {
		t.Errorf("Confidence=%q", r.Confidence)
	}
	if r.Version != "" {
		t.Errorf("Version=%q, want empty (refs are not versions)", r.Version)
	}
	if r.RequestedSpec != "github:vercel/ai@main" {
		t.Errorf("RequestedSpec=%q, want %q", r.RequestedSpec, "github:vercel/ai@main")
	}

	r = got[1] // vercel-react-best-practices
	if r.PackageName != "vercel-labs/agent-skills" {
		t.Errorf("PackageName=%q", r.PackageName)
	}
	if r.RequestedSpec != "github:vercel-labs/agent-skills/react" {
		t.Errorf("RequestedSpec=%q, want %q", r.RequestedSpec, "github:vercel-labs/agent-skills/react")
	}
}

func TestScanLockFile_LegacyV1(t *testing.T) {
	// v1 (open-agents example): only source/sourceType/computedHash.
	// computedHash is intentionally not retained on the record; we
	// only assert that the parse works and the slug is preserved.
	dir := t.TempDir()
	path := filepath.Join(dir, ".skill-lock.json")
	writeFile(t, path, `{
  "version": 1,
  "skills": {
    "chat-sdk": {
      "source": "vercel/chat",
      "sourceType": "github",
      "computedHash": "3483217a04e5abd951e9f90f26beb062cdcccb5785a3b2a97ec9fe797536a135"
    }
  }
}`)
	got := runScan(t, path)
	if len(got) != 1 {
		t.Fatalf("got %d records, want 1", len(got))
	}
	r := got[0]
	if r.PackageName != "vercel/chat" {
		t.Errorf("PackageName=%q", r.PackageName)
	}
	if r.RequestedSpec != "github:vercel/chat" {
		t.Errorf("RequestedSpec=%q", r.RequestedSpec)
	}
	if !strings.Contains(r.SourceFile, ".skill-lock.json") {
		t.Errorf("SourceFile=%q does not look like a global lock", r.SourceFile)
	}
}

func TestScanLockFile_LocalSourceTypeDoesNotLeakPath(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "skills-lock.json")
	writeFile(t, path, `{
  "version": 3,
  "skills": {
    "my-local-skill": {
      "source": "/Users/alice/secret/path/to/skill",
      "sourceType": "local"
    }
  }
}`)
	got := runScan(t, path)
	if len(got) != 1 {
		t.Fatalf("got %d records, want 1", len(got))
	}
	r := got[0]
	if r.PackageName != "my-local-skill" {
		t.Errorf("PackageName=%q, want fallback to local alias", r.PackageName)
	}
	if strings.Contains(r.PackageName, "/") || strings.Contains(r.RequestedSpec, "/Users") {
		t.Errorf("local path leaked into record: PackageName=%q RequestedSpec=%q", r.PackageName, r.RequestedSpec)
	}
	if r.RequestedSpec != "local:" {
		t.Errorf("RequestedSpec=%q, want %q", r.RequestedSpec, "local:")
	}
}

func TestScanLockFile_NormalizesNameLower(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "skills-lock.json")
	writeFile(t, path, `{
  "version": 3,
  "skills": {
    "Mixed-Case": {
      "source": "Vercel/AI-SDK",
      "sourceType": "github"
    }
  }
}`)
	got := runScan(t, path)
	if len(got) != 1 {
		t.Fatalf("got %d records", len(got))
	}
	if got[0].PackageName != "Vercel/AI-SDK" {
		t.Errorf("PackageName=%q, want original casing", got[0].PackageName)
	}
	if got[0].NormalizedName != "vercel/ai-sdk" {
		t.Errorf("NormalizedName=%q, want %q", got[0].NormalizedName, "vercel/ai-sdk")
	}
}

func TestScanLockFile_UnknownVersionTolerated(t *testing.T) {
	// Future schema bump must not break inventory.
	dir := t.TempDir()
	path := filepath.Join(dir, "skills-lock.json")
	writeFile(t, path, `{
  "version": 99,
  "skills": {
    "future-skill": {
      "source": "owner/repo",
      "sourceType": "github",
      "someFutureField": {"nested": "value"}
    }
  }
}`)
	got := runScan(t, path)
	if len(got) != 1 {
		t.Fatalf("got %d records, want 1", len(got))
	}
	if got[0].PackageName != "owner/repo" {
		t.Errorf("PackageName=%q", got[0].PackageName)
	}
}

func TestScanLockFile_MalformedJSONWarns(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "skills-lock.json")
	writeFile(t, path, `{not json`)

	var diags []string
	var records []model.Record
	s := &Scanner{
		MaxFileSize: 1 << 20,
		Emit:        func(r model.Record) { records = append(records, r) },
		Diag:        func(level, _, msg string) { diags = append(diags, level+": "+msg) },
	}
	if err := s.ScanLockFile(path, model.Record{}); err != nil {
		t.Fatalf("ScanLockFile: %v", err)
	}
	if len(records) != 0 {
		t.Errorf("malformed lock should produce no records, got %d", len(records))
	}
	if len(diags) == 0 || !strings.HasPrefix(diags[0], "warn: parse skill lock:") {
		t.Errorf("expected a warn diag about parse, got %v", diags)
	}
}

func TestScanLockFile_EmptySkillsMapIsInfo(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "skills-lock.json")
	writeFile(t, path, `{"version": 3, "skills": {}}`)

	var diags []string
	var records []model.Record
	s := &Scanner{
		MaxFileSize: 1 << 20,
		Emit:        func(r model.Record) { records = append(records, r) },
		Diag:        func(level, _, msg string) { diags = append(diags, level+": "+msg) },
	}
	if err := s.ScanLockFile(path, model.Record{}); err != nil {
		t.Fatalf("ScanLockFile: %v", err)
	}
	if len(records) != 0 {
		t.Errorf("empty skills map should produce no records, got %d", len(records))
	}
	if len(diags) == 0 || !strings.Contains(diags[0], "info") {
		t.Errorf("expected an info diag, got %v", diags)
	}
}

func TestScanLockFile_MaxSizeEnforced(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "skills-lock.json")
	writeFile(t, path, `{"version":3,"skills":{"x":{"source":"a/b","sourceType":"github"}}}`)

	var records []model.Record
	var diags []string
	s := &Scanner{
		MaxFileSize: 4, // far below the file size
		Emit:        func(r model.Record) { records = append(records, r) },
		Diag:        func(level, _, msg string) { diags = append(diags, level+": "+msg) },
	}
	if err := s.ScanLockFile(path, model.Record{}); err == nil {
		t.Fatalf("ScanLockFile: expected size-exceeded error")
	}
	if len(records) != 0 {
		t.Errorf("oversize file produced %d records", len(records))
	}
	if len(diags) == 0 || !strings.Contains(diags[0], "exceeds max") {
		t.Errorf("expected size diag, got %v", diags)
	}
}

func runScan(t *testing.T, path string) []model.Record {
	t.Helper()
	var got []model.Record
	s := &Scanner{
		MaxFileSize: 1 << 20,
		Emit:        func(r model.Record) { got = append(got, r) },
		Diag:        func(level, _, msg string) { t.Logf("diag %s: %s", level, msg) },
	}
	if err := s.ScanLockFile(path, model.Record{}); err != nil {
		t.Fatalf("ScanLockFile: %v", err)
	}
	return got
}
