package scanner

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/perplexityai/bumblebee/internal/model"
	"github.com/perplexityai/bumblebee/internal/output"
)

func writeFile(t *testing.T, path, body string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
}

func TestEndToEndScan(t *testing.T) {
	root := t.TempDir()

	// npm lockfile with one package, plus the same package present in
	// node_modules/<pkg>/package.json. Records must come from different
	// source_types and therefore NOT be deduplicated.
	writeFile(t, filepath.Join(root, "proj", "package-lock.json"), `{
  "lockfileVersion": 3,
  "packages": {
    "": {"name":"proj","version":"1.0.0"},
    "node_modules/lodash": {"version":"4.17.21","integrity":"sha512-a"}
  }
}`)
	writeFile(t, filepath.Join(root, "proj", "node_modules", "lodash", "package.json"), `{
  "name":"lodash","version":"4.17.21","scripts":{"postinstall":"echo hi"}
}`)

	// Python dist-info.
	di := filepath.Join(root, "venv", "lib", "site-packages", "Requests-2.31.0.dist-info")
	writeFile(t, filepath.Join(di, "METADATA"), "Metadata-Version: 2.1\nName: Requests\nVersion: 2.31.0\n\n")
	writeFile(t, filepath.Join(di, "INSTALLER"), "pip\n")

	// Excluded credential-ish path that must not be visited.
	writeFile(t, filepath.Join(root, ".ssh", "id_rsa"), "should not be read")
	// .env file that must be skipped even outside excluded dirs.
	writeFile(t, filepath.Join(root, "proj", ".env"), "SECRET=nope")

	// Duplicate lockfile contents in a second directory to verify dedup
	// across files of the same source_type+file collapses correctly.
	writeFile(t, filepath.Join(root, "dup", "package-lock.json"), `{
  "lockfileVersion": 3,
  "packages": {
    "node_modules/lodash": {"version":"4.17.21","integrity":"sha512-a"}
  }
}`)

	stdout := &bytes.Buffer{}
	stderr := &bytes.Buffer{}
	em := output.New(stdout, stderr, "runtest")

	res, err := Run(context.Background(), Config{
		Roots:       []Root{{Path: root, Kind: model.RootKindProject}},
		Profile:     model.ProfileProject,
		MaxFileSize: 5 * 1024 * 1024,
		Concurrency: 2,
		BaseRecord: model.Record{
			SchemaVersion:  model.SchemaVersion,
			ScannerName:    model.ScannerName,
			ScannerVersion: "test",
			RunID:          "runtest",
			ScanTime:       time.Now().UTC().Format(time.RFC3339Nano),
		},
		Emitter: em,
	})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}

	var records []model.Record
	for _, line := range bytes.Split(bytes.TrimSpace(stdout.Bytes()), []byte("\n")) {
		if len(line) == 0 {
			continue
		}
		var r model.Record
		if err := json.Unmarshal(line, &r); err != nil {
			t.Fatalf("bad ndjson line: %v: %s", err, line)
		}
		if r.RecordType != model.RecordTypePackage {
			t.Errorf("record_type = %q, want %q", r.RecordType, model.RecordTypePackage)
		}
		if r.RecordID == "" {
			t.Errorf("record_id missing on package record: %+v", r)
		}
		records = append(records, r)
	}

	var lockFromProj, lockFromDup, nmRec, pyRec bool
	for _, r := range records {
		switch {
		case r.Ecosystem == "npm" && r.SourceType == "npm-lockfile" && strings.Contains(r.SourceFile, "/proj/"):
			lockFromProj = true
		case r.Ecosystem == "npm" && r.SourceType == "npm-lockfile" && strings.Contains(r.SourceFile, "/dup/"):
			lockFromDup = true
		case r.Ecosystem == "npm" && r.SourceType == "npm-node_modules":
			nmRec = true
			if !r.HasLifecycleScripts {
				t.Errorf("expected lifecycle scripts on node_modules record")
			}
		case r.Ecosystem == "pypi" && r.NormalizedName == "requests":
			pyRec = true
			if r.PackageManager != "pip" {
				t.Errorf("expected pip installer, got %q", r.PackageManager)
			}
		}
	}
	if !lockFromProj || !lockFromDup || !nmRec || !pyRec {
		t.Fatalf("missing expected records: lockProj=%v lockDup=%v nm=%v py=%v records=%d",
			lockFromProj, lockFromDup, nmRec, pyRec, len(records))
	}

	// Sanity on counters.
	if res.RecordsEmitted != len(records) {
		t.Errorf("counter mismatch: %d vs %d", res.RecordsEmitted, len(records))
	}

	// Diagnostics on stderr must be JSON lines, never inventory records.
	for _, line := range bytes.Split(bytes.TrimSpace(stderr.Bytes()), []byte("\n")) {
		if len(line) == 0 {
			continue
		}
		var d model.Diagnostic
		if err := json.Unmarshal(line, &d); err != nil {
			t.Fatalf("stderr line is not a diagnostic: %v: %s", err, line)
		}
		if d.RecordType != "diagnostic" {
			t.Errorf("unexpected record_type %q on stderr", d.RecordType)
		}
	}
}

func TestDedupIdenticalRecords(t *testing.T) {
	root := t.TempDir()
	// Same lockfile contents emitted twice via separate Run calls would
	// dedup at the file level; here we instead emit the same record twice
	// through the emitter directly to lock the contract in place.
	em := output.New(&bytes.Buffer{}, &bytes.Buffer{}, "r")
	r := model.Record{
		Ecosystem:      "npm",
		NormalizedName: "lodash",
		Version:        "4.17.21",
		SourceType:     "npm-lockfile",
		SourceFile:     filepath.Join(root, "x"),
	}
	_, _ = em.Emit(r)
	_, _ = em.Emit(r)
	if em.RecordsEmitted != 1 || em.Duplicates != 1 {
		t.Fatalf("dedup: emitted=%d dup=%d", em.RecordsEmitted, em.Duplicates)
	}
}

// TestPermissionDeniedIsDebugLevelDiagnostic verifies that EACCES /
// EPERM while walking is reported as a structured diagnostic at
// level=debug, not level=warn. macOS TCC denies many subtrees under
// $HOME (Library/ContainerManager, Library/Photos, etc.), and surfacing
// them as warnings made operators believe a healthy scan had failed.
func TestPermissionDeniedIsDebugLevelDiagnostic(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX permission semantics required")
	}
	if os.Geteuid() == 0 {
		t.Skip("root bypasses unix DAC permission checks")
	}
	root := t.TempDir()
	// A scannable file at the top so the walk visits the root normally.
	writeFile(t, filepath.Join(root, "proj", "package-lock.json"),
		`{"lockfileVersion":3,"packages":{"node_modules/lodash":{"version":"4.17.21"}}}`)

	// A directory that the walker will try to enter but cannot read.
	denied := filepath.Join(root, "denied")
	if err := os.MkdirAll(denied, 0o755); err != nil {
		t.Fatal(err)
	}
	// Put something inside so descent is the failing op, not Stat.
	if err := os.WriteFile(filepath.Join(denied, "x"), []byte("y"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(denied, 0); err != nil {
		t.Skipf("cannot chmod 0 in this environment: %v", err)
	}
	// Restore so t.TempDir cleanup works.
	t.Cleanup(func() { _ = os.Chmod(denied, 0o755) })

	stdout := &bytes.Buffer{}
	stderr := &bytes.Buffer{}
	em := output.New(stdout, stderr, "r")
	_, err := Run(context.Background(), Config{
		Roots:       []Root{{Path: root, Kind: model.RootKindProject}},
		Profile:     model.ProfileProject,
		MaxFileSize: 1 << 20,
		Concurrency: 1,
		Emitter:     em,
	})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}

	var diagsForDenied []model.Diagnostic
	for _, line := range bytes.Split(bytes.TrimSpace(stderr.Bytes()), []byte("\n")) {
		if len(line) == 0 {
			continue
		}
		var d model.Diagnostic
		if err := json.Unmarshal(line, &d); err != nil {
			t.Fatalf("bad diagnostic line: %v: %s", err, line)
		}
		if strings.Contains(d.Path, "denied") {
			diagsForDenied = append(diagsForDenied, d)
		}
	}
	if len(diagsForDenied) == 0 {
		t.Fatalf("expected at least one diagnostic for the denied path; stderr=%s", stderr.String())
	}
	for _, d := range diagsForDenied {
		if d.Level != "debug" {
			t.Errorf("permission-denied diagnostic level = %q, want %q (path=%q msg=%q)",
				d.Level, "debug", d.Path, d.Message)
		}
	}
}

// TestMissingRootIsInfoLevelDiagnostic verifies that an absent root path
// (ENOENT) is surfaced as a structured diagnostic at level=info, not warn.
// Default-candidate roots routinely do not exist on individual hosts and a
// warn here used to require per-host whitelisting in fleet pipelines.
func TestMissingRootIsInfoLevelDiagnostic(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX error mapping required")
	}
	missing := filepath.Join(t.TempDir(), "does-not-exist")

	stdout := &bytes.Buffer{}
	stderr := &bytes.Buffer{}
	em := output.New(stdout, stderr, "r")
	_, err := Run(context.Background(), Config{
		Roots:       []Root{{Path: missing, Kind: model.RootKindProject}},
		Profile:     model.ProfileProject,
		MaxFileSize: 1 << 20,
		Concurrency: 1,
		Emitter:     em,
	})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}

	var diagsForMissing []model.Diagnostic
	for _, line := range bytes.Split(bytes.TrimSpace(stderr.Bytes()), []byte("\n")) {
		if len(line) == 0 {
			continue
		}
		var d model.Diagnostic
		if err := json.Unmarshal(line, &d); err != nil {
			t.Fatalf("bad diagnostic line: %v: %s", err, line)
		}
		if strings.Contains(d.Path, "does-not-exist") {
			diagsForMissing = append(diagsForMissing, d)
		}
	}
	if len(diagsForMissing) == 0 {
		t.Fatalf("expected at least one diagnostic for the missing path; stderr=%s", stderr.String())
	}
	for _, d := range diagsForMissing {
		if d.Level != "info" {
			t.Errorf("missing-root diagnostic level = %q, want %q (path=%q msg=%q)",
				d.Level, "info", d.Path, d.Message)
		}
	}
}

// TestFileSymlinkDoesNotExfiltrateOutOfScope verifies that a file-typed
// symlink planted inside a scan root (the supply-chain attack shape: a
// malicious package's postinstall hook drops a symlink at
// node_modules/<pkg>/package.json pointing at an unrelated JSON config
// outside the scan root) does NOT cause the target file's fields to be
// emitted under the npm ecosystem. The walker must skip the symlink so
// the parser never sees it; before the fix, the scanner read through
// the link and emitted a record carrying the target's name/version,
// effectively exfiltrating fields from out-of-tree files via the
// configured records sink.
func TestFileSymlinkDoesNotExfiltrateOutOfScope(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("symlinks require admin on Windows")
	}
	root := t.TempDir()

	// Legitimate in-scope package whose record we still want to see.
	proj := filepath.Join(root, "proj")
	writeFile(t, filepath.Join(proj, "node_modules", "good", "package.json"),
		`{"name":"good","version":"1.0.0"}`)

	// Attacker-controlled out-of-scope JSON file. Field shape matches
	// the parser's expectations so a successful exfil would be obvious.
	outOfScope := filepath.Join(root, "elsewhere", "stolen.json")
	writeFile(t, outOfScope, `{"name":"SHOULD-NOT-LEAK","version":"v-leaked"}`)

	// Plant the symlink under the scan root.
	symlinkPath := filepath.Join(proj, "node_modules", "evil", "package.json")
	if err := os.MkdirAll(filepath.Dir(symlinkPath), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outOfScope, symlinkPath); err != nil {
		t.Skipf("symlink unsupported: %v", err)
	}

	stdout := &bytes.Buffer{}
	em := output.New(stdout, &bytes.Buffer{}, "r")
	_, err := Run(context.Background(), Config{
		Roots:       []Root{{Path: proj, Kind: model.RootKindProject}},
		Profile:     model.ProfileProject,
		MaxFileSize: 1 << 20,
		MaxDuration: 5 * time.Second,
		Concurrency: 2,
		Emitter:     em,
	})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}

	for _, line := range bytes.Split(bytes.TrimRight(stdout.Bytes(), "\n"), []byte{'\n'}) {
		if len(line) == 0 {
			continue
		}
		var r model.Record
		if jerr := json.Unmarshal(line, &r); jerr != nil {
			continue
		}
		if r.RecordType != model.RecordTypePackage {
			continue
		}
		if r.PackageName == "SHOULD-NOT-LEAK" || r.Version == "v-leaked" {
			t.Errorf("out-of-scope field leaked via file symlink: name=%q version=%q source_file=%q",
				r.PackageName, r.Version, r.SourceFile)
		}
		if strings.Contains(r.SourceFile, "/evil/") {
			t.Errorf("symlink path was surfaced as source_file: %q", r.SourceFile)
		}
	}

	if em.RecordsEmitted < 1 {
		t.Errorf("expected at least 1 record from the legitimate package, got %d", em.RecordsEmitted)
	}
}

func TestSymlinkLoopSafety(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("symlinks require admin on Windows")
	}
	root := t.TempDir()
	a := filepath.Join(root, "a")
	b := filepath.Join(root, "a", "b")
	if err := os.MkdirAll(b, 0o755); err != nil {
		t.Fatal(err)
	}
	// Make b/loop point back to a.
	if err := os.Symlink(a, filepath.Join(b, "loop")); err != nil {
		t.Skipf("symlink not supported: %v", err)
	}
	writeFile(t, filepath.Join(a, "package-lock.json"), `{"lockfileVersion":3,"packages":{"node_modules/foo":{"version":"1.0.0"}}}`)

	stdout := &bytes.Buffer{}
	em := output.New(stdout, &bytes.Buffer{}, "r")
	done := make(chan error, 1)
	go func() {
		_, err := Run(context.Background(), Config{
			Roots:       []Root{{Path: root, Kind: model.RootKindProject}},
			Profile:     model.ProfileProject,
			MaxFileSize: 1 << 20,
			MaxDuration: 5 * time.Second,
			Concurrency: 2,
			Emitter:     em,
		})
		done <- err
	}()
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("scan did not terminate; symlink loop suspected")
	}
	if em.RecordsEmitted < 1 {
		t.Errorf("expected at least 1 record, got %d", em.RecordsEmitted)
	}
}
