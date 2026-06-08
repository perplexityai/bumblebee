package output

import (
	"bytes"
	"encoding/json"
	"io"
	"strings"
	"testing"

	"github.com/perplexityai/bumblebee/internal/model"
)

func TestEmitterDedupsWithinRun(t *testing.T) {
	var buf bytes.Buffer
	e := New(&buf, io.Discard, "run-1")
	rec := model.Record{
		Ecosystem: "npm", NormalizedName: "left-pad", Version: "1.0.0",
		SourceType: "npm-lockfile", SourceFile: "/p/package-lock.json",
	}
	if _, err := e.Emit(rec); err != nil {
		t.Fatal(err)
	}
	if _, err := e.Emit(rec); err != nil {
		t.Fatal(err)
	}
	if e.RecordsEmitted != 1 || e.Duplicates != 1 {
		t.Fatalf("emit=%d dup=%d", e.RecordsEmitted, e.Duplicates)
	}
	if got := strings.Count(buf.String(), "\n"); got != 1 {
		t.Fatalf("want one NDJSON line, got %d", got)
	}
}

type closableBuf struct {
	bytes.Buffer
	closed bool
}

func (c *closableBuf) Close() error { c.closed = true; return nil }

func TestEmitterCloseClosesUnderlyingWriter(t *testing.T) {
	cb := &closableBuf{}
	e := New(cb, io.Discard, "run-1")
	if err := e.Close(); err != nil {
		t.Fatal(err)
	}
	if !cb.closed {
		t.Fatal("expected underlying writer to be closed")
	}
}

func TestEmitterCloseNoopOnPlainWriter(t *testing.T) {
	var buf bytes.Buffer
	e := New(&buf, io.Discard, "run-1")
	if err := e.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestEmitDefaultsRecordTypeToPackage(t *testing.T) {
	var buf bytes.Buffer
	e := New(&buf, io.Discard, "run-1")
	rec := model.Record{
		Ecosystem: "npm", NormalizedName: "left-pad", Version: "1.0.0",
		SourceType: "npm-lockfile", SourceFile: "/p/package-lock.json",
	}
	if _, err := e.Emit(rec); err != nil {
		t.Fatal(err)
	}
	var got map[string]any
	if err := json.Unmarshal(bytes.TrimSpace(buf.Bytes()), &got); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if got["record_type"] != model.RecordTypePackage {
		t.Fatalf("record_type = %v, want %q", got["record_type"], model.RecordTypePackage)
	}
	if got["record_id"] == "" {
		t.Fatalf("record_id missing from emitted package record: %v", got)
	}
}

func TestEmitSummaryWritesScanSummaryRecord(t *testing.T) {
	var buf bytes.Buffer
	e := New(&buf, io.Discard, "run-1")
	s := model.ScanSummary{
		SchemaVersion: model.SchemaVersion,
		ScannerName:   model.ScannerName,
		RunID:         "run-1",
		Status:        model.ScanStatusComplete,
	}
	if err := e.EmitSummary(s); err != nil {
		t.Fatal(err)
	}
	var got map[string]any
	if err := json.Unmarshal(bytes.TrimSpace(buf.Bytes()), &got); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if got["record_type"] != model.RecordTypeScanSummary {
		t.Fatalf("record_type = %v, want %q", got["record_type"], model.RecordTypeScanSummary)
	}
	if got["status"] != model.ScanStatusComplete {
		t.Fatalf("status = %v, want %q", got["status"], model.ScanStatusComplete)
	}
	if got["record_id"] == "" {
		t.Fatalf("record_id missing from summary: %v", got)
	}
	// EmitSummary should not bump the records dedup counter.
	if e.RecordsEmitted != 0 {
		t.Fatalf("RecordsEmitted=%d, want 0 (summary is not a package record)", e.RecordsEmitted)
	}
}

func TestQuietSuppressesInfoDiag(t *testing.T) {
	var diagBuf bytes.Buffer
	e := New(io.Discard, &diagBuf, "run-q")
	e.SetQuiet(true)
	e.Diag("info", "", "this should be suppressed")
	if diagBuf.Len() != 0 {
		t.Fatalf("quiet mode: info diag written to stderr, want suppressed; got %q", diagBuf.String())
	}
	if e.Diagnostics != 1 {
		t.Fatalf("Diagnostics counter should still be incremented; got %d", e.Diagnostics)
	}
}

func TestQuietPassesThroughWarnAndError(t *testing.T) {
	var diagBuf bytes.Buffer
	e := New(io.Discard, &diagBuf, "run-q")
	e.SetQuiet(true)
	e.Diag("warn", "", "this warn should appear")
	e.Diag("error", "", "this error should appear")
	lines := strings.Split(strings.TrimSpace(diagBuf.String()), "\n")
	if len(lines) != 2 {
		t.Fatalf("expected 2 diagnostic lines (warn+error), got %d: %q", len(lines), diagBuf.String())
	}
	if !strings.Contains(lines[0], `"warn"`) {
		t.Errorf("first line should be warn diag: %q", lines[0])
	}
	if !strings.Contains(lines[1], `"error"`) {
		t.Errorf("second line should be error diag: %q", lines[1])
	}
}

func TestDefaultModeEmitsInfoDiag(t *testing.T) {
	var diagBuf bytes.Buffer
	e := New(io.Discard, &diagBuf, "run-default")
	e.Diag("info", "", "visible by default")
	if diagBuf.Len() == 0 {
		t.Fatal("default (non-quiet) mode must emit info diagnostics")
	}
	if !strings.Contains(diagBuf.String(), "visible by default") {
		t.Fatalf("expected info message in output, got %q", diagBuf.String())
	}
}

func TestObservePackageDedupsWithoutWriting(t *testing.T) {
	e := New(io.Discard, io.Discard, "run-1")
	rec := model.Record{
		Profile:        model.ProfileBaseline,
		Ecosystem:      model.EcosystemMCP,
		NormalizedName: "mcp-server-time",
		SourceType:     "mcp-config",
		SourceFile:     "/x/mcp.json",
		ServerName:     "time",
	}
	observed, ok := e.ObservePackage(rec)
	if !ok {
		t.Fatal("first observation should not dedup")
	}
	if observed.RecordID == "" {
		t.Fatal("observed record should have record_id")
	}
	if _, ok := e.ObservePackage(rec); ok {
		t.Fatal("second observation should dedup")
	}
	if e.Duplicates != 1 {
		t.Fatalf("Duplicates=%d, want 1", e.Duplicates)
	}
	if e.RecordsEmitted != 0 {
		t.Fatalf("RecordsEmitted=%d, want 0 before write", e.RecordsEmitted)
	}
}
