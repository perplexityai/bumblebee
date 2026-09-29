package output

import (
	"bytes"
	"compress/gzip"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/perplexityai/bumblebee/internal/model"
)

func TestHTTPSink_RejectsPlainHTTPToRemote(t *testing.T) {
	_, err := NewHTTPSink(HTTPConfig{URL: "http://example.com/ingest"})
	if err == nil || !strings.Contains(err.Error(), "refusing plain http") {
		t.Fatalf("expected plain-http refusal, got %v", err)
	}
}

func TestHTTPSink_AllowsLoopbackPlainHTTP(t *testing.T) {
	if _, err := NewHTTPSink(HTTPConfig{URL: "http://127.0.0.1:8080/ingest"}); err != nil {
		t.Fatalf("loopback http should be allowed: %v", err)
	}
	if _, err := NewHTTPSink(HTTPConfig{URL: "http://localhost:8080/ingest"}); err != nil {
		t.Fatalf("localhost http should be allowed: %v", err)
	}
}

func TestHTTPSink_RequiresAuthCredentials(t *testing.T) {
	if _, err := NewHTTPSink(HTTPConfig{URL: "https://example.com", Auth: HTTPAuth{Mode: "bearer"}}); err == nil {
		t.Fatal("expected error for bearer with empty token")
	}
	if _, err := NewHTTPSink(HTTPConfig{URL: "https://example.com", Auth: HTTPAuth{Mode: "hmac-sha256"}}); err == nil {
		t.Fatal("expected error for hmac with empty key")
	}
	if _, err := NewHTTPSink(HTTPConfig{URL: "https://example.com", Auth: HTTPAuth{Mode: "nonsense"}}); err == nil {
		t.Fatal("expected error for unknown auth mode")
	}
}

type captured struct {
	mu      sync.Mutex
	headers []http.Header
	bodies  [][]byte
}

func (c *captured) handler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		c.mu.Lock()
		c.headers = append(c.headers, r.Header.Clone())
		c.bodies = append(c.bodies, body)
		c.mu.Unlock()
		w.WriteHeader(http.StatusOK)
	}
}

func TestHTTPSink_BearerAuth_BatchAndFlush(t *testing.T) {
	cap := &captured{}
	srv := httptest.NewServer(cap.handler())
	defer srv.Close()

	sink, err := NewHTTPSink(HTTPConfig{
		URL:       srv.URL,
		Auth:      HTTPAuth{Mode: "bearer", Token: "shh"},
		BatchSize: 2,
		UserAgent: "bumblebee/test",
	})
	if err != nil {
		t.Fatal(err)
	}

	e := New(sink, io.Discard, "run-1")
	for i := range 3 {
		if _, err := e.Emit(model.Record{
			Ecosystem:      "npm",
			NormalizedName: "a",
			Version:        []string{"1.0.0", "1.0.1", "1.0.2"}[i],
			SourceType:     "npm-lockfile",
			SourceFile:     "/x",
		}); err != nil {
			t.Fatalf("emit %d: %v", i, err)
		}
	}
	if err := e.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}

	if len(cap.bodies) != 2 {
		t.Fatalf("want 2 POSTs (batch=2 + flush), got %d", len(cap.bodies))
	}
	// First batch: 2 lines. Second: 1.
	if got := bytes.Count(cap.bodies[0], []byte{'\n'}); got != 2 {
		t.Fatalf("first batch lines = %d, want 2", got)
	}
	if got := bytes.Count(cap.bodies[1], []byte{'\n'}); got != 1 {
		t.Fatalf("second batch lines = %d, want 1", got)
	}
	for _, h := range cap.headers {
		if h.Get("Authorization") != "Bearer shh" {
			t.Errorf("missing/incorrect bearer header: %q", h.Get("Authorization"))
		}
		if h.Get("Content-Type") != contentTypeNDJSON {
			t.Errorf("bad content-type: %q", h.Get("Content-Type"))
		}
		if h.Get("User-Agent") != "bumblebee/test" {
			t.Errorf("bad user-agent: %q", h.Get("User-Agent"))
		}
	}
	stats := sink.Stats()
	if stats.HTTPBatchesAttempted != 2 || stats.HTTPBatchesSucceeded != 2 || stats.HTTPBatchesFailed != 0 || stats.HTTPLastStatus != http.StatusOK {
		t.Fatalf("unexpected sink stats: %+v", stats)
	}
}

func TestHTTPSink_HMACSignsBody(t *testing.T) {
	cap := &captured{}
	srv := httptest.NewServer(cap.handler())
	defer srv.Close()

	key := []byte("supersecret")
	sink, err := NewHTTPSink(HTTPConfig{
		URL: srv.URL,
		Auth: HTTPAuth{
			Mode:            "hmac-sha256",
			HMACKey:         key,
			TimestampHeader: "X-Inventory-Timestamp",
		},
		BatchSize: 10,
	})
	if err != nil {
		t.Fatal(err)
	}

	e := New(sink, io.Discard, "run-1")
	if _, err := e.Emit(model.Record{
		Ecosystem: "npm", NormalizedName: "left-pad", Version: "1.0.0",
		SourceType: "npm-lockfile", SourceFile: "/x",
	}); err != nil {
		t.Fatal(err)
	}
	if err := e.Close(); err != nil {
		t.Fatal(err)
	}
	if len(cap.bodies) != 1 {
		t.Fatalf("want 1 POST, got %d", len(cap.bodies))
	}
	ts := cap.headers[0].Get("X-Inventory-Timestamp")
	if ts == "" {
		t.Fatal("missing timestamp header")
	}
	sig := cap.headers[0].Get("X-Inventory-Signature")
	if !strings.HasPrefix(sig, "sha256=") {
		t.Fatalf("missing/incorrect signature header: %q", sig)
	}
	mac := hmac.New(sha256.New, key)
	mac.Write([]byte(ts + "."))
	mac.Write(cap.bodies[0])
	want := "sha256=" + hex.EncodeToString(mac.Sum(nil))
	if sig != want {
		t.Fatalf("signature mismatch:\n got %s\nwant %s", sig, want)
	}
}

// TestHTTPSink_GzipEncodesBody verifies that --http-gzip puts gzip on
// the wire (Content-Encoding header + inflatable body) and that the
// inflated body matches what the emitter produced. This is the path
// that lets fleet-scale deployments cut ingest bytes 8-15x without
// changing the record schema.
func TestHTTPSink_GzipEncodesBody(t *testing.T) {
	cap := &captured{}
	srv := httptest.NewServer(cap.handler())
	defer srv.Close()

	sink, err := NewHTTPSink(HTTPConfig{
		URL:       srv.URL,
		BatchSize: 10,
		Gzip:      true,
	})
	if err != nil {
		t.Fatal(err)
	}
	e := New(sink, io.Discard, "run-1")
	for i := range 3 {
		if _, err := e.Emit(model.Record{
			Ecosystem:      "npm",
			NormalizedName: "lodash",
			Version:        []string{"1.0.0", "1.0.1", "1.0.2"}[i],
			SourceType:     "npm-lockfile",
			SourceFile:     "/x",
		}); err != nil {
			t.Fatal(err)
		}
	}
	if err := e.Close(); err != nil {
		t.Fatal(err)
	}
	if len(cap.bodies) != 1 {
		t.Fatalf("want 1 POST, got %d", len(cap.bodies))
	}
	if ce := cap.headers[0].Get("Content-Encoding"); ce != "gzip" {
		t.Fatalf("Content-Encoding = %q, want %q", ce, "gzip")
	}
	if ct := cap.headers[0].Get("Content-Type"); ct != contentTypeNDJSON {
		t.Fatalf("Content-Type = %q, want %q", ct, contentTypeNDJSON)
	}
	zr, err := gzip.NewReader(bytes.NewReader(cap.bodies[0]))
	if err != nil {
		t.Fatalf("body is not gzip: %v", err)
	}
	inflated, err := io.ReadAll(zr)
	if err != nil {
		t.Fatalf("inflate: %v", err)
	}
	if got := bytes.Count(inflated, []byte{'\n'}); got != 3 {
		t.Fatalf("inflated NDJSON lines = %d, want 3 (body=%q)", got, inflated)
	}
}

// TestHTTPSink_GzipPlusHMACSignsCompressedBody pins down the auth/gzip
// interaction: with both enabled, the signature must be over the
// on-the-wire bytes, since that is what the receiver verifies before
// inflating. Changing this would break receiver implementations.
func TestHTTPSink_GzipPlusHMACSignsCompressedBody(t *testing.T) {
	cap := &captured{}
	srv := httptest.NewServer(cap.handler())
	defer srv.Close()

	key := []byte("k")
	sink, err := NewHTTPSink(HTTPConfig{
		URL: srv.URL,
		Auth: HTTPAuth{
			Mode:            "hmac-sha256",
			HMACKey:         key,
			TimestampHeader: "X-Inventory-Timestamp",
		},
		BatchSize: 10,
		Gzip:      true,
	})
	if err != nil {
		t.Fatal(err)
	}
	e := New(sink, io.Discard, "run-1")
	if _, err := e.Emit(model.Record{
		Ecosystem: "npm", NormalizedName: "lodash", Version: "1",
		SourceType: "npm-lockfile", SourceFile: "/x",
	}); err != nil {
		t.Fatal(err)
	}
	if err := e.Close(); err != nil {
		t.Fatal(err)
	}
	if len(cap.bodies) != 1 {
		t.Fatalf("want 1 POST, got %d", len(cap.bodies))
	}
	ts := cap.headers[0].Get("X-Inventory-Timestamp")
	if ts == "" {
		t.Fatal("missing timestamp header")
	}
	mac := hmac.New(sha256.New, key)
	mac.Write([]byte(ts + "."))
	mac.Write(cap.bodies[0]) // compressed body, exactly as POSTed
	want := "sha256=" + hex.EncodeToString(mac.Sum(nil))
	if got := cap.headers[0].Get("X-Inventory-Signature"); got != want {
		t.Fatalf("signature mismatch\n got %s\nwant %s", got, want)
	}
}

func TestHTTPSink_Non2xxIsError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte("boom"))
	}))
	defer srv.Close()

	sink, err := NewHTTPSink(HTTPConfig{URL: srv.URL, BatchSize: 1})
	if err != nil {
		t.Fatal(err)
	}
	e := New(sink, io.Discard, "run-1")
	_, _ = e.Emit(model.Record{
		Ecosystem: "npm", NormalizedName: "a", Version: "1",
		SourceType: "npm-lockfile", SourceFile: "/x",
	})
	closeErr := e.Close()
	// Either Emit or Close should surface the server error; the sink
	// caches the error on Write so subsequent operations fail too.
	if closeErr == nil && sink.err == nil {
		t.Fatal("expected error from non-2xx server response")
	}
	stats := sink.Stats()
	if stats.HTTPBatchesAttempted != 1 || stats.HTTPBatchesSucceeded != 0 || stats.HTTPBatchesFailed != 1 || stats.HTTPLastStatus != http.StatusInternalServerError {
		t.Fatalf("unexpected sink stats after non-2xx: %+v", stats)
	}
}
