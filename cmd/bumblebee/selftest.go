package main

import (
	"context"
	"embed"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"time"

	"github.com/perplexityai/bumblebee/internal/endpoint"
	"github.com/perplexityai/bumblebee/internal/exposure"
	"github.com/perplexityai/bumblebee/internal/model"
	"github.com/perplexityai/bumblebee/internal/output"
	"github.com/perplexityai/bumblebee/internal/scanner"
)

//go:embed selftest/fixtures selftest/catalog.json
var selftestFS embed.FS

// expectedSelftestFindings is the count of catalog-matched findings the
// embedded fixtures must produce. One npm package-lock.json entry, one
// PyPI dist-info METADATA file, and one MCP config naming a pinned
// docker image — each matched against the embedded catalog: three
// findings. The MCP fixture guards against regressions in the MCP
// parser/scanner integration (basename dispatch, docker tag split,
// catalog matching for the mcp ecosystem).
const expectedSelftestFindings = 3

// runSelftest extracts the embedded fixture tree to a temp directory,
// runs the scanner with the embedded exposure catalog, and asserts the
// scan emits exactly expectedSelftestFindings findings.
//
// Intended uses:
//   - First-install smoke test on an adopter machine.
//   - CI end-to-end check that the build still detects what it should.
//
// runSelftest is deterministic, makes no network calls, and never reads
// outside its own temp directory.
func runSelftest(args []string) int {
	fs := flag.NewFlagSet("selftest", flag.ExitOnError)
	var quiet bool
	fs.BoolVar(&quiet, "quiet", false, "suppress per-step status output")
	_ = fs.Parse(args)

	start := time.Now()

	tmp, err := os.MkdirTemp("", "bumblebee-selftest-*")
	if err != nil {
		fmt.Fprintf(os.Stderr, "selftest: mktemp: %v\n", err)
		return 1
	}
	defer os.RemoveAll(tmp)

	if err := extractEmbeddedTree(selftestFS, "selftest/fixtures", tmp); err != nil {
		fmt.Fprintf(os.Stderr, "selftest: extract fixtures: %v\n", err)
		return 1
	}

	catalogData, err := selftestFS.ReadFile("selftest/catalog.json")
	if err != nil {
		fmt.Fprintf(os.Stderr, "selftest: read embedded catalog: %v\n", err)
		return 1
	}
	catalog, err := exposure.Parse(catalogData)
	if err != nil {
		fmt.Fprintf(os.Stderr, "selftest: parse embedded catalog: %v\n", err)
		return 1
	}

	runID := newRunID()
	emitter := output.New(io.Discard, io.Discard, runID)
	base := model.Record{
		RecordType:     model.RecordTypePackage,
		SchemaVersion:  model.SchemaVersion,
		ScannerName:    model.ScannerName,
		ScannerVersion: currentVersion(),
		RunID:          runID,
		ScanTime:       start.UTC().Format(time.RFC3339Nano),
		Endpoint:       endpoint.Current(""),
		Profile:        model.ProfileProject,
	}

	cfg := scanner.Config{
		Profile:     model.ProfileProject,
		Roots:       []scanner.Root{{Path: tmp, Kind: model.RootKindProject}},
		MaxFileSize: 16 * 1024 * 1024,
		Concurrency: 2,
		Catalog:     catalog,
		BaseRecord:  base,
		Emitter:     emitter,
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	res, runErr := scanner.Run(ctx, cfg)
	if runErr != nil {
		fmt.Fprintf(os.Stderr, "selftest: scan failed: %v\n", runErr)
		return 1
	}

	if res.FindingsEmitted != expectedSelftestFindings {
		fmt.Fprintf(os.Stderr,
			"selftest FAILED: got %d findings (records=%d files=%d), want %d\n",
			res.FindingsEmitted, res.RecordsEmitted, res.FilesConsidered, expectedSelftestFindings)
		return 1
	}

	if !quiet {
		fmt.Printf("selftest OK (%d findings in %s)\n",
			res.FindingsEmitted, time.Since(start).Round(time.Millisecond))
	}
	return 0
}

// extractEmbeddedTree copies every file under src in efs to dst on
// disk, preserving subdirectory structure. Files are written 0644 and
// directories 0755 — the scanner only needs to read them.
func extractEmbeddedTree(efs embed.FS, src, dst string) error {
	return fs.WalkDir(efs, src, func(p string, d fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		rel, err := filepath.Rel(src, p)
		if err != nil {
			return err
		}
		target := filepath.Join(dst, rel)
		if d.IsDir() {
			return os.MkdirAll(target, 0o755)
		}
		data, err := efs.ReadFile(p)
		if err != nil {
			return err
		}
		if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
			return err
		}
		return os.WriteFile(target, data, 0o644)
	})
}
