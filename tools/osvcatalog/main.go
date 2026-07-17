// Command osvcatalog converts offline OSV data into a Bumblebee exposure
// catalog.
//
// It is a maintainer-side tool, not part of the shipped scanner: Bumblebee
// never contacts osv.dev at scan time. Download the OSV data separately,
// then point this tool at a directory tree, a .zip archive, or a single
// .json record.
//
// Recommended source: the OSSF malicious-packages repo
// (https://github.com/ossf/malicious-packages), the upstream
// malicious-only set covering every ecosystem in one tree:
//
//	osvcatalog -o threat_intel/osv-malicious.json /path/to/malicious-packages/osv/malicious/
//
// Also supported: an OSV per-ecosystem dump archive
// (https://osv-vulnerabilities.storage.googleapis.com/<eco>/all.zip),
// from which only malicious-package records are extracted:
//
//	curl -fsSLO https://osv-vulnerabilities.storage.googleapis.com/npm/all.zip
//	osvcatalog -o threat_intel/osv-npm-malicious.json npm/all.zip
//
// Only malicious-package records (MAL- ids, or records aliased to one)
// are emitted, with severity "critical". Vulnerability advisories are
// out of scope. Records whose ranges declare all versions affected are
// emitted with versions ["*"]; records with only bounded ranges and no
// enumerated versions are skipped — see internal/osv.
//
// The output validates against docs/schema/v0.2.0/exposure-catalog.schema.json
// and is consumed by `bumblebee scan --exposure-catalog`.
package main

import (
	"archive/zip"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/perplexityai/bumblebee/internal/osv"
)

func main() {
	if err := run(os.Args[1:], os.Stdout, os.Stderr); err != nil {
		fmt.Fprintln(os.Stderr, "osvcatalog: "+err.Error())
		os.Exit(1)
	}
}

func run(args []string, stdout, stderr io.Writer) error {
	fs := flag.NewFlagSet("osvcatalog", flag.ContinueOnError)
	fs.SetOutput(stderr)
	out := fs.String("o", "", "output catalog path (default stdout)")
	ecoFlag := fs.String("ecosystem", "", "restrict to these Bumblebee ecosystems (comma-separated: npm,pypi,go,rubygems,packagist,editor-extension)")
	maxFileSize := fs.Int64("max-file-size", 5*1024*1024, "max bytes to read from any single OSV JSON record")
	source := fs.String("source", "", "optional provenance label (e.g. repo URL or snapshot date) stamped into the generated catalog's _comment")
	fs.Usage = func() {
		fmt.Fprintf(stderr, "Usage: osvcatalog [flags] <path>...\n\n"+
			"Each <path> is a directory tree (walked for .json/.zip), an OSV all.zip\n"+
			"archive, or an individual OSV .json record. Only malicious-package (MAL-)\n"+
			"records are emitted. Bumblebee does not fetch OSV at scan time; download\n"+
			"first from https://github.com/ossf/malicious-packages or\n"+
			"https://osv-vulnerabilities.storage.googleapis.com/.\n\nFlags:\n")
		fs.PrintDefaults()
	}
	if err := fs.Parse(args); err != nil {
		return err
	}
	paths := fs.Args()
	if len(paths) == 0 {
		fs.Usage()
		return fmt.Errorf("at least one input path is required")
	}

	opts := osv.Options{
		Ecosystems: parseEcosystems(*ecoFlag),
		Source:     strings.TrimSpace(*source),
	}

	var records []osv.Record
	for _, p := range paths {
		recs, err := loadPath(p, *maxFileSize, stderr)
		if err != nil {
			return err
		}
		records = append(records, recs...)
	}

	entries, st := osv.Convert(records, opts)
	catalog := osv.BuildCatalog(entries, opts, st)

	data, err := json.MarshalIndent(catalog, "", "  ")
	if err != nil {
		return err
	}
	data = append(data, '\n')
	if *out == "" {
		_, err = stdout.Write(data)
	} else {
		err = os.WriteFile(*out, data, 0o644)
	}
	if err != nil {
		return err
	}
	fmt.Fprintf(stderr, "osvcatalog: %d entries (%d any-version) from %d records (skipped: %d non-malicious, %d no-versions, %d unsupported-ecosystem, %d withdrawn, %d bad-id)\n",
		st.Entries, st.AnyVersionEntries, st.RecordsSeen, st.SkippedNotMalicious, st.SkippedNoVersions, st.SkippedEcosystem, st.SkippedWithdrawn, st.SkippedBadID)
	return nil
}

func parseEcosystems(s string) map[string]bool {
	s = strings.TrimSpace(s)
	if s == "" {
		return nil
	}
	out := map[string]bool{}
	for _, part := range strings.Split(s, ",") {
		if part = strings.TrimSpace(part); part != "" {
			out[strings.ToLower(part)] = true
		}
	}
	return out
}

// loadPath reads OSV records from a .zip, a directory, or a single .json
// file. Unreadable or non-OSV-shaped files are reported to stderr and
// skipped rather than aborting the whole import.
func loadPath(path string, maxSize int64, stderr io.Writer) ([]osv.Record, error) {
	info, err := os.Stat(path)
	if err != nil {
		return nil, err
	}
	switch {
	case info.IsDir():
		var records []osv.Record
		err := filepath.WalkDir(path, func(p string, d os.DirEntry, err error) error {
			// Per the contract, unreadable entries are reported and skipped
			// rather than aborting the whole import.
			if err != nil {
				fmt.Fprintf(stderr, "osvcatalog: skipping %s: %v\n", p, err)
				return nil
			}
			if d.IsDir() {
				return nil
			}
			switch strings.ToLower(filepath.Ext(p)) {
			case ".zip":
				recs, zerr := loadZip(p, maxSize, stderr)
				if zerr != nil {
					fmt.Fprintf(stderr, "osvcatalog: skipping %s: %v\n", p, zerr)
					return nil
				}
				records = append(records, recs...)
			case ".json":
				if rec, ok := loadJSONFile(p, maxSize, stderr); ok {
					records = append(records, rec)
				}
			}
			return nil
		})
		return records, err
	case strings.EqualFold(filepath.Ext(path), ".zip"):
		return loadZip(path, maxSize, stderr)
	default:
		if rec, ok := loadJSONFile(path, maxSize, stderr); ok {
			return []osv.Record{rec}, nil
		}
		return nil, nil
	}
}

func loadZip(path string, maxSize int64, stderr io.Writer) ([]osv.Record, error) {
	zr, err := zip.OpenReader(path)
	if err != nil {
		return nil, err
	}
	defer zr.Close()
	var records []osv.Record
	for _, f := range zr.File {
		if f.FileInfo().IsDir() || !strings.EqualFold(filepath.Ext(f.Name), ".json") {
			continue
		}
		if maxSize > 0 && int64(f.UncompressedSize64) > maxSize {
			fmt.Fprintf(stderr, "osvcatalog: skipping %s!%s: %d bytes exceeds max %d\n", path, f.Name, f.UncompressedSize64, maxSize)
			continue
		}
		rc, err := f.Open()
		if err != nil {
			fmt.Fprintf(stderr, "osvcatalog: skipping %s!%s: %v\n", path, f.Name, err)
			continue
		}
		data, err := readLimited(rc, maxSize)
		rc.Close()
		if err != nil {
			fmt.Fprintf(stderr, "osvcatalog: skipping %s!%s: %v\n", path, f.Name, err)
			continue
		}
		// Defensive post-read length check. archive/zip will normally surface
		// a size mismatch against the central directory as a read error above,
		// so this rarely fires in practice; kept as belt-and-suspenders for
		// malformed archives where pre-read size could not be trusted.
		if maxSize > 0 && int64(len(data)) > maxSize {
			fmt.Fprintf(stderr, "osvcatalog: skipping %s!%s: exceeds max %d bytes\n", path, f.Name, maxSize)
			continue
		}
		var rec osv.Record
		if err := json.Unmarshal(data, &rec); err != nil || rec.ID == "" {
			fmt.Fprintf(stderr, "osvcatalog: skipping %s!%s: not a valid OSV record\n", path, f.Name)
			continue
		}
		records = append(records, rec)
	}
	return records, nil
}

func loadJSONFile(path string, maxSize int64, stderr io.Writer) (osv.Record, bool) {
	f, err := os.Open(path)
	if err != nil {
		fmt.Fprintf(stderr, "osvcatalog: skipping %s: %v\n", path, err)
		return osv.Record{}, false
	}
	defer f.Close()
	data, err := readLimited(f, maxSize)
	if err != nil {
		fmt.Fprintf(stderr, "osvcatalog: skipping %s: %v\n", path, err)
		return osv.Record{}, false
	}
	if maxSize > 0 && int64(len(data)) > maxSize {
		fmt.Fprintf(stderr, "osvcatalog: skipping %s: exceeds max %d bytes\n", path, maxSize)
		return osv.Record{}, false
	}
	var rec osv.Record
	if err := json.Unmarshal(data, &rec); err != nil || rec.ID == "" {
		fmt.Fprintf(stderr, "osvcatalog: skipping %s: not a valid OSV record\n", path)
		return osv.Record{}, false
	}
	return rec, true
}

// readLimited reads from r honoring maxSize. maxSize <= 0 means
// unbounded (matching internal/exposure.LoadFile semantics); maxSize > 0
// caps the read at maxSize+1 bytes so the caller can detect overflow.
func readLimited(r io.Reader, maxSize int64) ([]byte, error) {
	if maxSize <= 0 {
		return io.ReadAll(r)
	}
	return io.ReadAll(io.LimitReader(r, maxSize+1))
}
