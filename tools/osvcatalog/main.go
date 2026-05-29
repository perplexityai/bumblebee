// Command osvcatalog converts offline OSV data into a Bumblebee exposure
// catalog.
//
// It is a maintainer-side tool, not part of the shipped scanner: Bumblebee
// never contacts osv.dev at scan time. Download the OSV data separately,
// then point this tool at the .zip archives, directories, or .json
// records.
//
// The OSV per-ecosystem dumps are the convenient source and cover both
// malicious packages and vulnerabilities:
//
//	curl -fsSLO https://osv-vulnerabilities.storage.googleapis.com/npm/all.zip
//	osvcatalog -o threat_intel/osv-malicious.json npm/all.zip
//
// The OSSF malicious-packages repo (https://github.com/ossf/malicious-packages)
// is the upstream malicious-only set; clone it and point at its osv/ tree.
//
// By default only malicious-package records (`MAL-` ids) are emitted.
// Pass -include-vulns to widen to every OSV record with an enumerated
// affected-version list. Records whose only version information is a
// range (no enumerated versions) are skipped — see internal/osv.
//
// The output validates against docs/schema/v0.1.0/exposure-catalog.schema.json
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
	ecoFlag := fs.String("ecosystem", "", "restrict to these Bumblebee ecosystems (comma-separated: npm,pypi,go,rubygems,packagist)")
	includeVulns := fs.Bool("include-vulns", false, "include all OSV records with enumerated versions, not just malicious (MAL-) packages")
	maxFileSize := fs.Int64("max-file-size", 5*1024*1024, "max bytes to read from any single OSV JSON record")
	fs.Usage = func() {
		fmt.Fprintf(stderr, "Usage: osvcatalog [flags] <path>...\n\n"+
			"Each <path> is an OSV all.zip archive, a directory (walked for .json/.zip),\n"+
			"or an individual OSV .json record. Bumblebee does not fetch OSV at scan time;\n"+
			"download the data first from https://osv-vulnerabilities.storage.googleapis.com/.\n\nFlags:\n")
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
		IncludeVulns: *includeVulns,
		Ecosystems:   parseEcosystems(*ecoFlag),
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
	fmt.Fprintf(stderr, "osvcatalog: %d entries from %d records (skipped: %d non-malicious, %d no-versions, %d unsupported-ecosystem, %d withdrawn)\n",
		st.Entries, st.RecordsSeen, st.SkippedNotMalicious, st.SkippedNoVersions, st.SkippedEcosystem, st.SkippedWithdrawn)
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
			if err != nil || d.IsDir() {
				return err
			}
			switch strings.ToLower(filepath.Ext(p)) {
			case ".zip":
				recs, zerr := loadZip(p, maxSize, stderr)
				if zerr != nil {
					return zerr
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
		data, err := io.ReadAll(io.LimitReader(rc, maxSize+1))
		rc.Close()
		if err != nil {
			fmt.Fprintf(stderr, "osvcatalog: skipping %s!%s: %v\n", path, f.Name, err)
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
	data, err := io.ReadAll(io.LimitReader(f, maxSize+1))
	if err != nil {
		fmt.Fprintf(stderr, "osvcatalog: skipping %s: %v\n", path, err)
		return osv.Record{}, false
	}
	if int64(len(data)) > maxSize {
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
