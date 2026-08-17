// Package exposure loads an operator-supplied package exposure catalog and
// matches discovered package observations against it.
//
// The catalog describes packages whose mere presence on an endpoint is the
// signal of interest — typically the (ecosystem, name, version) tuples
// published by a recent supply-chain compromise advisory. It is not an
// IOC feed for network indicators, dropped files, or process behavior;
// those are EDR concerns and live outside this scanner.
//
// Matching is exact: a package record matches a catalog entry when
// ecosystem and normalized name are equal and the package version equals
// one of the catalog entry's versions. As of schema v0.2 an entry may
// instead declare versions ["*"], which matches every version of the
// package (including records with no version). Version ranges, hash
// matching, and integrity-based matching remain out of scope.
//
// A catalog may also carry an operator allow-list (schema v0.2+): the
// same (ecosystem, name, versions) shape, listing hits that must NOT
// produce findings (confirmed false positives). The allow-list is
// applied after matching, so it suppresses hits from every loaded
// catalog file, not only the file that declares it.
package exposure

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/perplexityai/bumblebee/internal/model"
	"github.com/perplexityai/bumblebee/internal/normalize"
)

// AnyVersion is the wildcard versions value that matches every version
// of a package. Requires catalog schema_version 0.2.0 or later.
const AnyVersion = "*"

// Catalog is a parsed exposure catalog.
//
// Concurrent reads via Match are safe; no mutation is performed after
// Load returns.
type Catalog struct {
	SchemaVersion string
	Entries       []Entry
	// Allowlist holds the operator allow-list entries (schema v0.2+).
	// A record covered by any allow-list entry never yields a Match.
	Allowlist []Entry

	// index is (ecosystem|normalized_name) -> slice of entries that
	// declare that (ecosystem, name). Built once at load time.
	index map[string][]*Entry
	// allow is the same index shape, built from Allowlist.
	allow map[string][]*Entry
}

// Entry is one exposure catalog item.
//
// Required fields: ID, Ecosystem, Package, Versions. Versions are matched
// exactly against a discovered package's Version field; any of the
// listed strings is sufficient for a hit. The single-element list ["*"]
// (schema v0.2+) matches any version.
//
// Optional Name is a free-form human label echoed onto findings as
// `catalog_name`; it is not used for matching.
//
// Optional Severity is a free-form label echoed onto the finding (e.g.
// "critical", "high", "info"). It is not interpreted by the scanner.
//
// Allow-list items use the same shape. There, Name is the place to
// record why the package is allow-listed; Severity is ignored.
type Entry struct {
	ID        string   `json:"id"`
	Name      string   `json:"name,omitempty"`
	Ecosystem string   `json:"ecosystem"`
	Package   string   `json:"package"`
	Versions  []string `json:"versions"`
	Severity  string   `json:"severity,omitempty"`

	normalized string
	anyVersion bool
}

// AnyVersion reports whether the entry matches every version of its
// package (versions declared as ["*"]).
func (e *Entry) AnyVersion() bool {
	return e.anyVersion
}

// Match reports whether record matches any catalog entry, and returns the
// first matched entry plus the matching version string (which equals
// record's Version on success — duplicated for explicit evidence on
// findings).
//
// On a miss both pointers are nil. Use MatchAll when overlapping catalog
// entries can cover the same (ecosystem, name, version) and every hit
// must be surfaced (e.g. one catalog file per advisory).
func (c *Catalog) Match(r model.Record) (*Entry, string) {
	hits := c.MatchAll(r)
	if len(hits) == 0 {
		return nil, ""
	}
	return hits[0].Entry, hits[0].Version
}

// Match is a single (entry, matched-version) pair returned by MatchAll.
// For an any-version entry, Version is the record's version (possibly
// empty) rather than a catalog string.
type Match struct {
	Entry   *Entry
	Version string
}

// MatchAll returns every catalog entry that matches r. With one catalog
// file per advisory, overlapping advisories on the same package/version
// are realistic; the scanner emits one finding per returned Match so an
// overlap is never silently masked. Order follows catalog load order
// (alphabetical-by-filename when loaded from a directory).
//
// Records covered by the allow-list never match; use Allowlisted to
// see the hits the allow-list suppressed.
func (c *Catalog) MatchAll(r model.Record) []Match {
	if c == nil || c.allowlisted(r) {
		return nil
	}
	return matchIndex(c.index, r)
}

// Allowlisted returns the catalog hits for r that the allow-list
// suppressed. It is empty when r is not allow-listed or would not have
// matched anyway, so callers can count real suppressions.
func (c *Catalog) Allowlisted(r model.Record) []Match {
	if c == nil || !c.allowlisted(r) {
		return nil
	}
	return matchIndex(c.index, r)
}

func (c *Catalog) allowlisted(r model.Record) bool {
	return len(matchIndex(c.allow, r)) > 0
}

func matchIndex(index map[string][]*Entry, r model.Record) []Match {
	if len(index) == 0 {
		return nil
	}
	hits, ok := index[r.Ecosystem+"\x00"+r.NormalizedName]
	if !ok {
		return nil
	}
	var out []Match
	for _, e := range hits {
		if e.anyVersion {
			out = append(out, Match{Entry: e, Version: r.Version})
			continue
		}
		for _, v := range e.Versions {
			if v == r.Version {
				out = append(out, Match{Entry: e, Version: v})
				break
			}
		}
	}
	return out
}

// Len is the entry count, useful for diagnostics.
func (c *Catalog) Len() int {
	if c == nil {
		return 0
	}
	return len(c.Entries)
}

// Load reads an exposure catalog from path. If path points at a regular
// file, it behaves exactly like LoadFile. If path points at a directory,
// every *.json file directly inside is loaded and the entries are
// merged into a single Catalog. Subdirectories and non-.json files are
// ignored; loading order is alphabetical by filename for predictable
// diagnostics. All catalogs in the directory must declare the same
// schema_version. maxSize is applied to each file individually.
//
// Directory mode is convenient for operators who maintain one catalog
// per advisory (e.g. one file per supply-chain campaign) and want to
// point `--exposure-catalog` at the whole directory rather than
// concatenating files.
func Load(path string, maxSize int64) (*Catalog, error) {
	info, err := os.Stat(path)
	if err != nil {
		return nil, fmt.Errorf("read exposure catalog: %w", err)
	}
	if !info.IsDir() {
		return LoadFile(path, maxSize)
	}
	return loadDir(path, maxSize)
}

func loadDir(path string, maxSize int64) (*Catalog, error) {
	entries, err := os.ReadDir(path)
	if err != nil {
		return nil, fmt.Errorf("read exposure catalog dir %s: %w", path, err)
	}
	names := make([]string, 0, len(entries))
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		if !strings.HasSuffix(strings.ToLower(e.Name()), ".json") {
			continue
		}
		// Resolve symlinks so a symlink-to-dir is treated like a
		// subdirectory (skipped) rather than handed to LoadFile and
		// erroring the whole load. Dangling symlinks fall through to
		// LoadFile so the per-file error names the offender.
		if e.Type()&os.ModeSymlink != 0 {
			if target, err := os.Stat(filepath.Join(path, e.Name())); err == nil && target.IsDir() {
				continue
			}
		}
		names = append(names, e.Name())
	}
	sort.Strings(names)

	var combined, allow []Entry
	var schemaVersion string
	var firstSource string
	for _, name := range names {
		sub := filepath.Join(path, name)
		c, err := LoadFile(sub, maxSize)
		if err != nil {
			return nil, fmt.Errorf("exposure catalog %s: %w", sub, err)
		}
		if schemaVersion == "" {
			schemaVersion = c.SchemaVersion
			firstSource = sub
		} else if c.SchemaVersion != "" && c.SchemaVersion != schemaVersion {
			return nil, fmt.Errorf("exposure catalog %s declares schema_version %q which conflicts with %q from %s", sub, c.SchemaVersion, schemaVersion, firstSource)
		}
		combined = append(combined, c.Entries...)
		allow = append(allow, c.Allowlist...)
	}
	if schemaVersion == "" {
		// Empty directory or all-empty files. Return an empty catalog
		// rather than erroring; matches single-file empty-input semantics.
		return &Catalog{index: map[string][]*Entry{}}, nil
	}
	return build(schemaVersion, combined, allow)
}

// LoadFile reads a JSON exposure catalog from disk and returns it. The
// catalog must be a JSON object of the form:
//
//	{ "schema_version": "0.1.0", "entries": [ {Entry}, ... ] }
//
// Both `schema_version` and `entries` are required to match the published
// JSON schema. An empty entries array is a valid zero-entry catalog. An
// optional `allowlist` array (schema v0.2+) holds entries in the same
// shape whose hits are suppressed.
// Completely empty / whitespace-only files are accepted as a no-op for
// placeholder-before-first-publish workflows.
//
// maxSize bounds the read in bytes. A value of 0 or less means
// unbounded. Files larger than maxSize return an error without being
// read into memory, matching the per-ecosystem readBounded discipline.
//
// LoadFile errors if path is a directory; use Load for the file-or-dir
// auto-detect entry point used by the CLI.
func LoadFile(path string, maxSize int64) (*Catalog, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("read exposure catalog: %w", err)
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		return nil, fmt.Errorf("read exposure catalog: %w", err)
	}
	if !info.Mode().IsRegular() {
		return nil, errors.New("read exposure catalog: not a regular file")
	}
	if maxSize > 0 && info.Size() > maxSize {
		return nil, fmt.Errorf("exposure catalog %s exceeds max size %d bytes (file is %d)", path, maxSize, info.Size())
	}
	data, err := io.ReadAll(f)
	if err != nil {
		return nil, fmt.Errorf("read exposure catalog: %w", err)
	}
	return Parse(data)
}

// Parse builds a Catalog from raw JSON bytes. Exposed separately so
// tests and embeddings can avoid touching disk.
//
// Accepted shapes:
//
//   - wrapped: { "schema_version": "0.1.0", "entries": [ {Entry}, ... ] }
//   - empty file: "", "  " (whitespace-only)
//
// The root must be a JSON object that carries BOTH `schema_version`
// and `entries`. Objects missing either key are rejected — this matches
// the published JSON schema, which marks both as required. A bare
// top-level array is rejected. An empty/whitespace-only file is
// accepted as a no-op so a placeholder catalog can be staged before
// content is published.
func Parse(data []byte) (*Catalog, error) {
	trimmed := strings.TrimSpace(string(data))
	if trimmed == "" {
		return &Catalog{index: map[string][]*Entry{}}, nil
	}
	if trimmed[0] != '{' {
		return nil, fmt.Errorf("parse exposure catalog: root must be a JSON object with 'schema_version' and 'entries' keys")
	}
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(data, &raw); err != nil {
		return nil, fmt.Errorf("parse exposure catalog: %w", err)
	}
	if _, ok := raw["schema_version"]; !ok {
		return nil, fmt.Errorf("parse exposure catalog: missing required field 'schema_version'")
	}
	if _, ok := raw["entries"]; !ok {
		return nil, fmt.Errorf("parse exposure catalog: missing required field 'entries'")
	}
	var wrapped struct {
		SchemaVersion string  `json:"schema_version"`
		Entries       []Entry `json:"entries"`
		Allowlist     []Entry `json:"allowlist"`
	}
	if err := json.Unmarshal(data, &wrapped); err != nil {
		return nil, fmt.Errorf("parse exposure catalog: %w", err)
	}
	if err := validateSchemaVersion(wrapped.SchemaVersion); err != nil {
		return nil, err
	}
	if _, ok := raw["allowlist"]; ok && wrapped.SchemaVersion == "0.1.0" {
		return nil, fmt.Errorf("parse exposure catalog: 'allowlist' requires schema_version %q", model.SchemaVersion)
	}
	return build(wrapped.SchemaVersion, wrapped.Entries, wrapped.Allowlist)
}

func build(schemaVersion string, in, allow []Entry) (*Catalog, error) {
	c := &Catalog{SchemaVersion: schemaVersion}
	var err error
	if c.Entries, c.index, err = buildIndex(schemaVersion, "catalog entry", in); err != nil {
		return nil, err
	}
	if c.Allowlist, c.allow, err = buildIndex(schemaVersion, "allowlist entry", allow); err != nil {
		return nil, err
	}
	return c, nil
}

// buildIndex validates entries and indexes them by (ecosystem, normalized
// name). kind labels error messages ("catalog entry" / "allowlist entry").
func buildIndex(schemaVersion, kind string, in []Entry) ([]Entry, map[string][]*Entry, error) {
	entries := make([]Entry, 0, len(in))
	for i := range in {
		e := in[i]
		if e.ID == "" {
			return nil, nil, fmt.Errorf("%s %d: missing id", kind, i)
		}
		if e.Ecosystem == "" {
			return nil, nil, fmt.Errorf("%s %q: missing ecosystem", kind, e.ID)
		}
		if e.Package == "" {
			return nil, nil, fmt.Errorf("%s %q: missing package", kind, e.ID)
		}
		if len(e.Versions) == 0 {
			return nil, nil, fmt.Errorf("%s %q: at least one version is required", kind, e.ID)
		}
		for _, v := range e.Versions {
			if v == AnyVersion {
				if schemaVersion == "0.1.0" {
					return nil, nil, fmt.Errorf("%s %q: versions %q requires schema_version %q", kind, e.ID, AnyVersion, model.SchemaVersion)
				}
				if len(e.Versions) != 1 {
					return nil, nil, fmt.Errorf("%s %q: %q must be the only element of versions", kind, e.ID, AnyVersion)
				}
				e.anyVersion = true
			}
		}
		e.normalized = normalizeName(e.Ecosystem, e.Package)
		entries = append(entries, e)
	}
	index := map[string][]*Entry{}
	for i := range entries {
		e := &entries[i]
		key := e.Ecosystem + "\x00" + e.normalized
		index[key] = append(index[key], e)
	}
	return entries, index, nil
}

// supportedSchemaVersions lists catalog schema versions the loader
// accepts. v0.1.0 catalogs remain valid; they just cannot use "*".
var supportedSchemaVersions = []string{"0.1.0", model.SchemaVersion}

func validateSchemaVersion(version string) error {
	version = strings.TrimSpace(version)
	if version == "" {
		return fmt.Errorf("exposure catalog schema_version is required (supported: %q)", supportedSchemaVersions)
	}
	for _, v := range supportedSchemaVersions {
		if version == v {
			return nil
		}
	}
	return fmt.Errorf("unsupported exposure catalog schema_version %q (supported: %q)", version, supportedSchemaVersions)
}

// normalizeName mirrors the per-ecosystem normalization used when
// emitting package records so catalog entries written with the natural
// package name (e.g. "Requests", "@TanStack/Query-Core") still match
// the scanner's normalized output.
func normalizeName(ecosystem, name string) string {
	switch ecosystem {
	case "pypi":
		return normalize.PyPI(name)
	case "npm":
		return normalize.NPM(name)
	default:
		return strings.ToLower(strings.TrimSpace(name))
	}
}
