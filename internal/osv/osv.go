// Package osv converts malicious-package records from the OSV schema
// (https://ossf.github.io/osv-schema/) into Bumblebee exposure-catalog
// entries. OSV data is downloaded and converted offline; the scanner
// itself never contacts osv.dev.
//
// Scope is malicious packages only — records with a MAL- id or aliased
// to one. CVE-style vulnerability advisories are deliberately not
// emitted: this catalog format is for supply-chain compromise response,
// not vulnerability tracking, and mixing the two would produce huge
// catalogs whose entries can't faithfully carry an OSV-side severity.
//
// Matching is by (ecosystem, normalized_name, exact version), so only
// OSV's enumerated affected[].versions are usable. An affected entry
// with only a version range (commonly introduced:"0", i.e. all versions)
// has nothing to match against — v0.1 has no all-versions wildcard — and
// is skipped. This drops a substantial share of malicious-package
// records and is the import's main coverage limit.
package osv

import (
	"fmt"
	"regexp"
	"sort"
	"strings"

	"github.com/perplexityai/bumblebee/internal/model"
)

// idShape constrains the OSV record id before it is embedded in the
// generated Source URL. OSV ids in practice are short alphanumeric strings
// with `-`, `.`, `_`, `:`, or `/` (the set chosen here mirrors what we see
// in MAL-/GHSA-/CVE- ids). It rejects whitespace, control characters, `?`,
// `#`, `%`, `@`, and anything else outside `[A-Za-z0-9._:/-]`. It does NOT
// reject `:` or `/`, so the id can contain colons and slashes; the id is
// only ever appended to a fixed `https://osv.dev/vulnerability/` prefix and
// lands in the URL path, so the host cannot be spoofed regardless.
var idShape = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:/-]{0,128}$`)

// Catalog is the exposure-catalog document this package emits, matching
// docs/schema/v0.1.0/exposure-catalog.schema.json with a leading
// `_comment` recording provenance.
type Catalog struct {
	SchemaVersion string         `json:"schema_version"`
	Comment       string         `json:"_comment,omitempty"`
	Entries       []CatalogEntry `json:"entries"`
}

// BuildCatalog assembles a Catalog from converted entries and a provenance
// comment derived from opts and st. The comment is deterministic (no
// timestamps) so regenerating from identical input is byte-stable.
func BuildCatalog(entries []CatalogEntry, opts Options, st Stats) Catalog {
	if entries == nil {
		entries = []CatalogEntry{}
	}
	return Catalog{
		SchemaVersion: model.SchemaVersion,
		Comment:       comment(opts, st),
		Entries:       entries,
	}
}

func comment(opts Options, st Stats) string {
	ecos := make([]string, 0, len(st.EcosystemCounts))
	for e := range st.EcosystemCounts {
		ecos = append(ecos, e)
	}
	sort.Strings(ecos)
	parts := make([]string, 0, len(ecos))
	for _, e := range ecos {
		parts = append(parts, fmt.Sprintf("%s %d", e, st.EcosystemCounts[e]))
	}
	byEco := "none"
	if len(parts) > 0 {
		byEco = strings.Join(parts, ", ")
	}
	// Skip-reason breakdown: deterministic, in a fixed order, and only
	// for non-zero buckets so the typical comment stays short.
	var skips []string
	if st.SkippedNotMalicious > 0 {
		skips = append(skips, fmt.Sprintf("%d non-malicious", st.SkippedNotMalicious))
	}
	if st.SkippedNoVersions > 0 {
		skips = append(skips, fmt.Sprintf("%d no-versions", st.SkippedNoVersions))
	}
	if st.SkippedEcosystem > 0 {
		skips = append(skips, fmt.Sprintf("%d unsupported-ecosystem", st.SkippedEcosystem))
	}
	if st.SkippedWithdrawn > 0 {
		skips = append(skips, fmt.Sprintf("%d withdrawn", st.SkippedWithdrawn))
	}
	if st.SkippedBadID > 0 {
		skips = append(skips, fmt.Sprintf("%d bad-id", st.SkippedBadID))
	}
	skipStr := ""
	if len(skips) > 0 {
		skipStr = " Skipped: " + strings.Join(skips, ", ") + "."
	}
	srcStr := ""
	if s := strings.TrimSpace(opts.Source); s != "" {
		srcStr = " Source: " + s + "."
	}
	return fmt.Sprintf(
		"Generated offline from OSV (https://osv.dev) by tools/osvcatalog; not fetched at scan time. "+
			"Scope: malicious packages only (MAL- ids). %d entries across %d source records (by ecosystem: %s).%s%s "+
			"Affected entries with only version ranges and no enumerated versions are not included, "+
			"since v0.1 matching is exact-version only.",
		st.Entries, st.RecordsSeen, byEco, skipStr, srcStr)
}

// Record is the subset of an OSV record consumed by the converter.
type Record struct {
	ID        string     `json:"id"`
	Aliases   []string   `json:"aliases"`
	Summary   string     `json:"summary"`
	Withdrawn string     `json:"withdrawn"`
	Affected  []Affected `json:"affected"`
}

// Affected is one affected-package entry within an OSV record.
type Affected struct {
	Package  Package  `json:"package"`
	Versions []string `json:"versions"`
}

// Package identifies the affected package in OSV's namespace.
type Package struct {
	Ecosystem string `json:"ecosystem"`
	Name      string `json:"name"`
}

// CatalogEntry is one exposure-catalog item. Source is the OSV record's
// page, so each entry is traceable to its upstream advisory.
type CatalogEntry struct {
	ID        string   `json:"id"`
	Name      string   `json:"name,omitempty"`
	Ecosystem string   `json:"ecosystem"`
	Package   string   `json:"package"`
	Versions  []string `json:"versions"`
	Severity  string   `json:"severity,omitempty"`
	Source    string   `json:"source,omitempty"`
}

// Options controls which OSV records the converter emits.
type Options struct {
	// Ecosystems, when non-empty, restricts output to these Bumblebee
	// ecosystem values (e.g. "npm", "pypi"). Empty means all supported.
	Ecosystems map[string]bool
	// Source is an optional human-readable provenance label (e.g. the
	// upstream repo URL or a snapshot timestamp) stamped into the
	// generated catalog's `_comment`. Empty means no extra stamping.
	Source string
}

// Stats records why records were or were not converted, for the catalog
// provenance comment and operator visibility.
type Stats struct {
	RecordsSeen         int
	Entries             int
	SkippedWithdrawn    int
	SkippedNotMalicious int
	SkippedNoVersions   int
	SkippedEcosystem    int
	SkippedBadID        int
	EcosystemCounts     map[string]int
}

// ecosystemMap maps OSV's published ecosystem identifiers
// (https://osv-vulnerabilities.storage.googleapis.com/ecosystems.txt) to
// the lowercased values Bumblebee emits on records, so a generated entry
// matches the scanner's output. Only the registries Bumblebee inventories
// by package version are mapped; others (NuGet, Maven, Linux distros, ...)
// have no equivalent and their records are skipped.
var ecosystemMap = map[string]string{
	"npm":       "npm",
	"PyPI":      "pypi",
	"Go":        "go",
	"RubyGems":  "rubygems",
	"Packagist": "packagist",
	"VSCode":    "editor-extension",
	"crates.io": "crates.io",
}

// mapEcosystem returns the Bumblebee ecosystem for an OSV ecosystem
// string. OSV may suffix an ecosystem (e.g. "Debian:11"); only the part
// before the first ':' is significant for the registries we support.
func mapEcosystem(osvEcosystem string) (string, bool) {
	base := osvEcosystem
	if i := strings.IndexByte(base, ':'); i >= 0 {
		base = base[:i]
	}
	eco, ok := ecosystemMap[base]
	return eco, ok
}

// isMalicious reports whether the record describes a malicious package.
// The canonical signal is the OSSF malicious-packages `MAL-` id prefix;
// records surfaced under another database that alias a MAL- id count too.
func (r Record) isMalicious() bool {
	if strings.HasPrefix(r.ID, "MAL-") {
		return true
	}
	for _, a := range r.Aliases {
		if strings.HasPrefix(a, "MAL-") {
			return true
		}
	}
	return false
}

// Convert turns a stream of OSV records into exposure-catalog entries.
// Entries are sorted deterministically (by ecosystem, package, id) so
// regenerating a catalog from the same input yields byte-identical
// output. Stats is always populated.
func Convert(records []Record, opts Options) ([]CatalogEntry, Stats) {
	st := Stats{EcosystemCounts: map[string]int{}}
	var out []CatalogEntry
	for _, rec := range records {
		st.RecordsSeen++
		out = append(out, rec.toEntries(opts, &st)...)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Ecosystem != out[j].Ecosystem {
			return out[i].Ecosystem < out[j].Ecosystem
		}
		if out[i].Package != out[j].Package {
			return out[i].Package < out[j].Package
		}
		return out[i].ID < out[j].ID
	})
	st.Entries = len(out)
	return out, st
}

// toEntries converts a single OSV record into zero or more catalog
// entries (one per affected package that maps to a supported ecosystem
// and carries enumerated versions).
func (r Record) toEntries(opts Options, st *Stats) []CatalogEntry {
	if r.Withdrawn != "" {
		st.SkippedWithdrawn++
		return nil
	}
	// Reject ids with a shape we can't safely embed in the Source URL.
	// In practice this only fires on corrupt or hand-crafted records;
	// keeping them out is cheaper than URL-escaping every id.
	if !idShape.MatchString(r.ID) {
		st.SkippedBadID++
		return nil
	}
	if !r.isMalicious() {
		st.SkippedNotMalicious++
		return nil
	}

	// Aggregate enumerated versions per (ecosystem, name) so multiple
	// affected ranges for the same package collapse into one entry.
	type key struct{ eco, name string }
	order := []key{}
	versions := map[key]map[string]struct{}{}
	for _, a := range r.Affected {
		eco, ok := mapEcosystem(a.Package.Ecosystem)
		if !ok {
			st.SkippedEcosystem++
			continue
		}
		if len(opts.Ecosystems) > 0 && !opts.Ecosystems[eco] {
			st.SkippedEcosystem++
			continue
		}
		name := strings.TrimSpace(a.Package.Name)
		if name == "" {
			// Malformed affected entry; not counted in Stats
			// (empty names are effectively nonexistent in the real corpus).
			continue
		}
		if len(a.Versions) == 0 {
			st.SkippedNoVersions++
			continue
		}
		k := key{eco, name}
		set, seen := versions[k]
		if !seen {
			set = map[string]struct{}{}
			versions[k] = set
			order = append(order, k)
		}
		for _, v := range a.Versions {
			if v = strings.TrimSpace(v); v != "" {
				set[v] = struct{}{}
			}
		}
	}

	multi := len(order) > 1
	var entries []CatalogEntry
	for _, k := range order {
		set := versions[k]
		if len(set) == 0 {
			continue
		}
		vers := make([]string, 0, len(set))
		for v := range set {
			vers = append(vers, v)
		}
		sort.Strings(vers)

		id := r.ID
		// Keep entry ids unique when one advisory names several packages,
		// so a generated catalog has no colliding ids. Include the
		// ecosystem so the same name in two ecosystems stays distinct.
		if multi {
			id = r.ID + ":" + k.eco + "/" + k.name
		}
		// Hand-curated catalogs use "critical" for malicious packages;
		// stamp the same so generated entries are consistent with the
		// rest of threat_intel.
		entries = append(entries, CatalogEntry{
			ID:        id,
			Name:      strings.TrimSpace(r.Summary),
			Ecosystem: k.eco,
			Package:   k.name,
			Versions:  vers,
			Severity:  "critical",
			Source:    "https://osv.dev/vulnerability/" + r.ID,
		})
		st.EcosystemCounts[k.eco]++
	}
	return entries
}
