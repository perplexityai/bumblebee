// Package osv converts records from the OSV schema
// (https://ossf.github.io/osv-schema/) into Bumblebee exposure-catalog
// entries. OSV data is downloaded and converted offline; the scanner
// itself never contacts osv.dev.
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
	"sort"
	"strings"

	"github.com/perplexityai/bumblebee/internal/model"
)

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
	scope := "malicious packages only (MAL- ids)"
	if opts.IncludeVulns {
		scope = "all OSV records with enumerated versions (malicious + vulnerabilities)"
	}
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
	return fmt.Sprintf(
		"Generated offline from OSV (https://osv.dev) by tools/osvcatalog; not fetched at scan time. "+
			"Scope: %s. %d entries across %d source records (by ecosystem: %s). "+
			"Affected entries with only version ranges and no enumerated versions are not included, "+
			"since v0.1 matching is exact-version only.",
		scope, st.Entries, st.RecordsSeen, byEco)
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
// page, so each entry is traceable to its upstream advisory. The schema's
// optional `severity` field is left unset: OSV carries no rating an
// importer could assign faithfully.
type CatalogEntry struct {
	ID        string   `json:"id"`
	Name      string   `json:"name,omitempty"`
	Ecosystem string   `json:"ecosystem"`
	Package   string   `json:"package"`
	Versions  []string `json:"versions"`
	Source    string   `json:"source,omitempty"`
}

// Options controls which OSV records the converter emits.
type Options struct {
	// IncludeVulns widens conversion to every OSV record with enumerated
	// versions. When false (the default), only malicious-package records
	// (MAL- ids, or records aliased to one) are converted — the
	// supply-chain-response slice Bumblebee targets.
	IncludeVulns bool
	// Ecosystems, when non-empty, restricts output to these Bumblebee
	// ecosystem values (e.g. "npm", "pypi"). Empty means all supported.
	Ecosystems map[string]bool
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
	EcosystemCounts     map[string]int
}

// ecosystemMap maps OSV's published ecosystem identifiers
// (https://osv-vulnerabilities.storage.googleapis.com/ecosystems.txt) to
// the lowercased values Bumblebee emits on records, so a generated entry
// matches the scanner's output. Only the registries Bumblebee inventories
// by package version are mapped; others (crates.io, NuGet, Maven, VSCode,
// Linux distros, ...) have no equivalent and their records are skipped.
var ecosystemMap = map[string]string{
	"npm":       "npm",
	"PyPI":      "pypi",
	"Go":        "go",
	"RubyGems":  "rubygems",
	"Packagist": "packagist",
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
	malicious := r.isMalicious()
	if !opts.IncludeVulns && !malicious {
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
		entries = append(entries, CatalogEntry{
			ID:        id,
			Name:      strings.TrimSpace(r.Summary),
			Ecosystem: k.eco,
			Package:   k.name,
			Versions:  vers,
			Source:    "https://osv.dev/vulnerability/" + r.ID,
		})
		st.EcosystemCounts[k.eco]++
	}
	return entries
}
