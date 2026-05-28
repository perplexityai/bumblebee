// Package model defines the inventory record schema emitted by the scanner.
package model

import (
	"crypto/sha256"
	"encoding/hex"
	"sort"
	"strconv"
	"strings"
)

const (
	SchemaVersion = "0.1.0"
	ScannerName   = "bumblebee"

	RecordTypePackage     = "package"
	RecordTypeFinding     = "finding"
	RecordTypeScanSummary = "scan_summary"
	RecordTypeDiagnostic  = "diagnostic"

	ScanStatusComplete = "complete"
	ScanStatusPartial  = "partial"
	ScanStatusError    = "error"

	// Profiles determine which roots are scanned and which records are
	// emitted. They are the single knob operators tune for a deployment.
	ProfileBaseline = "baseline" // bounded known package/tool roots
	ProfileProject  = "project"  // configured developer/project roots
	ProfileDeep     = "deep"     // incident-response exposure scan

	// FindingType discriminates between possible finding shapes. v0.1 only
	// emits package_exposure (exact name+version match against an
	// operator-supplied exposure catalog).
	FindingTypePackageExposure = "package_exposure"
)

const (
	EcosystemNPM              = "npm"
	EcosystemPyPI             = "pypi"
	EcosystemGo               = "go"
	EcosystemRubyGems         = "rubygems"
	EcosystemPackagist        = "packagist"
	EcosystemConda            = "conda"
	EcosystemMCP              = "mcp"
	EcosystemEditorExtension  = "editor-extension"
	EcosystemBrowserExtension = "browser-extension"
)

var supportedEcosystems = map[string]struct{}{
	EcosystemNPM:              {},
	EcosystemPyPI:             {},
	EcosystemGo:               {},
	EcosystemRubyGems:         {},
	EcosystemPackagist:        {},
	EcosystemConda:            {},
	EcosystemMCP:              {},
	EcosystemEditorExtension:  {},
	EcosystemBrowserExtension: {},
}

var supportedEcosystemOrder = []string{
	EcosystemNPM,
	EcosystemPyPI,
	EcosystemGo,
	EcosystemRubyGems,
	EcosystemPackagist,
	EcosystemConda,
	EcosystemMCP,
	EcosystemEditorExtension,
	EcosystemBrowserExtension,
}

// SupportedEcosystems returns the emitted ecosystem values supported by v0.1.
func SupportedEcosystems() []string {
	out := append([]string(nil), supportedEcosystemOrder...)
	return out
}

// IsSupportedEcosystem reports whether ecosystem is a recognized emitted value.
func IsSupportedEcosystem(ecosystem string) bool {
	_, ok := supportedEcosystems[ecosystem]
	return ok
}

// RootKind classifies why a scan root is being walked. It is recorded on
// every package and finding record so receivers can tell whether a
// match came from a global toolchain location, a project tree, or a
// broad incident-response sweep.
const (
	RootKindGlobalPackage    = "global_package_root"
	RootKindUserPackage      = "user_package_root"
	RootKindProject          = "project_root"
	RootKindEditorExtension  = "editor_extension_root"
	RootKindBrowserExtension = "browser_extension_root"
	RootKindMCPConfig        = "mcp_config_root"
	RootKindHomebrew         = "homebrew_root"
	RootKindDeepHome         = "deep_home_root"
	RootKindUnknown          = "unknown"
)

// Endpoint identifies the host on which the scan ran.
//
// DeviceID, when set, is a stable opaque identifier supplied by the
// deployment environment (MDM, EDR, fleet-management tool, or a
// provisioning script) so receiver-side current-state can be keyed
// on something that survives hostname / username changes. It is
// never read from a CLI literal — only from an environment variable
// named by --device-id-env — to avoid leaking it through the process
// list.
type Endpoint struct {
	Hostname string `json:"hostname"`
	OS       string `json:"os"`
	Arch     string `json:"arch"`
	Username string `json:"username"`
	UID      string `json:"uid"`
	DeviceID string `json:"device_id,omitempty"`
}

// Record is one discovered package observation.
//
// Records are emitted as NDJSON, one per line, to the records sink.
// Scanner errors are emitted as Diagnostic to stderr and never mixed in here.
//
// The schema is intentionally slim: noisy or large fields (resolved URLs,
// integrity hashes, hash digests, free-form notes) were removed in v0.1.
// Exposure matching is exact-name + exact-version against an operator-
// supplied catalog; hash matching is not needed for that workflow.
type Record struct {
	RecordType          string   `json:"record_type"`
	RecordID            string   `json:"record_id"`
	SchemaVersion       string   `json:"schema_version"`
	ScannerName         string   `json:"scanner_name"`
	ScannerVersion      string   `json:"scanner_version"`
	RunID               string   `json:"run_id"`
	ScanTime            string   `json:"scan_time"`
	Endpoint            Endpoint `json:"endpoint"`
	Profile             string   `json:"profile"`
	Ecosystem           string   `json:"ecosystem"`
	PackageName         string   `json:"package_name"`
	NormalizedName      string   `json:"normalized_name"`
	Version             string   `json:"version"`
	ProjectPath         string   `json:"project_path,omitempty"`
	RootKind            string   `json:"root_kind,omitempty"`
	InstallScope        string   `json:"install_scope,omitempty"`
	PackageManager      string   `json:"package_manager,omitempty"`
	SourceType          string   `json:"source_type"`
	SourceFile          string   `json:"source_file"`
	DirectDependency    *bool    `json:"direct_dependency,omitempty"`
	HasLifecycleScripts bool     `json:"has_lifecycle_scripts"`
	LifecycleScripts    []string `json:"lifecycle_scripts,omitempty"`
	Confidence          string   `json:"confidence"`

	// RequestedSpec is set on MCP records when the configured command/args
	// reference a package by spec (e.g. "@playwright/mcp@latest" or
	// "left-pad@1.2.3"). The selector portion ("@latest", "@1.2.3") is
	// preserved here while PackageName is normalized to the bare name.
	// Version remains empty unless an exact installed version is known.
	RequestedSpec string `json:"requested_spec,omitempty"`

	// ServerName is set on MCP records to the id (map key) of the server
	// entry in the config so the configured alias survives even when
	// PackageName is derived from the command/args.
	ServerName string `json:"server_name,omitempty"`
}

// Finding is an exposure-catalog match against a discovered package.
//
// Findings are emitted alongside package records (same sink, same NDJSON
// stream) but are tagged with record_type=finding so receivers can route
// them to a separate exposure table without re-running the match.
//
// v0.1 only emits FindingTypePackageExposure: an exact (ecosystem,
// normalized_name, version) match. Catalog entry id and name are echoed
// so receivers can attribute the hit without re-loading the catalog.
type Finding struct {
	RecordType     string   `json:"record_type"`
	RecordID       string   `json:"record_id"`
	SchemaVersion  string   `json:"schema_version"`
	ScannerName    string   `json:"scanner_name"`
	ScannerVersion string   `json:"scanner_version"`
	RunID          string   `json:"run_id"`
	ScanTime       string   `json:"scan_time"`
	Endpoint       Endpoint `json:"endpoint"`
	Profile        string   `json:"profile"`
	FindingType    string   `json:"finding_type"`
	Severity       string   `json:"severity,omitempty"`
	CatalogID      string   `json:"catalog_id"`
	CatalogName    string   `json:"catalog_name,omitempty"`
	Ecosystem      string   `json:"ecosystem"`
	PackageName    string   `json:"package_name"`
	NormalizedName string   `json:"normalized_name"`
	Version        string   `json:"version"`
	RootKind       string   `json:"root_kind,omitempty"`
	ProjectPath    string   `json:"project_path,omitempty"`
	SourceType     string   `json:"source_type"`
	SourceFile     string   `json:"source_file"`
	Confidence     string   `json:"confidence"`
	Evidence       string   `json:"evidence,omitempty"`
}

// ScanSummary is a per-run terminator record emitted to the same sink as
// package and finding records. Receivers should only promote a run to
// current state after a matching scan_summary with status=complete has
// arrived.
type ScanSummary struct {
	RecordType               string         `json:"record_type"`
	RecordID                 string         `json:"record_id"`
	SchemaVersion            string         `json:"schema_version"`
	ScannerName              string         `json:"scanner_name"`
	ScannerVersion           string         `json:"scanner_version"`
	RunID                    string         `json:"run_id"`
	ScanTime                 string         `json:"scan_time"`
	EndTime                  string         `json:"end_time"`
	Endpoint                 Endpoint       `json:"endpoint"`
	Profile                  string         `json:"profile"`
	Status                   string         `json:"status"`
	Roots                    []SummaryRoot  `json:"roots,omitempty"`
	Counts                   map[string]int `json:"counts,omitempty"`
	PackageRecordsEmitted    int            `json:"package_records_emitted"`
	PackageRecordsSuppressed int            `json:"package_records_suppressed,omitempty"`
	FindingsEmitted          int            `json:"findings_emitted"`
	Duplicates               int            `json:"duplicates"`
	DiagnosticsCount         int            `json:"diagnostics_count"`
	FilesConsidered          int            `json:"files_considered"`
	TimedOut                 bool           `json:"timed_out"`
	DurationMS               int64          `json:"duration_ms"`
	HTTPBatchesAttempted     int            `json:"http_batches_attempted,omitempty"`
	HTTPBatchesSucceeded     int            `json:"http_batches_succeeded,omitempty"`
	HTTPBatchesFailed        int            `json:"http_batches_failed,omitempty"`
	HTTPLastStatus           int            `json:"http_last_status,omitempty"`
	Error                    string         `json:"error,omitempty"`
}

// SummaryRoot is one entry in ScanSummary.Roots — path plus the root kind
// that drove its inclusion. Recording the kind on the summary makes
// "which population is this scan covering?" answerable without
// re-parsing the records.
type SummaryRoot struct {
	Path string `json:"path"`
	Kind string `json:"kind"`
}

// Diagnostic is a scanner-side error or skipped-file event emitted to stderr.
type Diagnostic struct {
	RecordType string `json:"record_type"`
	RecordID   string `json:"record_id"`
	RunID      string `json:"run_id"`
	Time       string `json:"time"`
	Level      string `json:"level"`
	Path       string `json:"path,omitempty"`
	Message    string `json:"message"`
}

// DedupKey returns a stable identity for a package record so duplicate
// observations from the same source file collapse within a run.
func (r Record) DedupKey() string {
	return r.StableID()
}

// StableID returns the canonical record_id for a package record.
func (r Record) StableID() string {
	return stableID(RecordTypePackage, []string{
		r.Profile,
		r.Ecosystem,
		r.NormalizedName,
		r.Version,
		r.ProjectPath,
		r.RootKind,
		r.InstallScope,
		r.PackageManager,
		r.SourceType,
		r.SourceFile,
		boolPointerString(r.DirectDependency),
		strconv.FormatBool(r.HasLifecycleScripts),
		joinSorted(r.LifecycleScripts),
		r.Confidence,
		r.RequestedSpec,
		r.ServerName,
	})
}

// StableID returns the canonical record_id for a finding record.
func (f Finding) StableID() string {
	return stableID(RecordTypeFinding, []string{
		f.Profile,
		f.FindingType,
		f.CatalogID,
		f.Ecosystem,
		f.NormalizedName,
		f.Version,
		f.RootKind,
		f.ProjectPath,
		f.SourceType,
		f.SourceFile,
		f.Confidence,
	})
}

// StableID returns the canonical record_id for a scan summary record.
func (s ScanSummary) StableID() string {
	rootParts := make([]string, 0, len(s.Roots))
	for _, root := range s.Roots {
		rootParts = append(rootParts, root.Path+"\x1f"+root.Kind)
	}
	return stableID(RecordTypeScanSummary, []string{
		s.Profile,
		s.Status,
		s.ScanTime,
		s.EndTime,
		joinWithUnitSeparator(rootParts),
		canonicalCounts(s.Counts),
		strconv.Itoa(s.PackageRecordsEmitted),
		strconv.Itoa(s.PackageRecordsSuppressed),
		strconv.Itoa(s.FindingsEmitted),
		strconv.Itoa(s.Duplicates),
		strconv.Itoa(s.DiagnosticsCount),
		strconv.Itoa(s.FilesConsidered),
		strconv.FormatBool(s.TimedOut),
		strconv.FormatInt(s.DurationMS, 10),
		strconv.Itoa(s.HTTPBatchesAttempted),
		strconv.Itoa(s.HTTPBatchesSucceeded),
		strconv.Itoa(s.HTTPBatchesFailed),
		strconv.Itoa(s.HTTPLastStatus),
		s.Error,
	})
}

// StableID returns the canonical record_id for a diagnostic record.
func (d Diagnostic) StableID() string {
	return stableID(RecordTypeDiagnostic, []string{
		d.Level,
		d.Path,
		d.Message,
	})
}

// stableID returns the canonical record_id for a record. The hash here
// is a content-addressed dedup key over scanner-derived public metadata
// (record type, ecosystem, package name, version, source paths, etc.).
// The output is emitted in cleartext on every record. SHA-256 is used so
// a record_id is stable across runs and across hosts that observe the
// same package identity tuple.
func stableID(recordType string, parts []string) string {
	canonical := recordType + "\x00" + joinWithUnitSeparator(parts)
	digest := sha256.Sum256([]byte(canonical))
	return recordType + ":" + hex.EncodeToString(digest[:])
}

func boolPointerString(v *bool) string {
	if v == nil {
		return ""
	}
	return strconv.FormatBool(*v)
}

func joinSorted(values []string) string {
	if len(values) == 0 {
		return ""
	}
	sorted := append([]string(nil), values...)
	sort.Strings(sorted)
	return joinWithUnitSeparator(sorted)
}

func canonicalCounts(counts map[string]int) string {
	if len(counts) == 0 {
		return ""
	}
	keys := make([]string, 0, len(counts))
	for key := range counts {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	parts := make([]string, 0, len(keys))
	for _, key := range keys {
		parts = append(parts, key+"\x1f"+strconv.Itoa(counts[key]))
	}
	return joinWithUnitSeparator(parts)
}

func joinWithUnitSeparator(parts []string) string {
	return strings.Join(parts, "\x1e")
}
