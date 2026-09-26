// Command bumblebee is a read-only endpoint package inventory collector.
//
// It walks profile-scoped filesystem roots and emits NDJSON records describing
// installed packages found in lockfiles and install metadata. It does NOT
// execute package managers, fetch from the network for resolution, or read
// arbitrary source files.
//
// Subcommands:
//
//	bumblebee scan     [--profile P] ...    run a scan and emit NDJSON records
//	bumblebee roots    [--profile P] ...    print the resolved scan roots and exit
//	bumblebee selftest [flags]              scan embedded fixtures and verify detection
//	bumblebee version                       print version and exit
//
// Subcommand implementations and their support code live in sibling files:
//
//	main.go        — dispatch (main, usage), scan/roots subcommands,
//	                 flag types, small per-run helpers
//	selftest.go    — selftest subcommand and embedded-fixture extraction
//	roots.go       — root resolution per profile
//	version.go     — Version variable and the version-string formatters
//	sink.go        — --output stdout|file|http construction and HTTP auth
//
// Output destinations: stdout (default), a local NDJSON file, a human-readable
// terminal report, or POST to a generic HTTPS log-ingest endpoint. See
// `scan --help` and the README.
package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"sort"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/perplexityai/bumblebee/internal/endpoint"
	"github.com/perplexityai/bumblebee/internal/exposure"
	"github.com/perplexityai/bumblebee/internal/model"
	"github.com/perplexityai/bumblebee/internal/output"
	"github.com/perplexityai/bumblebee/internal/scanner"
)

type stringList []string

func (s *stringList) String() string { return strings.Join(*s, ",") }
func (s *stringList) Set(v string) error {
	for _, x := range strings.Split(v, ",") {
		x = strings.TrimSpace(x)
		if x != "" {
			*s = append(*s, x)
		}
	}
	return nil
}

func main() {
	if len(os.Args) < 2 {
		usage(os.Stderr)
		os.Exit(2)
	}
	switch os.Args[1] {
	case "scan":
		os.Exit(runScan(os.Args[2:]))
	case "roots":
		os.Exit(runRoots(os.Args[2:]))
	case "selftest":
		os.Exit(runSelftest(os.Args[2:]))
	case "version", "--version", "-version":
		fmt.Println(versionString())
	case "-h", "--help", "help":
		usage(os.Stdout)
	default:
		fmt.Fprintf(os.Stderr, "unknown subcommand %q\n", os.Args[1])
		usage(os.Stderr)
		os.Exit(2)
	}
}

func usage(w io.Writer) {
	fmt.Fprintln(w, `bumblebee — endpoint package inventory collector

usage:
  bumblebee scan     [flags]   run a scan and emit NDJSON records
  bumblebee roots    [flags]   print the resolved scan roots and exit
  bumblebee selftest [flags]   scan embedded fixtures and verify detection
  bumblebee version            print version and exit

run "bumblebee scan --help" for scan flags, including --profile.`)
}

// scanOpts holds flag values shared by the scan subcommand.
type scanOpts struct {
	profile     string
	roots       stringList
	excludes    stringList
	ecosystems  stringList
	maxFileSize int64
	maxDuration time.Duration
	concurrency int

	exposureCatalog string
	maxCatalogSize  int64
	findingsOnly    bool

	allUsers bool

	outputDest    string
	outputFile    string
	appendFile    bool
	emitSummary   bool
	terminalMode  bool
	httpURL       string
	httpAuth      string
	httpTokenEnv  string
	httpKeyEnv    string
	httpTimeout   time.Duration
	httpBatchSize int
	httpAllowHTTP bool
	httpGzip      bool

	deviceIDEnv string
}

func registerScanFlags(fs *flag.FlagSet, o *scanOpts) {
	fs.StringVar(&o.profile, "profile", model.ProfileBaseline,
		"scan profile: baseline (bounded known package/tool roots), project (configured developer/project roots), or deep (incident-response exposure scan; may include user home roots)")
	fs.Var(&o.roots, "root", "directory to scan (repeatable or comma-separated; unrelated to running as root). Required for deep; optional for baseline/project.")
	fs.Var(&o.excludes, "exclude", "additional directory name or suffix path to exclude (repeatable)")
	fs.Var(&o.ecosystems, "ecosystem", "limit scanning to emitted ecosystem values (repeatable or comma-separated): "+strings.Join(model.SupportedEcosystems(), ","))
	fs.Int64Var(&o.maxFileSize, "max-file-size", 5*1024*1024, "max bytes to read from any single metadata file")
	fs.DurationVar(&o.maxDuration, "max-duration", 0, "max wall-clock duration for the whole scan (0 = unbounded)")
	fs.IntVar(&o.concurrency, "concurrency", 4, "number of concurrent file parsers")

	fs.StringVar(&o.exposureCatalog, "exposure-catalog", "",
		"path to a JSON exposure catalog file, or a directory containing one or more *.json catalogs (merged non-recursively). Matches emit record_type=finding alongside packages. Matching is by exact (ecosystem, normalized_name, version); an entry with versions [\"*\"] matches any version. The catalog is package-presence criteria only; it is NOT an EDR IOC feed.")
	fs.Int64Var(&o.maxCatalogSize, "max-catalog-size", 64*1024*1024,
		"max bytes to read from any single exposure catalog file (0 = unbounded). Applied per file when --exposure-catalog is a directory.")
	fs.BoolVar(&o.findingsOnly, "findings-only", false,
		"require --exposure-catalog and suppress only record_type=package output while still emitting findings, scan_summary, and diagnostics")

	fs.BoolVar(&o.allUsers, "all-users", false,
		"on macOS, expand baseline/project per-user default roots across every real /Users/<name>/ home. Useful for root-owned LaunchDaemon runs. Cannot be combined with --root or --profile=deep. System/Homebrew roots are still included once. No effect on Linux.")

	fs.StringVar(&o.outputDest, "output", "stdout", "where to send records: stdout, file, http, or terminal")
	fs.BoolVar(&o.terminalMode, "terminal", false, "render a human-readable terminal report instead of raw NDJSON (implies --output=terminal)")
	fs.StringVar(&o.outputFile, "output-file", "", "path for --output=file (NDJSON; required when --output=file)")
	fs.BoolVar(&o.appendFile, "append", false, "append to --output-file instead of truncating")
	fs.BoolVar(&o.emitSummary, "emit-summary", true, "emit a scan_summary record at end of run")
	fs.StringVar(&o.httpURL, "http-url", "", "ingest URL for --output=http (https required for non-loopback)")
	fs.StringVar(&o.httpAuth, "http-auth", "none", "auth mode for --output=http: none, bearer, hmac-sha256")
	fs.StringVar(&o.httpTokenEnv, "http-token-env", "", "env var holding the bearer token (for --http-auth=bearer)")
	fs.StringVar(&o.httpKeyEnv, "http-hmac-key-env", "", "env var holding the HMAC shared secret (for --http-auth=hmac-sha256)")
	fs.DurationVar(&o.httpTimeout, "http-timeout", 30*time.Second, "per-request timeout for --output=http")
	fs.IntVar(&o.httpBatchSize, "http-batch-size", 500, "records per POST for --output=http")
	fs.BoolVar(&o.httpAllowHTTP, "http-allow-insecure", false, "allow plain http:// to non-loopback hosts (testing only)")
	fs.BoolVar(&o.httpGzip, "http-gzip", false, "gzip the POST body for --output=http (Content-Encoding: gzip)")

	fs.StringVar(&o.deviceIDEnv, "device-id-env", "",
		"env var holding a stable opaque endpoint/device id (e.g. set by MDM, EDR, or a provisioning script); populates endpoint.device_id when set")
}

// runScan executes the scan subcommand. Returns the process exit code.
func runScan(args []string) int {
	fs := flag.NewFlagSet("scan", flag.ExitOnError)
	var o scanOpts
	registerScanFlags(fs, &o)
	_ = fs.Parse(args)

	profile, err := normalizeProfile(o.profile)
	if err != nil {
		fmt.Fprintln(os.Stderr, err.Error())
		return 2
	}
	o.profile = profile

	filter, err := parseEcosystemFilter(o.ecosystems)
	if err != nil {
		fmt.Fprintln(os.Stderr, err.Error())
		return 2
	}

	if o.findingsOnly && o.exposureCatalog == "" {
		fmt.Fprintln(os.Stderr, "--findings-only requires --exposure-catalog")
		return 2
	}
	if o.terminalMode {
		o.outputDest = "terminal"
	}

	roots, diagNotes, err := resolveRoots(o.profile, o.roots, rootsOpts{AllUsers: o.allUsers})
	if err != nil {
		fmt.Fprintln(os.Stderr, err.Error())
		return 2
	}

	var catalog *exposure.Catalog
	if o.exposureCatalog != "" {
		catalog, err = exposure.Load(o.exposureCatalog, o.maxCatalogSize)
		if err != nil {
			fmt.Fprintln(os.Stderr, err.Error())
			return 2
		}
	}

	recordsW, closeFn, err := openSink(o.outputDest, o.outputFile, o.appendFile, sinkHTTPOpts{
		URL:       o.httpURL,
		AuthMode:  o.httpAuth,
		TokenEnv:  o.httpTokenEnv,
		KeyEnv:    o.httpKeyEnv,
		Timeout:   o.httpTimeout,
		BatchSize: o.httpBatchSize,
		AllowHTTP: o.httpAllowHTTP,
		Gzip:      o.httpGzip,
		UserAgent: fmt.Sprintf("bumblebee/%s", currentVersion()),
	})
	if err != nil {
		fmt.Fprintln(os.Stderr, err.Error())
		return 2
	}

	runID := newRunID()
	diagW := io.Writer(os.Stderr)
	if o.outputDest == "terminal" {
		diagW = newTerminalDiagWriter(os.Stderr)
	}
	emitter := output.New(recordsW, diagW, runID)

	if o.outputDest == "terminal" {
		for _, n := range diagNotes {
			fmt.Fprintln(os.Stderr, n)
		}
	} else {
		for _, n := range diagNotes {
			emitter.Diag("info", "", n)
		}
	}
	deviceID, deviceIDWarn := resolveDeviceID(o.deviceIDEnv)
	if deviceIDWarn != "" && o.outputDest == "terminal" {
		fmt.Fprintln(os.Stderr, deviceIDWarn)
	}
	if deviceIDWarn != "" && o.outputDest != "terminal" {
		emitter.Diag("warn", "", deviceIDWarn)
	}
	ep := endpoint.Current(deviceID)
	scanStart := time.Now().UTC()
	base := model.Record{
		RecordType:     model.RecordTypePackage,
		SchemaVersion:  model.SchemaVersion,
		ScannerName:    model.ScannerName,
		ScannerVersion: currentVersion(),
		RunID:          runID,
		ScanTime:       scanStart.Format(time.RFC3339Nano),
		Endpoint:       ep,
		Profile:        o.profile,
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sigCh
		cancel()
	}()

	spinnerDone := make(chan struct{})
	spinnerFinished := make(chan struct{})
	if o.outputDest == "terminal" && isInteractiveTerminal(os.Stderr) {
		go runSpinner(os.Stderr, spinnerDone, spinnerFinished)
	}

	cfg := scanner.Config{
		Profile:      o.profile,
		Roots:        roots,
		Excludes:     o.excludes,
		Ecosystems:   filter,
		MaxFileSize:  o.maxFileSize,
		MaxDuration:  o.maxDuration,
		Concurrency:  o.concurrency,
		Catalog:      catalog,
		FindingsOnly: o.findingsOnly,
		BaseRecord:   base,
		Emitter:      emitter,
	}
	res, runErr := scanner.Run(ctx, cfg)
	if o.outputDest == "terminal" {
		close(spinnerDone)
		<-spinnerFinished
	}
	if runErr != nil {
		if o.outputDest == "terminal" {
			fmt.Fprintln(os.Stderr, runErr.Error())
		} else {
			emitter.Diag("error", "", runErr.Error())
		}
	}

	exitCode := 0
	status := model.ScanStatusComplete
	errMsg := ""
	sinkStats := emitter.SinkStats()
	switch {
	case runErr != nil && res.RecordsEmitted > 0:
		status = model.ScanStatusPartial
		errMsg = runErr.Error()
		exitCode = 1
	case runErr != nil:
		status = model.ScanStatusError
		errMsg = runErr.Error()
		exitCode = 1
	}
	if sinkStats.HTTPBatchesFailed > 0 && status == model.ScanStatusComplete {
		status = model.ScanStatusPartial
		if errMsg == "" {
			errMsg = "http sink delivery failed"
		}
		exitCode = 1
	}

	if o.emitSummary {
		summaryRoots := make([]model.SummaryRoot, 0, len(roots))
		for _, r := range roots {
			summaryRoots = append(summaryRoots, model.SummaryRoot{Path: r.Path, Kind: r.Kind})
		}
		counts := map[string]int{
			model.RecordTypePackage: res.RecordsEmitted,
			model.RecordTypeFinding: res.FindingsEmitted,
		}
		if err := emitter.EmitSummary(model.ScanSummary{
			SchemaVersion:            model.SchemaVersion,
			ScannerName:              model.ScannerName,
			ScannerVersion:           currentVersion(),
			RunID:                    runID,
			ScanTime:                 scanStart.Format(time.RFC3339Nano),
			EndTime:                  time.Now().UTC().Format(time.RFC3339Nano),
			Endpoint:                 ep,
			Profile:                  o.profile,
			Status:                   status,
			Roots:                    summaryRoots,
			Counts:                   counts,
			PackageRecordsEmitted:    res.RecordsEmitted,
			PackageRecordsSuppressed: res.PackageRecordsSuppressed,
			FindingsEmitted:          res.FindingsEmitted,
			Duplicates:               res.Duplicates,
			DiagnosticsCount:         res.Diagnostics,
			FilesConsidered:          res.FilesConsidered,
			TimedOut:                 res.TimedOut,
			DurationMS:               res.Duration.Milliseconds(),
			HTTPBatchesAttempted:     sinkStats.HTTPBatchesAttempted,
			HTTPBatchesSucceeded:     sinkStats.HTTPBatchesSucceeded,
			HTTPBatchesFailed:        sinkStats.HTTPBatchesFailed,
			HTTPLastStatus:           sinkStats.HTTPLastStatus,
			Error:                    errMsg,
		}); err != nil {
			emitter.Diag("error", "", "emit scan_summary: "+err.Error())
			exitCode = 1
		}
	}

	if closeErr := closeFn(); closeErr != nil {
		if o.outputDest == "terminal" {
			fmt.Fprintln(os.Stderr, closeErr.Error())
		} else {
			emitter.Diag("error", "", closeErr.Error())
		}
		exitCode = 1
	}

	emitter.Diag("info", "", fmt.Sprintf(
		"scan complete: profile=%s status=%s files_considered=%d records=%d findings=%d suppressed=%d duplicates=%d diagnostics=%d timed_out=%v duration=%s",
		o.profile, status, res.FilesConsidered, res.RecordsEmitted, res.FindingsEmitted, res.PackageRecordsSuppressed, res.Duplicates, res.Diagnostics, res.TimedOut, res.Duration,
	))
	return exitCode
}

type terminalDiagWriter struct {
	out     io.Writer
	mu      sync.Mutex
	pending []byte
}

func newTerminalDiagWriter(out io.Writer) io.Writer {
	return &terminalDiagWriter{out: out}
}

func (w *terminalDiagWriter) Write(p []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.pending = append(w.pending, p...)
	for {
		idx := bytes.IndexByte(w.pending, '\n')
		if idx < 0 {
			break
		}
		line := bytes.TrimSpace(w.pending[:idx])
		w.pending = w.pending[idx+1:]
		if len(line) == 0 {
			continue
		}
		var d model.Diagnostic
		if err := json.Unmarshal(line, &d); err != nil {
			_, _ = fmt.Fprintln(w.out, string(line))
			continue
		}
		msg := d.Message
		if d.Path != "" {
			msg = d.Path + ": " + msg
		}
		if d.Level != "" {
			_, _ = fmt.Fprintf(w.out, "%s: %s\n", strings.ToUpper(d.Level), msg)
		} else {
			_, _ = fmt.Fprintln(w.out, msg)
		}
	}
	return len(p), nil
}

func isInteractiveTerminal(f *os.File) bool {
	info, err := f.Stat()
	if err != nil {
		return false
	}
	return info.Mode()&os.ModeCharDevice != 0
}

// runRoots prints the resolved roots for the given profile and exits. It
// shares scoping flags with `scan` so operators can preview exactly what
// the next scan will walk on this host.
func runRoots(args []string) int {
	fs := flag.NewFlagSet("roots", flag.ExitOnError)
	var (
		profile  string
		roots    stringList
		allUsers bool
	)
	fs.StringVar(&profile, "profile", model.ProfileBaseline, "scan profile: baseline, project, or deep")
	fs.Var(&roots, "root", "filesystem root to scan (repeatable). Overrides profile defaults when set.")
	fs.BoolVar(&allUsers, "all-users", false, "on macOS, expand per-user defaults across every /Users/<name>/ home. See scan --help.")
	_ = fs.Parse(args)

	var err error
	profile, err = normalizeProfile(profile)
	if err != nil {
		fmt.Fprintln(os.Stderr, err.Error())
		return 2
	}
	resolved, notes, err := resolveRoots(profile, roots, rootsOpts{AllUsers: allUsers})
	if err != nil {
		fmt.Fprintln(os.Stderr, err.Error())
		return 2
	}
	for _, n := range notes {
		fmt.Fprintln(os.Stderr, n)
	}
	for _, r := range resolved {
		fmt.Printf("%s\t%s\n", r.Kind, r.Path)
	}
	return 0
}

func runSpinner(w io.Writer, done <-chan struct{}, finished chan<- struct{}) {
	defer close(finished)
	frames := []string{"|", "/", "-", "\\"}
	ticker := time.NewTicker(120 * time.Millisecond)
	defer ticker.Stop()
	idx := 0
	_, _ = fmt.Fprint(w, "scanning ")
	for {
		select {
		case <-done:
			_, _ = fmt.Fprint(w, "\r")
			_, _ = fmt.Fprintln(w, "scanning complete")
			return
		case <-ticker.C:
			_, _ = fmt.Fprintf(w, "\rscanning %s", frames[idx%len(frames)])
			idx++
		}
	}
}

// resolveDeviceID reads the configured env var and returns the trimmed
// device id. If the flag was unset, both returns are empty. If the flag
// was set but the env var is missing or whitespace-only, the id is empty
// and a human-readable warning is returned. The scan proceeds with no
// DeviceID populated rather than failing — externally-supplied
// attributes can lag behind the scheduled job, and failing the scan
// would lose every other signal it carries.
func resolveDeviceID(envName string) (string, string) {
	if envName == "" {
		return "", ""
	}
	raw, ok := os.LookupEnv(envName)
	if !ok {
		return "", fmt.Sprintf("--device-id-env=%q is not set in the environment; proceeding without endpoint.device_id", envName)
	}
	id := strings.TrimSpace(raw)
	if id == "" {
		return "", fmt.Sprintf("--device-id-env=%q is set but empty/whitespace; proceeding without endpoint.device_id", envName)
	}
	return id, ""
}

func newRunID() string {
	var b [16]byte
	_, _ = rand.Read(b[:])
	return hex.EncodeToString(b[:])
}

func normalizeProfile(profile string) (string, error) {
	switch strings.TrimSpace(profile) {
	case "", model.ProfileBaseline:
		return model.ProfileBaseline, nil
	case model.ProfileProject:
		return model.ProfileProject, nil
	case model.ProfileDeep:
		return model.ProfileDeep, nil
	default:
		return "", fmt.Errorf("unknown --profile %q (want: baseline, project, deep)", profile)
	}
}

func parseEcosystemFilter(values []string) (map[string]bool, error) {
	if len(values) == 0 {
		return nil, nil
	}
	filter := make(map[string]bool, len(values))
	var invalid []string
	for _, value := range values {
		for _, part := range strings.Split(value, ",") {
			ecosystem := strings.TrimSpace(part)
			if ecosystem == "" {
				continue
			}
			if !model.IsSupportedEcosystem(ecosystem) {
				invalid = append(invalid, ecosystem)
				continue
			}
			filter[ecosystem] = true
		}
	}
	if len(invalid) > 0 {
		sort.Strings(invalid)
		return nil, fmt.Errorf("invalid --ecosystem value(s): %s (allowed: %s)", strings.Join(invalid, ", "), strings.Join(model.SupportedEcosystems(), ","))
	}
	if len(filter) == 0 {
		return nil, nil
	}
	return filter, nil
}
