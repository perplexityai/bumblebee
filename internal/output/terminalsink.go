package output

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"sort"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"github.com/perplexityai/bumblebee/internal/model"
)

const terminalFindingLimit = 10

// TerminalSink collects the existing NDJSON record stream and renders a
// human-readable scan report when closed.
type TerminalSink struct {
	mu sync.Mutex

	out     io.Writer
	color   bool
	pending []byte

	packageCounts  map[string]int
	severityCounts map[string]int
	findings       []model.Finding
	findingCount   int
	summary        *model.ScanSummary
	err            error
	closed         bool
}

// NewTerminalSink returns a sink that accepts the same NDJSON record stream as
// stdout, but emits a formatted terminal report on Close.
func NewTerminalSink(out io.Writer) *TerminalSink {
	if out == nil {
		out = os.Stdout
	}
	return &TerminalSink{
		out:            out,
		color:          terminalColorEnabled(out),
		packageCounts:  make(map[string]int),
		severityCounts: make(map[string]int),
	}
}

// Write accepts one or more NDJSON records and stores them until Close renders
// the final report.
func (t *TerminalSink) Write(p []byte) (int, error) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.closed {
		return 0, fmt.Errorf("terminal sink: write after close")
	}
	if t.err != nil {
		return 0, t.err
	}
	t.pending = append(t.pending, p...)
	for {
		idx := bytes.IndexByte(t.pending, '\n')
		if idx < 0 {
			break
		}
		line := bytes.TrimSpace(t.pending[:idx])
		t.pending = t.pending[idx+1:]
		if len(line) == 0 {
			continue
		}
		if err := t.consumeLine(line); err != nil {
			t.err = err
			return len(p), err
		}
	}
	return len(p), nil
}

// Close flushes any remaining buffered line and renders the human-readable
// report. It is idempotent.
func (t *TerminalSink) Close() error {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.closed {
		return t.err
	}
	t.closed = true
	if t.err != nil {
		return t.err
	}
	if len(t.pending) > 0 {
		line := bytes.TrimSpace(t.pending)
		if len(line) > 0 {
			if err := t.consumeLine(line); err != nil {
				t.err = err
				return err
			}
		}
		t.pending = nil
	}
	if err := t.render(); err != nil {
		t.err = err
		return err
	}
	return nil
}

func (t *TerminalSink) consumeLine(line []byte) error {
	var meta struct {
		RecordType string `json:"record_type"`
	}
	if err := json.Unmarshal(line, &meta); err != nil {
		return fmt.Errorf("terminal sink: decode record type: %w", err)
	}
	switch meta.RecordType {
	case model.RecordTypePackage:
		var rec model.Record
		if err := json.Unmarshal(line, &rec); err != nil {
			return fmt.Errorf("terminal sink: decode package record: %w", err)
		}
		if rec.Ecosystem == "" {
			rec.Ecosystem = "unknown"
		}
		t.packageCounts[rec.Ecosystem]++
	case model.RecordTypeFinding:
		var finding model.Finding
		if err := json.Unmarshal(line, &finding); err != nil {
			return fmt.Errorf("terminal sink: decode finding record: %w", err)
		}
		if finding.Severity == "" {
			finding.Severity = "unspecified"
		}
		t.severityCounts[finding.Severity]++
		t.findingCount++
		t.findings = append(t.findings, finding)
		sort.SliceStable(t.findings, func(i, j int) bool {
			li, lj := severityRank(t.findings[i].Severity), severityRank(t.findings[j].Severity)
			if li != lj {
				return li < lj
			}
			if t.findings[i].PackageName != t.findings[j].PackageName {
				return t.findings[i].PackageName < t.findings[j].PackageName
			}
			if t.findings[i].Version != t.findings[j].Version {
				return t.findings[i].Version < t.findings[j].Version
			}
			if t.findings[i].SourceFile != t.findings[j].SourceFile {
				return t.findings[i].SourceFile < t.findings[j].SourceFile
			}
			return t.findings[i].CatalogID < t.findings[j].CatalogID
		})
		if len(t.findings) > terminalFindingLimit {
			t.findings = append([]model.Finding(nil), t.findings[:terminalFindingLimit]...)
		}
	case model.RecordTypeScanSummary:
		var summary model.ScanSummary
		if err := json.Unmarshal(line, &summary); err != nil {
			return fmt.Errorf("terminal sink: decode scan summary: %w", err)
		}
		t.summary = &summary
	default:
		// Ignore diagnostics and any future record types. The terminal view is
		// intentionally presentation-only.
	}
	return nil
}

func (t *TerminalSink) render() error {
	summary := t.summary
	if summary == nil {
		summary = &model.ScanSummary{
			Status:                "unknown",
			PackageRecordsEmitted: t.totalPackages(),
			FindingsEmitted:       t.findingCount,
		}
	}

	if err := t.writeLine(t.styleTitle("Bumblebee scan report")); err != nil {
		return err
	}
	if err := t.writeLine(""); err != nil {
		return err
	}

	if err := t.renderKeyValueTable("Run Summary", []kvRow{
		{"Status", t.styleStatus(summary.Status)},
		{"Duration", formatDuration(summary.DurationMS)},
		{"Files considered", fmt.Sprintf("%d", summary.FilesConsidered)},
		{"Package records", fmt.Sprintf("%d", summary.PackageRecordsEmitted)},
		{"Findings", fmt.Sprintf("%d", summary.FindingsEmitted)},
		{"Suppressed", fmt.Sprintf("%d", summary.PackageRecordsSuppressed)},
		{"Duplicates", fmt.Sprintf("%d", summary.Duplicates)},
		{"Diagnostics", fmt.Sprintf("%d", summary.DiagnosticsCount)},
		{"Timed out", fmt.Sprintf("%t", summary.TimedOut)},
	}); err != nil {
		return err
	}

	if len(summary.Roots) > 0 {
		rows := make([][]string, 0, len(summary.Roots))
		for _, root := range summary.Roots {
			rows = append(rows, []string{root.Kind, clip(root.Path, 80)})
		}
		if err := t.renderTable("Roots", []string{"Kind", "Path"}, rows, nil); err != nil {
			return err
		}
	}

	if len(t.packageCounts) > 0 {
		if err := t.renderTable("Packages by ecosystem", []string{"Ecosystem", "Records"}, t.sortedEcosystemRows(), nil); err != nil {
			return err
		}
	}

	if len(t.severityCounts) > 0 {
		if err := t.renderTable("Findings by severity", []string{"Severity", "Count"}, t.sortedSeverityRows(), map[int]cellTransform{0: t.styleSeverity}); err != nil {
			return err
		}
	}

	if t.findingCount == 0 {
		return t.writeLine("No findings were emitted.")
	}

	sortedFindings := append([]model.Finding(nil), t.findings...)
	sort.SliceStable(sortedFindings, func(i, j int) bool {
		li, lj := severityRank(sortedFindings[i].Severity), severityRank(sortedFindings[j].Severity)
		if li != lj {
			return li < lj
		}
		if sortedFindings[i].PackageName != sortedFindings[j].PackageName {
			return sortedFindings[i].PackageName < sortedFindings[j].PackageName
		}
		if sortedFindings[i].Version != sortedFindings[j].Version {
			return sortedFindings[i].Version < sortedFindings[j].Version
		}
		return sortedFindings[i].SourceFile < sortedFindings[j].SourceFile
	})
	limit := terminalFindingLimit
	if len(sortedFindings) < limit {
		limit = len(sortedFindings)
	}
	rows := make([][]string, 0, limit)
	for _, finding := range sortedFindings[:limit] {
		catalog := finding.CatalogName
		if catalog == "" {
			catalog = finding.CatalogID
		}
		rows = append(rows, []string{
			finding.Severity,
			clip(finding.PackageName, 28),
			clip(finding.Version, 20),
			clip(catalog, 30),
			clip(finding.SourceFile, 48),
		})
	}
	if err := t.renderTable("Findings", []string{"Severity", "Package", "Version", "Catalog", "Source"}, rows, map[int]cellTransform{0: t.styleSeverity}); err != nil {
		return err
	}
	if len(sortedFindings) > limit {
		return t.writeLine(fmt.Sprintf("Showing %d of %d findings.", limit, len(sortedFindings)))
	}
	return nil
}

type kvRow struct {
	label string
	value string
}

type cellTransform func(string) string

func (t *TerminalSink) renderKeyValueTable(title string, rows []kvRow) error {
	cells := make([][]string, 0, len(rows))
	for _, row := range rows {
		cells = append(cells, []string{row.label, row.value})
	}
	return t.renderTable(title, []string{"Metric", "Value"}, cells, nil)
}

func (t *TerminalSink) renderTable(title string, headers []string, rows [][]string, transforms map[int]cellTransform) error {
	if err := t.writeLine(title); err != nil {
		return err
	}
	widths := make([]int, len(headers))
	for i, header := range headers {
		widths[i] = displayWidth(header)
	}
	for _, row := range rows {
		for i := range headers {
			if i >= len(row) {
				continue
			}
			if w := displayWidth(row[i]); w > widths[i] {
				widths[i] = w
			}
		}
	}
	if err := t.writeBorder(widths); err != nil {
		return err
	}
	if err := t.writeRow(headers, widths, nil); err != nil {
		return err
	}
	if err := t.writeBorder(widths); err != nil {
		return err
	}
	for _, row := range rows {
		if err := t.writeRow(row, widths, transforms); err != nil {
			return err
		}
	}
	return t.writeBorder(widths)
}

func (t *TerminalSink) writeBorder(widths []int) error {
	var b strings.Builder
	b.WriteByte('+')
	for _, width := range widths {
		b.WriteString(strings.Repeat("-", width+2))
		b.WriteByte('+')
	}
	return t.writeLine(b.String())
}

func (t *TerminalSink) writeRow(cols []string, widths []int, transforms map[int]cellTransform) error {
	var b strings.Builder
	b.WriteByte('|')
	for i, width := range widths {
		value := ""
		if i < len(cols) {
			value = cols[i]
		}
		pad := width - displayWidth(value)
		if pad < 0 {
			pad = 0
		}
		cell := value + strings.Repeat(" ", pad)
		if transforms != nil {
			if transform, ok := transforms[i]; ok && transform != nil {
				cell = transform(cell)
			}
		}
		b.WriteByte(' ')
		b.WriteString(cell)
		b.WriteByte(' ')
		b.WriteByte('|')
	}
	return t.writeLine(b.String())
}

func (t *TerminalSink) writeLine(line string) error {
	_, err := fmt.Fprintln(t.out, line)
	return err
}

func (t *TerminalSink) totalPackages() int {
	total := 0
	for _, count := range t.packageCounts {
		total += count
	}
	return total
}

func (t *TerminalSink) sortedEcosystemRows() [][]string {
	rows := make([][]string, 0, len(t.packageCounts))
	seen := make(map[string]struct{}, len(t.packageCounts))
	for _, ecosystem := range model.SupportedEcosystems() {
		count, ok := t.packageCounts[ecosystem]
		if !ok {
			continue
		}
		rows = append(rows, []string{ecosystem, fmt.Sprintf("%d", count)})
		seen[ecosystem] = struct{}{}
	}
	if count, ok := t.packageCounts["unknown"]; ok {
		rows = append(rows, []string{"unknown", fmt.Sprintf("%d", count)})
		seen["unknown"] = struct{}{}
	}
	var extras []string
	for ecosystem := range t.packageCounts {
		if _, ok := seen[ecosystem]; ok {
			continue
		}
		extras = append(extras, ecosystem)
	}
	sort.Strings(extras)
	for _, ecosystem := range extras {
		rows = append(rows, []string{ecosystem, fmt.Sprintf("%d", t.packageCounts[ecosystem])})
	}
	return rows
}

func (t *TerminalSink) sortedSeverityRows() [][]string {
	order := []string{"critical", "high", "medium", "low", "unspecified"}
	rows := make([][]string, 0, len(t.severityCounts))
	seen := make(map[string]struct{}, len(t.severityCounts))
	for _, severity := range order {
		count, ok := t.severityCounts[severity]
		if !ok {
			continue
		}
		rows = append(rows, []string{severity, fmt.Sprintf("%d", count)})
		seen[severity] = struct{}{}
	}
	var extras []string
	for severity := range t.severityCounts {
		if _, ok := seen[severity]; ok {
			continue
		}
		extras = append(extras, severity)
	}
	sort.Strings(extras)
	for _, severity := range extras {
		rows = append(rows, []string{severity, fmt.Sprintf("%d", t.severityCounts[severity])})
	}
	return rows
}

func (t *TerminalSink) styleTitle(text string) string {
	return t.colorize(text, "1;36")
}

func (t *TerminalSink) styleStatus(status string) string {
	switch status {
	case model.ScanStatusComplete:
		return t.colorize(strings.ToUpper(status), "1;32")
	case model.ScanStatusPartial:
		return t.colorize(strings.ToUpper(status), "1;33")
	case model.ScanStatusError:
		return t.colorize(strings.ToUpper(status), "1;31")
	default:
		return t.colorize(strings.ToUpper(status), "1;37")
	}
}

func (t *TerminalSink) styleSeverity(text string) string {
	switch strings.ToLower(strings.TrimSpace(text)) {
	case "critical":
		return t.colorize(strings.ToUpper(text), "1;31")
	case "high":
		return t.colorize(strings.ToUpper(text), "31")
	case "medium":
		return t.colorize(strings.ToUpper(text), "33")
	case "low":
		return t.colorize(strings.ToUpper(text), "36")
	case "unspecified":
		return t.colorize(strings.ToUpper(text), "37")
	default:
		return t.colorize(strings.ToUpper(text), "37")
	}
}

func (t *TerminalSink) colorize(text, code string) string {
	if !t.color || text == "" {
		return text
	}
	return "\033[" + code + "m" + text + "\033[0m"
}

func terminalColorEnabled(w io.Writer) bool {
	f, ok := w.(*os.File)
	if !ok {
		return false
	}
	info, err := f.Stat()
	if err != nil {
		return false
	}
	return info.Mode()&os.ModeCharDevice != 0
}

func displayWidth(s string) int {
	return utf8.RuneCountInString(s)
}

func clip(s string, limit int) string {
	if limit <= 0 {
		return ""
	}
	runes := []rune(s)
	if len(runes) <= limit {
		return s
	}
	if limit <= 3 {
		return string(runes[:limit])
	}
	return string(runes[:limit-3]) + "..."
}

func formatDuration(ms int64) string {
	if ms <= 0 {
		return "0s"
	}
	return (time.Duration(ms) * time.Millisecond).String()
}

func severityRank(severity string) int {
	switch strings.ToLower(strings.TrimSpace(severity)) {
	case "critical":
		return 0
	case "high":
		return 1
	case "medium":
		return 2
	case "low":
		return 3
	case "unspecified":
		return 4
	default:
		return 5
	}
}
