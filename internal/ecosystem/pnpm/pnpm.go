// Package pnpm scans pnpm artifacts: pnpm-lock.yaml and the
// node_modules/.pnpm/<name>@<version>/node_modules/<name>/package.json layout.
//
// The lockfile parser is intentionally minimal. It does not pull in a YAML
// dependency; it line-scans the top-level "packages:" block and extracts
// version-bearing entry keys. This handles pnpm-lock.yaml v5, v6, and v9
// well enough to inventory installed name@version pairs without executing
// pnpm.
package pnpm

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/perplexityai/bumblebee/internal/model"
	"github.com/perplexityai/bumblebee/internal/normalize"
)

const Ecosystem = model.EcosystemNPM // pnpm installs npm-registry packages; we keep ecosystem=npm.

type Scanner struct {
	MaxFileSize int64
	Emit        func(model.Record)
	Diag        func(level, path, msg string)
}

// IsLockfile reports whether a basename is the pnpm lockfile.
func IsLockfile(base string) bool { return base == "pnpm-lock.yaml" }

// IsPnpmStorePackageJSON returns (true, projectPath, name, version) for a
// package.json under node_modules/.pnpm/<name>@<ver>/node_modules/<name>/package.json.
// projectPath is the directory containing the top-level node_modules.
func IsPnpmStorePackageJSON(path string) (ok bool, projectPath, name, version string) {
	if filepath.Base(path) != "package.json" {
		return false, "", "", ""
	}
	parts := strings.Split(filepath.ToSlash(path), "/")
	// Need at least: node_modules/.pnpm/<dir>/node_modules/<pkg>/package.json
	// Find ".pnpm" segment with surrounding context.
	pnpmIdx := -1
	for i := len(parts) - 1; i >= 1; i-- {
		if parts[i] == ".pnpm" && parts[i-1] == "node_modules" {
			pnpmIdx = i
			break
		}
	}
	if pnpmIdx < 0 || pnpmIdx+4 >= len(parts) {
		return false, "", "", ""
	}
	storeDir := parts[pnpmIdx+1]
	// Expect: storeDir / node_modules / <pkg or @scope> / [pkg /] package.json
	if parts[pnpmIdx+2] != "node_modules" {
		return false, "", "", ""
	}
	tail := parts[pnpmIdx+3:]
	switch len(tail) {
	case 2:
		if strings.HasPrefix(tail[0], "@") {
			return false, "", "", ""
		}
		name = tail[0]
	case 3:
		if !strings.HasPrefix(tail[0], "@") {
			return false, "", "", ""
		}
		name = tail[0] + "/" + tail[1]
	default:
		return false, "", "", ""
	}
	// Extract version from storeDir. Formats:
	//   foo@1.2.3
	//   foo@1.2.3_peer@... (suffix after first underscore is peer set)
	//   @scope+pkg@1.2.3   (scope encoded with +)
	// We only need version.
	name2, ver := splitPnpmStoreDir(storeDir)
	if ver != "" {
		version = ver
	}
	// Cross-check name parity, but trust the on-disk directory name.
	_ = name2
	projectPath = filepath.FromSlash(strings.Join(parts[:pnpmIdx-1], "/"))
	if projectPath == "" {
		// Relative-rooted layout (e.g. "node_modules/.pnpm/..."). Use "." as
		// the relative-root marker rather than the absolute "/".
		projectPath = "."
	}
	return true, projectPath, name, version
}

// splitPnpmStoreDir splits a pnpm store-dir name into (name, version).
//
// Examples:
//
//	lodash@4.17.21                       -> "lodash", "4.17.21"
//	string_decoder@1.1.1                 -> "string_decoder", "1.1.1"
//	@tanstack+query-core@5.0.0           -> "@tanstack/query-core", "5.0.0"
//	@types+babel__core@7.20.5            -> "@types/babel__core", "7.20.5"
//	lodash@4.17.21_react@18.0.0          -> "lodash", "4.17.21"
//	@scope+pkg@1.2.3_peer@4.5.6          -> "@scope/pkg", "1.2.3"
//	string_decoder@1.3.0_react@18.2.0    -> "string_decoder", "1.3.0"
//
// Two real-world subtleties make naive splits wrong:
//
//  1. Package names commonly contain '_' ("string_decoder",
//     "@types/babel__core"), so the peer-id suffix can't be stripped by
//     cutting at the first '_' in the whole string.
//  2. The peer-id suffix itself contains '@' ("_react@18.2.0"), so the
//     last '@' in the string is the PEER version's '@', not the
//     package version's '@'.
//
// The version separator is therefore the FIRST '@' in the string,
// except for scoped names that start with '@' — in that case it's the
// FIRST '@' AFTER index 0. Once the version is split out, peer-id is
// stripped from the version portion only.
func splitPnpmStoreDir(dir string) (name, version string) {
	if dir == "" {
		return "", ""
	}
	searchFrom := 0
	if dir[0] == '@' {
		searchFrom = 1
	}
	rel := strings.IndexByte(dir[searchFrom:], '@')
	if rel < 0 {
		return "", ""
	}
	at := searchFrom + rel
	rawName := dir[:at]
	ver := dir[at+1:]
	if i := strings.IndexByte(ver, '_'); i >= 0 {
		ver = ver[:i]
	}
	if strings.HasPrefix(rawName, "@") {
		rawName = strings.Replace(rawName, "+", "/", 1)
	}
	return rawName, ver
}

// ScanLockfile parses a pnpm-lock.yaml at path and emits records.
//
// The parser is line-oriented and only recognizes the top-level "packages:"
// block. Each entry under that block whose key is "/name@version" (v6+) or
// "/name/version" (v5) is recorded. Sub-fields ("resolution:", "dev:", etc.)
// are recognized up to the next top-level entry. resolution.integrity and
// resolution.tarball are parsed into the in-memory entry for forward
// compatibility but are not emitted on records in v0.1.
func (s *Scanner) ScanLockfile(path string, base model.Record) error {
	data, err := s.readBounded(path)
	if err != nil {
		return err
	}
	projectPath := filepath.Dir(path)
	diag := func(level, msg string) {
		if s.Diag != nil {
			s.Diag(level, path, msg)
		}
	}
	entries := parsePnpmPackages(data, diag)
	directs := parsePnpmImporterDirects(data)

	for _, e := range entries {
		if e.name == "" || e.version == "" {
			continue
		}
		r := base
		r.Ecosystem = Ecosystem
		r.PackageName = e.name
		r.NormalizedName = normalize.NPM(e.name)
		r.Version = e.version
		r.ProjectPath = projectPath
		r.PackageManager = "pnpm"
		r.SourceType = "pnpm-lockfile"
		r.SourceFile = path
		if e.dev {
			r.InstallScope = "dev"
		} else {
			r.InstallScope = "prod"
		}
		// pnpm-lock.yaml's `requiresBuild: true` is a pnpm-specific hint
		// that one or more of preinstall/install/postinstall is defined;
		// it is not itself an npm lifecycle hook name. We surface that
		// flag via HasLifecycleScripts (boolean) and leave LifecycleScripts
		// empty so callers that filter on real hook names (`install`,
		// `postinstall`, ...) are not misled.
		r.HasLifecycleScripts = e.hasScripts
		// Only set DirectDependency when the importers parse produced at
		// least one (name,version) hit. Otherwise — empty importers block,
		// v5-layout with semver-range specifiers we couldn't resolve, or
		// no importers section at all — leave the field absent. A package
		// declared only by a workspace importer can't be cleanly attributed
		// to direct or transitive without resolving workspaces, so missing
		// from the root-importer map deliberately yields `false` rather
		// than absent only when we have evidence the root importer parsed
		// non-trivially.
		if len(directs) > 0 {
			_, ok := directs[directKey(e.name, e.version)]
			d := ok
			r.DirectDependency = &d
		}
		r.Confidence = "high"
		s.Emit(r)
	}
	return nil
}

func directKey(name, version string) string { return name + "\x00" + version }

type pnpmEntry struct {
	name       string
	version    string
	integrity  string
	tarball    string
	dev        bool
	hasScripts bool
}

// parsePnpmPackages line-scans for the top-level "packages:" map and returns
// every entry inside it. It does not depend on a YAML library and relies on
// the following load-bearing invariant:
//
//   - only the top-level `packages:` block is read (not `snapshots:`,
//     `importers:`, `settings:`, etc.);
//   - entry keys under `packages:` are indented at exactly two spaces;
//   - nested fields under each entry are indented at four or more spaces.
//
// pnpm v5/v6/v9 lockfiles emitted by pnpm itself follow this invariant
// uniformly. Other top-level sections in pnpm v9 (e.g. `snapshots:`) use a
// different indent scheme — extending this parser to those sections requires
// re-deriving the indent rules and is intentionally out of scope for v0.1.
//
// When a line under `packages:` has an unexpected indent (>0 but not exactly
// 2 nor >=4 spaces) we emit a one-shot diagnostic via the optional `diag`
// callback so silent drift becomes visible to operators.
func parsePnpmPackages(data []byte, diag func(level, msg string)) []pnpmEntry {
	var out []pnpmEntry
	sc := bufio.NewScanner(bytes.NewReader(data))
	sc.Buffer(make([]byte, 0, 64*1024), 4*1024*1024)
	inPackages := false
	driftWarned := false
	var cur *pnpmEntry
	flush := func() {
		if cur != nil && cur.name != "" && cur.version != "" {
			out = append(out, *cur)
		}
		cur = nil
	}
	for sc.Scan() {
		line := sc.Text()
		if !inPackages {
			// Top-level "packages:" header (no leading spaces).
			if line == "packages:" {
				inPackages = true
			}
			continue
		}
		// Detect leaving the block: any non-blank line with zero indent that
		// is not a comment terminates the packages section.
		if line == "" {
			continue
		}
		if !startsWithSpace(line) && !strings.HasPrefix(line, "#") {
			flush()
			inPackages = false
			continue
		}
		// Indent drift detection. Within `packages:`, a non-empty,
		// non-comment line must be indented either exactly 2 spaces (entry
		// key) or 4+ spaces (nested field). Anything else — including any
		// leading tab — is unexpected.
		if !driftWarned && diag != nil && !strings.HasPrefix(strings.TrimLeft(line, " \t"), "#") {
			if len(line) > 0 && line[0] == '\t' {
				diag("warn", "unexpected pnpm-lock indent in packages block")
				driftWarned = true
			} else {
				n := 0
				for n < len(line) && line[n] == ' ' {
					n++
				}
				if n > 0 && n != 2 && n < 4 {
					diag("warn", "unexpected pnpm-lock indent in packages block")
					driftWarned = true
				}
			}
		}
		// Entry keys are indented by exactly two spaces and end with a colon.
		if strings.HasPrefix(line, "  ") && !strings.HasPrefix(line, "    ") {
			trim := strings.TrimSpace(line)
			if strings.HasSuffix(trim, ":") {
				flush()
				key := strings.TrimSuffix(trim, ":")
				key = strings.Trim(key, "'\"")
				name, ver := splitPnpmLockKey(key)
				cur = &pnpmEntry{name: name, version: ver}
				continue
			}
		}
		// Nested fields under the current entry.
		if cur != nil && strings.HasPrefix(line, "    ") {
			trim := strings.TrimSpace(line)
			switch {
			case strings.HasPrefix(trim, "resolution:"):
				// Inline flow: resolution: {integrity: ..., tarball: ...}
				inline := strings.TrimSpace(strings.TrimPrefix(trim, "resolution:"))
				if strings.HasPrefix(inline, "{") && strings.HasSuffix(inline, "}") {
					for k, v := range parseFlowMap(inline[1 : len(inline)-1]) {
						switch k {
						case "integrity":
							cur.integrity = v
						case "tarball":
							cur.tarball = v
						}
					}
				}
			case strings.HasPrefix(trim, "integrity:"):
				cur.integrity = unquote(strings.TrimSpace(strings.TrimPrefix(trim, "integrity:")))
			case strings.HasPrefix(trim, "tarball:"):
				cur.tarball = unquote(strings.TrimSpace(strings.TrimPrefix(trim, "tarball:")))
			case trim == "dev: true":
				cur.dev = true
			case trim == "requiresBuild: true":
				cur.hasScripts = true
			case strings.HasPrefix(trim, "version:") && cur.version == "":
				cur.version = unquote(strings.TrimSpace(strings.TrimPrefix(trim, "version:")))
			case strings.HasPrefix(trim, "name:") && cur.name == "":
				cur.name = unquote(strings.TrimSpace(strings.TrimPrefix(trim, "name:")))
			}
		}
	}
	flush()
	return out
}

func startsWithSpace(s string) bool {
	return len(s) > 0 && (s[0] == ' ' || s[0] == '\t')
}

// parsePnpmImporterDirects scans a pnpm-lock.yaml for top-level direct
// dependencies and returns a set of "name\x00version" keys. It supports two
// shapes:
//
//   - v6/v9 layout: importers block keyed by importer path (".", "packages/x")
//     each containing dependencies/devDependencies/optionalDependencies/
//     peerDependencies maps. Each entry is `name:` followed by indented
//     `specifier:` and `version:` fields.
//   - v5 legacy layout: top-level dependencies/devDependencies maps with
//     `name: version` flat scalar values.
//
// Only the root importer (key ".") is treated as direct. Workspace importers
// are intentionally skipped — their declared deps don't correspond to
// top-level node_modules and conflating them risks marking transitive
// installs as direct. Resolved versions are stripped of pnpm peer-id
// suffixes such as `1.2.3(react@18)` or `1.2.3_react@18`. If a value looks
// like a semver range rather than a concrete version, it is ignored so the
// matching pass leaves DirectDependency unset ("unknown" rather than guessed).
func parsePnpmImporterDirects(data []byte) map[string]struct{} {
	out := map[string]struct{}{}
	lines := splitLines(data)

	depHeaders := map[string]bool{
		"dependencies:":         true,
		"devDependencies:":      true,
		"optionalDependencies:": true,
		"peerDependencies:":     true,
	}

	record := func(name, val string) {
		val = stripPeerSuffix(val)
		if name == "" || val == "" || !looksLikeVersion(val) {
			return
		}
		out[directKey(name, val)] = struct{}{}
	}

	// State.
	inImporters := false
	inRootImporter := false
	inDepSection := false
	// v5Section is non-empty when we're inside a top-level
	// dependencies/devDependencies/optionalDependencies/peerDependencies
	// block (v5 layout); entries appear at indent 2 as `name: version`.
	inV5DepSection := false
	var curName string

	for _, line := range lines {
		if strings.TrimSpace(line) == "" || strings.HasPrefix(strings.TrimLeft(line, " \t"), "#") {
			continue
		}
		indent := leadingSpaces(line)
		trim := strings.TrimSpace(line)

		if indent == 0 {
			inImporters = trim == "importers:"
			inV5DepSection = depHeaders[trim]
			inRootImporter = false
			inDepSection = false
			curName = ""
			continue
		}

		if inV5DepSection {
			if indent != 2 {
				inV5DepSection = false
				continue
			}
			if i := strings.IndexByte(trim, ':'); i > 0 {
				name := strings.Trim(strings.TrimSpace(trim[:i]), "'\"")
				val := unquote(strings.TrimSpace(trim[i+1:]))
				record(name, val)
			}
			continue
		}

		if !inImporters {
			continue
		}

		if indent == 2 {
			if !strings.HasSuffix(trim, ":") {
				continue
			}
			key := strings.Trim(strings.TrimSuffix(trim, ":"), "'\"")
			inRootImporter = key == "."
			inDepSection = false
			curName = ""
			continue
		}

		if !inRootImporter {
			continue
		}

		if indent == 4 {
			inDepSection = depHeaders[trim]
			curName = ""
			continue
		}

		if !inDepSection {
			continue
		}

		// Indent 6: entry. Either `name:` (v6/v9 nested) or `name: version`.
		if indent == 6 {
			if strings.HasSuffix(trim, ":") {
				curName = strings.Trim(strings.TrimSuffix(trim, ":"), "'\"")
				continue
			}
			if i := strings.IndexByte(trim, ':'); i > 0 {
				name := strings.Trim(strings.TrimSpace(trim[:i]), "'\"")
				val := unquote(strings.TrimSpace(trim[i+1:]))
				record(name, val)
				curName = ""
			}
			continue
		}

		// Indent 8+: nested field under the current entry.
		if indent >= 8 && curName != "" && strings.HasPrefix(trim, "version:") {
			v := unquote(strings.TrimSpace(strings.TrimPrefix(trim, "version:")))
			record(curName, v)
		}
	}
	return out
}

func splitLines(data []byte) []string {
	var out []string
	sc := bufio.NewScanner(bytes.NewReader(data))
	sc.Buffer(make([]byte, 0, 64*1024), 4*1024*1024)
	for sc.Scan() {
		out = append(out, sc.Text())
	}
	return out
}

func leadingSpaces(s string) int {
	n := 0
	for n < len(s) && s[n] == ' ' {
		n++
	}
	return n
}

// stripPeerSuffix removes pnpm peer-id annotations from a resolved version.
// Both "1.2.3(react@18.0.0)" and "1.2.3_react@18.0.0" reduce to "1.2.3".
func stripPeerSuffix(v string) string {
	if i := strings.IndexByte(v, '('); i >= 0 {
		v = v[:i]
	}
	if i := strings.IndexByte(v, '_'); i >= 0 {
		v = v[:i]
	}
	return v
}

// parseFlowMap parses pnpm-resolution flow-mapping bodies like
//
//	"integrity: sha512-aaa, tarball: https://example/x.tgz"
//
// into a map. Scope: this is intended for the pnpm lockfile's `resolution:`
// inline flow only. Values are unquoted scalars; nested flow maps and arrays
// are not parsed. Quotes (single and double) are respected when splitting on
// `,` and when locating the key/value `:` separator, so that a quoted key
// like `"weird:name": v` is decoded as key=`weird:name`.
func parseFlowMap(body string) map[string]string {
	out := map[string]string{}
	// Split on commas, but skip commas inside quotes.
	var fields []string
	depth := 0
	inStr := byte(0)
	start := 0
	for i := 0; i < len(body); i++ {
		c := body[i]
		if inStr != 0 {
			if c == inStr {
				inStr = 0
			}
			continue
		}
		switch c {
		case '\'', '"':
			inStr = c
		case '{', '[':
			depth++
		case '}', ']':
			depth--
		case ',':
			if depth == 0 {
				fields = append(fields, body[start:i])
				start = i + 1
			}
		}
	}
	fields = append(fields, body[start:])
	for _, f := range fields {
		f = strings.TrimSpace(f)
		if f == "" {
			continue
		}
		// Locate the key/value separator, respecting quoted regions so that
		// a `:` inside a quoted key is not treated as the separator.
		sep := -1
		qs := byte(0)
		for i := 0; i < len(f); i++ {
			c := f[i]
			if qs != 0 {
				if c == qs {
					qs = 0
				}
				continue
			}
			if c == '\'' || c == '"' {
				qs = c
				continue
			}
			if c == ':' {
				sep = i
				break
			}
		}
		if sep <= 0 {
			continue
		}
		k := unquote(strings.TrimSpace(f[:sep]))
		v := unquote(strings.TrimSpace(f[sep+1:]))
		out[k] = v
	}
	return out
}

func unquote(s string) string {
	s = strings.TrimSpace(s)
	if len(s) >= 2 {
		if (s[0] == '\'' && s[len(s)-1] == '\'') || (s[0] == '"' && s[len(s)-1] == '"') {
			return s[1 : len(s)-1]
		}
	}
	return s
}

// splitPnpmLockKey extracts (name, version) from a pnpm-lock packages key.
// Supported formats:
//
//	/foo@1.2.3
//	/foo@1.2.3(peer@x.y.z)
//	/@scope/foo@1.2.3
//	foo@1.2.3              (v9)
//	@scope/foo@1.2.3       (v9)
//	/foo/1.2.3             (v5 legacy)
//	/@scope/foo/1.2.3      (v5 legacy)
func splitPnpmLockKey(key string) (name, version string) {
	if key == "" {
		return "", ""
	}
	if key[0] == '/' {
		key = key[1:]
	}
	// Strip peer-set suffix in parentheses.
	if i := strings.IndexByte(key, '('); i >= 0 {
		key = key[:i]
	}
	// v9 unquoted plain form: name@ver
	if at := strings.LastIndexByte(key, '@'); at > 0 {
		candName := key[:at]
		candVer := key[at+1:]
		// Confirm version starts with a digit-ish or v-prefix.
		if looksLikeVersion(candVer) {
			return candName, candVer
		}
	}
	// v5 legacy: name/version. For scoped, last slash separates version.
	if strings.HasPrefix(key, "@") {
		// @scope/pkg/version
		parts := strings.SplitN(key, "/", 3)
		if len(parts) == 3 {
			return parts[0] + "/" + parts[1], parts[2]
		}
	} else {
		if i := strings.LastIndexByte(key, '/'); i > 0 {
			return key[:i], key[i+1:]
		}
	}
	return "", ""
}

func looksLikeVersion(v string) bool {
	if v == "" {
		return false
	}
	c := v[0]
	if c >= '0' && c <= '9' {
		return true
	}
	if c == 'v' || c == 'V' {
		return true
	}
	return false
}

// ScanStorePackageJSON reads a package.json inside the pnpm content-addressed
// store layout and emits a medium-confidence installed-state record. The
// file is opened only to confirm it is a readable regular file within
// MaxFileSize; its contents are not needed because the name and version
// are derived from the store directory name.
func (s *Scanner) ScanStorePackageJSON(path, projectPath, name, version string, base model.Record) error {
	if _, err := s.readBounded(path); err != nil {
		return err
	}
	r := base
	r.Ecosystem = Ecosystem
	r.PackageName = name
	r.NormalizedName = normalize.NPM(name)
	r.Version = version
	r.ProjectPath = projectPath
	r.PackageManager = "pnpm"
	r.SourceType = "pnpm-node_modules"
	r.SourceFile = path
	r.Confidence = "medium"
	s.Emit(r)
	return nil
}

func (s *Scanner) readBounded(path string) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() {
		return nil, errors.New("not a regular file")
	}
	if s.MaxFileSize > 0 && info.Size() > s.MaxFileSize {
		if s.Diag != nil {
			s.Diag("warn", path, fmt.Sprintf("skipping: size %d exceeds max %d", info.Size(), s.MaxFileSize))
		}
		return nil, fmt.Errorf("file %s exceeds max size %d", path, s.MaxFileSize)
	}
	return io.ReadAll(f)
}
