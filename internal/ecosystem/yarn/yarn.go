// Package yarn scans yarn.lock files (Yarn Classic v1 and Yarn Berry v2+).
//
// Yarn Classic uses a custom indentation-based format. Berry's yarn.lock is
// the same format with a leading __metadata block. We line-scan, capturing
// every entry header (a line ending in ':' that lists one or more
// "name@spec" descriptors) and the entry's "version" / "resolved" /
// "integrity" lines.
package yarn

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/perplexityai/bumblebee/internal/model"
	"github.com/perplexityai/bumblebee/internal/normalize"
)

const Ecosystem = model.EcosystemNPM

type Scanner struct {
	MaxFileSize int64
	Emit        func(model.Record)
	Diag        func(level, path, msg string)
}

func IsLockfile(base string) bool { return base == "yarn.lock" }

func (s *Scanner) ScanLockfile(path string, base model.Record) error {
	data, err := s.readBounded(path)
	if err != nil {
		return err
	}
	projectPath := filepath.Dir(path)
	entries := parseYarnLock(data)
	directs := loadDirectDeps(filepath.Join(projectPath, "package.json"), s.MaxFileSize, s.Diag)
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
		r.PackageManager = "yarn"
		r.SourceType = "yarn-lockfile"
		r.SourceFile = path
		if directs != nil {
			d := directs[e.name]
			r.DirectDependency = &d
		}
		r.Confidence = "high"
		s.Emit(r)
	}
	return nil
}

// loadDirectDeps reads a package.json sibling to the lockfile and returns a
// set of package names that appear in any top-level dependency section
// (dependencies, devDependencies, optionalDependencies, peerDependencies).
// Returns nil if the file is missing, unreadable, oversized, or unparseable —
// callers should treat nil as "unknown" and leave DirectDependency absent.
//
// A non-nil diag is invoked for read or parse failures of a package.json
// that exists; missing or non-regular files are silent (the common case is
// a lockfile checked into a repo without a sibling package.json).
func loadDirectDeps(path string, maxSize int64, diag func(level, path, msg string)) map[string]bool {
	info, err := os.Stat(path)
	if err != nil || !info.Mode().IsRegular() {
		return nil
	}
	if maxSize > 0 && info.Size() > maxSize {
		if diag != nil {
			diag("warn", path, "skipping direct-dependency resolution: package.json exceeds max file size")
		}
		return nil
	}
	data, err := os.ReadFile(path)
	if err != nil {
		if diag != nil {
			diag("warn", path, "read package.json for direct-dependency resolution: "+err.Error())
		}
		return nil
	}
	var pj struct {
		Dependencies         map[string]string `json:"dependencies"`
		DevDependencies      map[string]string `json:"devDependencies"`
		OptionalDependencies map[string]string `json:"optionalDependencies"`
		PeerDependencies     map[string]string `json:"peerDependencies"`
	}
	if err := json.Unmarshal(data, &pj); err != nil {
		if diag != nil {
			diag("warn", path, "parse package.json for direct-dependency resolution: "+err.Error())
		}
		return nil
	}
	out := map[string]bool{}
	for n := range pj.Dependencies {
		out[n] = true
	}
	for n := range pj.DevDependencies {
		out[n] = true
	}
	for n := range pj.OptionalDependencies {
		out[n] = true
	}
	for n := range pj.PeerDependencies {
		out[n] = true
	}
	return out
}

type yarnEntry struct {
	name    string
	version string
}

func parseYarnLock(data []byte) []yarnEntry {
	var out []yarnEntry
	sc := bufio.NewScanner(bytes.NewReader(data))
	sc.Buffer(make([]byte, 0, 64*1024), 4*1024*1024)
	var cur *yarnEntry
	flush := func() {
		if cur != nil && cur.name != "" && cur.version != "" {
			out = append(out, *cur)
		}
		cur = nil
	}
	for sc.Scan() {
		raw := sc.Text()
		if strings.HasPrefix(raw, "#") || strings.TrimSpace(raw) == "" {
			continue
		}
		if !strings.HasPrefix(raw, " ") && !strings.HasPrefix(raw, "\t") {
			// New entry header (top-level, ends with ':').
			if !strings.HasSuffix(raw, ":") {
				continue
			}
			flush()
			header := strings.TrimSuffix(raw, ":")
			name := nameFromYarnHeader(header)
			if name == "__metadata" {
				continue
			}
			cur = &yarnEntry{name: name}
			continue
		}
		if cur == nil {
			continue
		}
		line := strings.TrimSpace(raw)
		// First-wins: yarn (Classic and Berry) always emits the entry's own
		// version as the first field, so any later match is a dependency
		// literally named "version" inside a dependencies:/peerDependencies:
		// block, not the entry version.
		if (strings.HasPrefix(line, "version ") || strings.HasPrefix(line, "version:")) && cur.version == "" {
			cur.version = unquote(trimField(line, "version"))
		}
	}
	flush()
	return out
}

func trimField(line, key string) string {
	s := strings.TrimSpace(strings.TrimPrefix(line, key))
	s = strings.TrimPrefix(s, ":")
	return strings.TrimSpace(s)
}

// nameFromYarnHeader extracts the package name from a header like:
//
//	"lodash@^4.17.0":
//	"@scope/pkg@^1.0.0, @scope/pkg@^1.1.0":
//	"lodash@npm:^4.17.0":
//
// Multi-descriptor headers may also appear with commas inside a Berry spec
// (e.g. `"foo@npm:>=1, <2":`). To pick the first descriptor without breaking
// quoted/escaped regions, the split respects quoted segments: only commas
// outside of single/double quotes terminate the first descriptor.
func nameFromYarnHeader(header string) string {
	header = strings.TrimSpace(header)
	// If the header begins with a quote, take the content up to the matching
	// closing quote, ignoring commas inside the quoted region.
	if len(header) > 0 && (header[0] == '"' || header[0] == '\'') {
		q := header[0]
		end := -1
		for i := 1; i < len(header); i++ {
			c := header[i]
			if c == '\\' && i+1 < len(header) {
				i++
				continue
			}
			if c == q {
				end = i
				break
			}
		}
		if end > 0 {
			header = header[1:end]
		} else {
			header = strings.Trim(header, "\"'")
		}
	}
	// Now look for the first comma that splits multiple descriptors. The
	// payload after unquoting cannot contain a literal `,` *within* one
	// descriptor at the Yarn classic level, but Berry specs may. Be
	// conservative: split on the first ", " (comma followed by space) which
	// is the canonical separator Yarn emits between descriptors. A bare
	// comma without a following space is treated as part of the spec.
	if i := strings.Index(header, ", "); i >= 0 {
		header = header[:i]
	}
	header = strings.TrimSpace(header)
	header = strings.Trim(header, "\"'")
	// Scoped: @scope/pkg@spec
	if strings.HasPrefix(header, "@") {
		// Find the SECOND '@' (after the scope).
		if slash := strings.IndexByte(header, '/'); slash >= 0 {
			rest := header[slash:]
			if at := strings.IndexByte(rest, '@'); at >= 0 {
				return header[:slash+at]
			}
		}
		return header
	}
	if at := strings.IndexByte(header, '@'); at >= 0 {
		return header[:at]
	}
	return header
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
