// Package rubygems scans Bundler artifacts (Gemfile.lock) and installed
// gemspec files.
//
// Gemfile.lock format is well-defined and stable. The parser only reads the
// GEM/GIT/PATH "specs:" blocks for top-level "name (version)" lines.
// Nested dependency lines (further indented) are ignored to avoid
// double-counting transitive deps as their own gems.
//
// Installed *.gemspec files are read for Name + Version via a simple text
// parser (no Ruby interpretation). This is a deliberately conservative
// reader that handles the canonical generated gemspec form.
package rubygems

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/perplexityai/bumblebee/internal/model"
)

const Ecosystem = model.EcosystemRubyGems

type Scanner struct {
	MaxFileSize int64
	Emit        func(model.Record)
	Diag        func(level, path, msg string)
}

func IsGemfileLock(base string) bool { return base == "Gemfile.lock" }
func IsGemspec(base string) bool     { return strings.HasSuffix(base, ".gemspec") }

func (s *Scanner) ScanGemfileLock(path string, base model.Record) error {
	data, err := s.readBounded(path)
	if err != nil {
		return err
	}
	projectPath := filepath.Dir(path)
	gems := parseGemfileLock(data)
	for _, g := range gems {
		r := base
		r.Ecosystem = Ecosystem
		r.PackageName = g.name
		r.NormalizedName = strings.ToLower(g.name)
		r.Version = g.version
		r.ProjectPath = projectPath
		r.PackageManager = "bundler"
		r.SourceType = "rubygems-gemfile-lock"
		r.SourceFile = path
		r.Confidence = "high"
		s.Emit(r)
	}
	return nil
}

type gemEntry struct {
	name    string
	version string
	section string
}

func parseGemfileLock(data []byte) []gemEntry {
	var out []gemEntry
	sc := bufio.NewScanner(bytes.NewReader(data))
	sc.Buffer(make([]byte, 0, 64*1024), 4*1024*1024)
	section := ""
	inSpecs := false
	for sc.Scan() {
		raw := sc.Text()
		trim := strings.TrimSpace(raw)
		if !strings.HasPrefix(raw, " ") && trim != "" {
			// Section header.
			switch trim {
			case "GEM", "GIT", "PATH", "PLATFORMS", "DEPENDENCIES", "RUBY VERSION", "BUNDLED WITH", "CHECKSUMS":
				section = trim
				inSpecs = false
			default:
				section = ""
				inSpecs = false
			}
			continue
		}
		if section != "GEM" && section != "GIT" && section != "PATH" {
			continue
		}
		// "  specs:" header.
		if trim == "specs:" {
			inSpecs = true
			continue
		}
		if !inSpecs {
			continue
		}
		// Top-level gem line: exactly 4 spaces of indent.
		if strings.HasPrefix(raw, "    ") && !strings.HasPrefix(raw, "      ") {
			name, ver := parseGemfileLockSpec(trim)
			if name != "" && ver != "" {
				out = append(out, gemEntry{name: name, version: ver, section: section})
			}
		}
	}
	return out
}

var gemSpecRe = regexp.MustCompile(`^([A-Za-z0-9_.\-]+)\s*\(([^)]+)\)$`)

func parseGemfileLockSpec(s string) (string, string) {
	m := gemSpecRe.FindStringSubmatch(s)
	if m == nil {
		return "", ""
	}
	// Gemfile.lock version field may be "1.2.3" or "1.2.3-x86_64-linux".
	return m[1], strings.TrimSpace(m[2])
}

// IsInstalledGemspec returns (true, gemsDir) for paths under
// .../specifications/<name>-<ver>.gemspec or a `gems/<name>-<ver>/<name>.gemspec`
// shape that is clearly under a recognized installed-gems root.
//
// We accept the gems/<name>-<ver>/ form only when:
//   - the immediate parent dir name is `<name>-<ver>` (contains a `-`), AND
//   - its grandparent is named `gems`, AND
//   - the gemspec basename matches the `<name>` prefix of the parent dir name
//     (real installed gems have `gems/foo-1.2.3/foo.gemspec`), AND
//   - the great-grandparent is a recognized gem-root indicator (has a sibling
//     `specifications/` dir, or is one of `bundler`, `rubygems`, `.bundle`,
//     `cache`, or itself contains a `cache/` subtree, or is `vendor`).
//
// This rejects arbitrary `~/proj/gems/foo-1.0/foo.gemspec` trees that are not
// actually installed-gem metadata.
func IsInstalledGemspec(path string) (bool, string) {
	if !IsGemspec(filepath.Base(path)) {
		return false, ""
	}
	parent := filepath.Dir(path)
	pb := filepath.Base(parent)
	gparent := filepath.Dir(parent)
	gpb := filepath.Base(gparent)
	// specifications/<name>-<ver>.gemspec — canonical installed metadata.
	if pb == "specifications" {
		return true, parent
	}
	// gems/<name>-<ver>/<name>.gemspec — only when the shape is clearly an
	// installed gem tree.
	if gpb != "gems" || !strings.Contains(pb, "-") {
		return false, ""
	}
	// Filename must match the `<name>` prefix of the parent dir.
	bn := strings.TrimSuffix(filepath.Base(path), ".gemspec")
	dash := strings.LastIndexByte(pb, '-')
	if dash <= 0 {
		return false, ""
	}
	if pb[:dash] != bn {
		return false, ""
	}
	// Great-grandparent must look like an installed-gems root: either has a
	// sibling `specifications/` directory, or is one of the recognized roots.
	ggparent := filepath.Dir(gparent)
	if isInstalledGemRoot(ggparent) {
		return true, parent
	}
	return false, ""
}

func isInstalledGemRoot(dir string) bool {
	if dir == "" || dir == "." || dir == "/" {
		return false
	}
	// Sibling specifications/ directory is the strongest signal: a gem home
	// has both `gems/` and `specifications/` under the same parent.
	if info, err := os.Stat(filepath.Join(dir, "specifications")); err == nil && info.IsDir() {
		return true
	}
	bn := filepath.Base(dir)
	switch bn {
	case "bundler", "rubygems", ".bundle", "vendor", "cache":
		return true
	}
	// RubyGems install layout: <root>/gems/<ruby_abi>/gems/<name>-<ver>/.
	// Great-grandparent of the gemspec is `<root>/gems/<ruby_abi>` whose
	// parent is `gems`. Accept that nesting.
	if filepath.Base(filepath.Dir(dir)) == "gems" && looksLikeRubyABI(bn) {
		return true
	}
	// Common Bundler layouts: vendor/bundle/ruby/<ver>/gems/...
	parent := filepath.Dir(dir)
	if filepath.Base(parent) == "ruby" {
		gp := filepath.Dir(parent)
		gpb := filepath.Base(gp)
		if gpb == "bundle" || gpb == "vendor" {
			return true
		}
	}
	return false
}

// looksLikeRubyABI reports whether s looks like a Ruby ABI version such as
// "3.2.0" or "2.7.0". This is the directory name RubyGems uses under
// `<gem_home>/gems/`.
func looksLikeRubyABI(s string) bool {
	if s == "" {
		return false
	}
	hasDigit := false
	for i := range len(s) {
		c := s[i]
		if c >= '0' && c <= '9' {
			hasDigit = true
			continue
		}
		if c == '.' {
			continue
		}
		return false
	}
	return hasDigit
}

var (
	gemspecNameRe = regexp.MustCompile(`(?m)^\s*\w+\.name\s*=\s*["']([^"']+)["']`)
	// Matches the canonical generated gemspec forms:
	//   s.version = "1.2.3"
	//   s.version = Gem::Version.new("1.2.3")
	//   s.version = Gem::Version.new('1.2.3')
	gemspecVersionRe = regexp.MustCompile(`(?m)^\s*\w+\.version\s*=\s*(?:Gem::Version\.new\(\s*)?["']([^"']+)["']`)
)

func (s *Scanner) ScanGemspec(path, projectPath string, base model.Record) error {
	data, err := s.readBounded(path)
	if err != nil {
		return err
	}
	name := firstSubmatch(gemspecNameRe, data)
	version := firstSubmatch(gemspecVersionRe, data)
	if name == "" || version == "" {
		// Prefer the parent dir "<name>-<version>" for `gems/<name>-<ver>/<name>.gemspec`:
		// the directory carries both fields, while the filename has only the name.
		parent := filepath.Base(filepath.Dir(path))
		if i := strings.LastIndexByte(parent, '-'); i > 0 && filepath.Base(filepath.Dir(filepath.Dir(path))) == "gems" {
			n2, v2 := parent[:i], parent[i+1:]
			if name == "" {
				name = n2
			}
			if version == "" {
				version = v2
			}
		}
	}
	if name == "" || version == "" {
		// Fall back to filename pattern "<name>-<version>.gemspec"
		// (this is the canonical specifications/ form).
		bn := strings.TrimSuffix(filepath.Base(path), ".gemspec")
		if i := strings.LastIndexByte(bn, '-'); i > 0 {
			n2, v2 := bn[:i], bn[i+1:]
			if name == "" {
				name = n2
			}
			if version == "" {
				version = v2
			}
		}
	}
	if name == "" || version == "" {
		return fmt.Errorf("incomplete gemspec at %s", path)
	}
	r := base
	r.Ecosystem = Ecosystem
	r.PackageName = name
	r.NormalizedName = strings.ToLower(name)
	r.Version = version
	r.ProjectPath = projectPath
	r.PackageManager = "rubygems"
	r.SourceType = "rubygems-gemspec"
	r.SourceFile = path
	r.Confidence = "medium"
	s.Emit(r)
	return nil
}

func firstSubmatch(re *regexp.Regexp, data []byte) string {
	m := re.FindSubmatch(data)
	if len(m) < 2 {
		return ""
	}
	return string(m[1])
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
