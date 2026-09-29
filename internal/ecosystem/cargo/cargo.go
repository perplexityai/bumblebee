// Package cargo scans Rust/Cargo package artifacts.
//
// Two on-disk surfaces are read:
//
//   - `~/.cargo/.crates2.json` — the canonical record of every binary
//     installed via `cargo install`. Highest-confidence baseline source:
//     each entry names the crate, version, and source registry.
//   - `Cargo.lock` — TOML lockfile listing the resolved dependency tree.
//     Higher-confidence than `Cargo.toml` because versions are pinned.
//
// No `cargo` commands are executed. Detection is path-/filename-based.
// `Cargo.toml` (the manifest) is intentionally not parsed: version
// requirements there are ranges rather than exact pins and would
// produce ambiguous records.
package cargo

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
)

const Ecosystem = model.EcosystemCargo

const (
	packageManager      = "cargo"
	crates2SourceType   = "cargo-crates2-installs"
	cargoLockSourceType = "cargo-lock"
	crates2FileName     = ".crates2.json"
	cargoLockFileName   = "Cargo.lock"
	cargoDirName        = ".cargo"
)

type Scanner struct {
	MaxFileSize int64
	Emit        func(model.Record)
	Diag        func(level, path, msg string)
}

// IsCargoLock reports whether base is a Cargo lockfile.
func IsCargoLock(base string) bool { return base == cargoLockFileName }

// IsCrates2JSON reports whether path is `<cargo home>/.crates2.json`.
// Dispatch is path-aware rather than basename-only because `.crates2.json`
// is unique to Cargo and only meaningful inside a Cargo home directory.
func IsCrates2JSON(path string) bool {
	return filepath.Base(path) == crates2FileName &&
		filepath.Base(filepath.Dir(path)) == cargoDirName
}

// crates2File is the on-disk shape of `~/.cargo/.crates2.json`. Cargo
// writes a single `installs` object whose keys are
// `"<name> <version> (<source>)"` triples. The value carries install
// metadata; we only consult `bins` to record whether the entry produced
// any binaries (a hint that informs the high-confidence default).
type crates2File struct {
	Installs map[string]crates2Install `json:"installs"`
}

type crates2Install struct {
	Bins []string `json:"bins"`
}

func (s *Scanner) ScanCrates2JSON(path string, base model.Record) error {
	data, err := s.readBounded(path)
	if err != nil {
		return err
	}
	var doc crates2File
	if err := json.Unmarshal(data, &doc); err != nil {
		if s.Diag != nil {
			s.Diag("warn", path, "skipping malformed .crates2.json: "+err.Error())
		}
		return nil
	}
	projectPath := filepath.Dir(path)
	for key := range doc.Installs {
		name, version, ok := parseCrates2InstallKey(key)
		if !ok {
			continue
		}
		r := base
		r.Ecosystem = Ecosystem
		r.PackageName = name
		r.NormalizedName = strings.ToLower(name)
		r.Version = version
		r.ProjectPath = projectPath
		r.PackageManager = packageManager
		r.SourceType = crates2SourceType
		r.SourceFile = path
		// `.crates2.json` only records crates the user explicitly ran
		// `cargo install` on, so every entry is a direct dependency.
		direct := true
		r.DirectDependency = &direct
		r.Confidence = "high"
		s.Emit(r)
	}
	return nil
}

// parseCrates2InstallKey splits a `.crates2.json` install key into its
// crate name and version. The key shape is
// `"<name> <version> (<source>)"` — a crate-name token, a SemVer token,
// then a parenthesized source descriptor. Crate names never contain
// spaces or parentheses, so a left-to-right split on the first two
// spaces is unambiguous.
func parseCrates2InstallKey(key string) (name, version string, ok bool) {
	key = strings.TrimSpace(key)
	if key == "" {
		return "", "", false
	}
	sp1 := strings.IndexByte(key, ' ')
	if sp1 <= 0 {
		return "", "", false
	}
	name = key[:sp1]
	rest := key[sp1+1:]
	sp2 := strings.IndexByte(rest, ' ')
	if sp2 <= 0 {
		// No source segment; tolerate `"<name> <version>"` shape.
		version = strings.TrimSpace(rest)
		return name, version, version != ""
	}
	version = rest[:sp2]
	return name, version, name != "" && version != ""
}

// ScanCargoLock emits a Record for every third-party crate recorded
// in a Cargo.lock file. The lockfile is the authoritative list of
// resolved package versions for a Rust project, including transitive
// dependencies pulled in from a registry.
func (s *Scanner) ScanCargoLock(path string, base model.Record) error {
	data, err := s.readBounded(path)
	if err != nil {
		return err
	}
	projectPath := filepath.Dir(path)
	pkgs := parseCargoLockPackages(data)
	seen := make(map[string]struct{}, len(pkgs))
	for _, p := range pkgs {
		if p.name == "" || p.version == "" {
			continue
		}
		// Skip workspace-local crates (root package and path-dependency
		// siblings): they are the user's own code, not registry-sourced
		// third-party artifacts. Catalog matching is name+version only and
		// doesn't consult the source, so a local crate sharing a name with
		// a published malicious one would otherwise produce a false positive.
		if p.source == "" {
			continue
		}
		key := p.name + "\x00" + p.version
		if _, dup := seen[key]; dup {
			continue
		}
		seen[key] = struct{}{}
		r := base
		r.Ecosystem = Ecosystem
		r.PackageName = p.name
		r.NormalizedName = strings.ToLower(p.name)
		r.Version = p.version
		r.ProjectPath = projectPath
		r.PackageManager = packageManager
		r.SourceType = cargoLockSourceType
		r.SourceFile = path
		r.Confidence = "high"
		s.Emit(r)
	}
	return nil
}

type cargoLockPackage struct {
	name    string
	version string
	source  string
}

// parseCargoLockPackages scans a Cargo.lock TOML body for `[[package]]`
// blocks and pulls name/version/source from each. The parser is
// deliberately minimal: Cargo.lock is machine-generated with a stable
// shape (one quoted-string value per line, no inline tables for the
// fields we care about), so a line-oriented scan is sufficient and
// keeps the scanner dependency-free.
func parseCargoLockPackages(data []byte) []cargoLockPackage {
	var out []cargoLockPackage
	sc := bufio.NewScanner(bytes.NewReader(data))
	sc.Buffer(make([]byte, 0, 64*1024), 4*1024*1024)
	inPackage := false
	var current cargoLockPackage
	flush := func() {
		if inPackage {
			out = append(out, current)
		}
		current = cargoLockPackage{}
		inPackage = false
	}
	for sc.Scan() {
		raw := sc.Text()
		line := strings.TrimSpace(raw)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if strings.HasPrefix(line, "[") {
			flush()
			if line == "[[package]]" {
				inPackage = true
			}
			continue
		}
		if !inPackage {
			continue
		}
		key, value, ok := parseCargoLockField(line)
		if !ok {
			continue
		}
		switch key {
		case "name":
			current.name = value
		case "version":
			current.version = value
		case "source":
			current.source = value
		}
	}
	flush()
	return out
}

// parseCargoLockField extracts the key and quoted-string value from a
// line shaped like `key = "value"`.
func parseCargoLockField(line string) (key, value string, ok bool) {
	eq := strings.IndexByte(line, '=')
	if eq <= 0 {
		return "", "", false
	}
	key = strings.TrimSpace(line[:eq])
	rest := strings.TrimSpace(line[eq+1:])
	if len(rest) < 2 || rest[0] != '"' {
		return "", "", false
	}
	rest = rest[1:]
	end := strings.IndexByte(rest, '"')
	if end < 0 {
		return "", "", false
	}
	return key, rest[:end], true
}

// readBounded opens path and returns its contents, refusing anything
// that is not a regular file or that exceeds MaxFileSize
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
