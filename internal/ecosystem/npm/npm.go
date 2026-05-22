// Package npm scans npm artifacts: package-lock.json, npm-shrinkwrap.json,
// node_modules/<pkg>/package.json and node_modules/.package-lock.json.
//
// Files are read at most once each, capped by MaxFileSize. No npm/yarn/pnpm
// commands are executed.
package npm

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

const Ecosystem = model.EcosystemNPM

// Scanner emits npm Records via the supplied Emit callback. Emit must be
// safe for concurrent use; the scanner itself is sequential per file.
type Scanner struct {
	MaxFileSize int64
	Emit        func(model.Record)
	Diag        func(level, path, msg string)
}

// lockfile is the union of fields we read from package-lock.json /
// npm-shrinkwrap.json across lockfileVersion 1, 2, and 3.
type lockfile struct {
	LockfileVersion int                  `json:"lockfileVersion"`
	Packages        map[string]lockEntry `json:"packages"`     // v2/v3
	Dependencies    map[string]lockDepV1 `json:"dependencies"` // v1, also present in v2 mirror
}

type lockEntry struct {
	Version  string            `json:"version"`
	Name     string            `json:"name"`
	Dev      bool              `json:"dev"`
	Optional bool              `json:"optional"`
	Link     bool              `json:"link"`
	Scripts  map[string]string `json:"scripts"`
}

type lockDepV1 struct {
	Version  string               `json:"version"`
	Dev      bool                 `json:"dev"`
	Optional bool                 `json:"optional"`
	Requires map[string]string    `json:"requires"`
	Deps     map[string]lockDepV1 `json:"dependencies"`
}

// packageJSON captures fields from node_modules/<pkg>/package.json that we need.
type packageJSON struct {
	Name    string            `json:"name"`
	Version string            `json:"version"`
	Scripts map[string]string `json:"scripts"`
}

// IsLockfile reports whether a basename is an npm lockfile we should parse.
func IsLockfile(base string) bool {
	switch base {
	case "package-lock.json", "npm-shrinkwrap.json", ".package-lock.json":
		return true
	}
	return false
}

// IsNodeModulesPackageJSON returns (true, projectPath) if path looks like a
// node_modules package.json at bounded depth:
//
//	.../node_modules/<pkg>/package.json
//	.../node_modules/@scope/<pkg>/package.json
//
// projectPath is the directory containing the top-level node_modules.
func IsNodeModulesPackageJSON(path string) (bool, string) {
	if filepath.Base(path) != "package.json" {
		return false, ""
	}
	parts := strings.Split(filepath.ToSlash(path), "/")
	// Need at least: node_modules/<pkg>/package.json
	if len(parts) < 3 {
		return false, ""
	}
	// Find the LAST node_modules so nested installs map to the nearest project.
	nmIdx := -1
	for i := len(parts) - 1; i >= 0; i-- {
		if parts[i] == "node_modules" {
			nmIdx = i
			break
		}
	}
	if nmIdx < 0 {
		return false, ""
	}
	tail := parts[nmIdx+1:]
	// Expected tails: [pkg, package.json] or [@scope, pkg, package.json].
	switch len(tail) {
	case 2:
		if strings.HasPrefix(tail[0], "@") {
			return false, ""
		}
	case 3:
		if !strings.HasPrefix(tail[0], "@") {
			return false, ""
		}
	default:
		return false, ""
	}
	projectPath := filepath.FromSlash(strings.Join(parts[:nmIdx], "/"))
	if projectPath == "" {
		// The lockfile lives at a relative path like "node_modules/foo/package.json"
		// (no parent segments). Reporting the absolute root "/" would be
		// misleading; "." is the sane relative-root marker.
		projectPath = "."
	}
	return true, projectPath
}

// ScanLockfile parses an npm lockfile at path and emits records.
func (s *Scanner) ScanLockfile(path string, base model.Record) error {
	data, err := s.readBounded(path)
	if err != nil {
		return err
	}
	var lf lockfile
	if err := json.Unmarshal(data, &lf); err != nil {
		return fmt.Errorf("parse %s: %w", path, err)
	}
	projectPath := filepath.Dir(path)
	pm := "npm"

	switch {
	case len(lf.Packages) > 0: // lockfileVersion 2 or 3
		keys := make([]string, 0, len(lf.Packages))
		for k := range lf.Packages {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, key := range keys {
			entry := lf.Packages[key]
			if key == "" {
				// The "" key is the project root, skip.
				continue
			}
			if entry.Link {
				// Workspace link, not an installed package.
				continue
			}
			name := nameFromPackagesKey(key, entry.Name)
			if name == "" || entry.Version == "" {
				continue
			}
			direct := isDirectFromKey(key)
			scripts := scriptKeys(entry.Scripts)
			r := base
			r.Ecosystem = Ecosystem
			r.PackageName = name
			r.NormalizedName = normalize.NPM(name)
			r.Version = entry.Version
			r.ProjectPath = projectPath
			r.PackageManager = pm
			r.SourceType = "npm-lockfile"
			r.SourceFile = path
			d := direct
			r.DirectDependency = &d
			r.HasLifecycleScripts = len(scripts) > 0
			r.LifecycleScripts = scripts
			r.InstallScope = installScope(entry.Dev)
			r.Confidence = "high"
			s.Emit(r)
		}
	case len(lf.Dependencies) > 0: // lockfileVersion 1
		s.emitDepsV1(lf.Dependencies, path, projectPath, pm, true, base)
	}
	return nil
}

func (s *Scanner) emitDepsV1(deps map[string]lockDepV1, path, projectPath, pm string, direct bool, base model.Record) {
	names := make([]string, 0, len(deps))
	for n := range deps {
		names = append(names, n)
	}
	sort.Strings(names)
	for _, name := range names {
		dep := deps[name]
		if name == "" || dep.Version == "" {
			continue
		}
		r := base
		r.Ecosystem = Ecosystem
		r.PackageName = name
		r.NormalizedName = normalize.NPM(name)
		r.Version = dep.Version
		r.ProjectPath = projectPath
		r.PackageManager = pm
		r.SourceType = "npm-lockfile"
		r.SourceFile = path
		d := direct
		r.DirectDependency = &d
		r.InstallScope = installScope(dep.Dev)
		r.Confidence = "high"
		s.Emit(r)
		if len(dep.Deps) > 0 {
			s.emitDepsV1(dep.Deps, path, projectPath, pm, false, base)
		}
	}
}

// ScanNodeModulesPackageJSON reads metadata for a single installed package.
func (s *Scanner) ScanNodeModulesPackageJSON(path, projectPath string, base model.Record) error {
	data, err := s.readBounded(path)
	if err != nil {
		return err
	}
	var pj packageJSON
	if err := json.Unmarshal(data, &pj); err != nil {
		return fmt.Errorf("parse %s: %w", path, err)
	}
	if pj.Name == "" || pj.Version == "" {
		return fmt.Errorf("incomplete package.json at %s", path)
	}
	scripts := scriptKeys(pj.Scripts)
	r := base
	r.Ecosystem = Ecosystem
	r.PackageName = pj.Name
	r.NormalizedName = normalize.NPM(pj.Name)
	r.Version = pj.Version
	r.ProjectPath = projectPath
	r.PackageManager = "npm"
	r.SourceType = "npm-node_modules"
	r.SourceFile = path
	r.HasLifecycleScripts = len(scripts) > 0
	r.LifecycleScripts = scripts
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

// nameFromPackagesKey extracts the package name from a v2/v3 packages key
// like "node_modules/foo" or "node_modules/@scope/pkg/node_modules/bar".
func nameFromPackagesKey(key, explicit string) string {
	if explicit != "" {
		return explicit
	}
	parts := strings.Split(key, "node_modules/")
	if len(parts) < 2 {
		return ""
	}
	tail := parts[len(parts)-1]
	tail = strings.TrimSuffix(tail, "/")
	if strings.HasPrefix(tail, "@") {
		// Scoped: keep "@scope/name", drop anything after.
		segs := strings.SplitN(tail, "/", 3)
		if len(segs) < 2 {
			return ""
		}
		return segs[0] + "/" + segs[1]
	}
	// Unscoped: take up to first slash.
	if i := strings.IndexByte(tail, '/'); i >= 0 {
		return tail[:i]
	}
	return tail
}

// isDirectFromKey: a top-level dep has exactly one "node_modules/" segment.
func isDirectFromKey(key string) bool {
	return strings.Count(key, "node_modules/") == 1
}

func scriptKeys(m map[string]string) []string {
	// Only the npm lifecycle scripts that npm actually runs on install.
	lifecycle := []string{"preinstall", "install", "postinstall", "prepare", "preprepare", "postprepare"}
	var out []string
	for _, k := range lifecycle {
		if v, ok := m[k]; ok && strings.TrimSpace(v) != "" {
			out = append(out, k)
		}
	}
	return out
}

func installScope(dev bool) string {
	if dev {
		return "dev"
	}
	return "prod"
}
