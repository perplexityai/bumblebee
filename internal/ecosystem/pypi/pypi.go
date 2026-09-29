// Package pypi scans Python install metadata: *.dist-info/METADATA (PEP 566)
// plus adjacent INSTALLER and direct_url.json, with a fallback for legacy
// *.egg-info/PKG-INFO.
//
// Read-only: no pip/uv commands. Per-file size capped by MaxFileSize.
package pypi

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

const Ecosystem = model.EcosystemPyPI

type Scanner struct {
	MaxFileSize int64
	Emit        func(model.Record)
	Diag        func(level, path, msg string)
}

// IsDistInfoMetadata returns (true, distInfoDir) if path is a METADATA file
// inside an *.dist-info directory.
func IsDistInfoMetadata(path string) (bool, string) {
	if filepath.Base(path) != "METADATA" {
		return false, ""
	}
	dir := filepath.Dir(path)
	if strings.HasSuffix(dir, ".dist-info") {
		return true, dir
	}
	return false, ""
}

// IsEggInfoPKGInfo returns (true, eggInfoDir) for legacy *.egg-info/PKG-INFO.
func IsEggInfoPKGInfo(path string) (bool, string) {
	if filepath.Base(path) != "PKG-INFO" {
		return false, ""
	}
	dir := filepath.Dir(path)
	if strings.HasSuffix(dir, ".egg-info") {
		return true, dir
	}
	return false, ""
}

func (s *Scanner) ScanDistInfo(metadataPath, distInfoDir string, base model.Record) error {
	data, err := s.readBounded(metadataPath)
	if err != nil {
		return err
	}
	name, version := parseRFC822NameVersion(data)
	if name == "" || version == "" {
		// Incomplete or malformed METADATA (missing Name/Version headers)
		// is common in vendored test fixtures and partially-installed
		// trees. Skip with a warning rather than treating it as an error.
		if s.Diag != nil {
			s.Diag("warn", metadataPath, "skipping: METADATA missing Name and/or Version header")
		}
		return nil
	}

	r := base
	r.Ecosystem = Ecosystem
	r.PackageName = name
	r.NormalizedName = normalize.PyPI(name)
	r.Version = version
	r.ProjectPath = sitePackagesProjectPath(distInfoDir)
	r.SourceType = "pypi-dist-info"
	r.SourceFile = metadataPath
	r.Confidence = "high"

	// Adjacent INSTALLER. PEP 627 says the file should be a single line
	// naming the tool that wrote the dist-info (e.g. "pip", "uv", "poetry").
	// Empty files are common in editable installs; treat as absent.
	if installer, ok := s.readOptional(filepath.Join(distInfoDir, "INSTALLER")); ok {
		if v := strings.TrimSpace(string(installer)); v != "" {
			r.PackageManager = v
		}
	}
	// Adjacent direct_url.json (PEP 610) — flags the install as a direct
	// dependency. The URL itself is no longer recorded; receivers that
	// need provenance can look at source_file + project_path.
	if du, ok := s.readOptional(filepath.Join(distInfoDir, "direct_url.json")); ok {
		var directURL struct {
			URL string `json:"url"`
		}
		if err := json.Unmarshal(du, &directURL); err == nil && directURL.URL != "" {
			d := true
			r.DirectDependency = &d
		}
	}
	s.Emit(r)
	return nil
}

func (s *Scanner) ScanEggInfo(pkgInfoPath, eggInfoDir string, base model.Record) error {
	data, err := s.readBounded(pkgInfoPath)
	if err != nil {
		return err
	}
	name, version := parseRFC822NameVersion(data)
	if name == "" || version == "" {
		if s.Diag != nil {
			s.Diag("warn", pkgInfoPath, "skipping: PKG-INFO missing Name and/or Version header")
		}
		return nil
	}
	r := base
	r.Ecosystem = Ecosystem
	r.PackageName = name
	r.NormalizedName = normalize.PyPI(name)
	r.Version = version
	r.ProjectPath = sitePackagesProjectPath(eggInfoDir)
	r.SourceType = "pypi-egg-info"
	r.SourceFile = pkgInfoPath
	r.Confidence = "medium"
	// Sibling INSTALLER (rare for .egg-info but populated by some tooling).
	if installer, ok := s.readOptional(filepath.Join(eggInfoDir, "INSTALLER")); ok {
		if v := strings.TrimSpace(string(installer)); v != "" {
			r.PackageManager = v
		}
	}
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

func (s *Scanner) readOptional(path string) ([]byte, bool) {
	info, err := os.Stat(path)
	if err != nil || !info.Mode().IsRegular() {
		return nil, false
	}
	if s.MaxFileSize > 0 && info.Size() > s.MaxFileSize {
		return nil, false
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, false
	}
	return b, true
}

// parseRFC822NameVersion reads only the header block of an RFC-822 style
// METADATA / PKG-INFO file. It stops at the first blank line so the
// (potentially large) description payload is not scanned.
func parseRFC822NameVersion(data []byte) (name, version string) {
	br := bufio.NewReader(bytes.NewReader(data))
	for {
		line, err := br.ReadString('\n')
		trim := strings.TrimRight(line, "\r\n")
		if trim == "" {
			break
		}
		// Continuation lines start with whitespace; skip them (we only
		// care about Name/Version which are single-line in practice).
		if len(trim) > 0 && (trim[0] == ' ' || trim[0] == '\t') {
			if errors.Is(err, io.EOF) {
				break
			}
			continue
		}
		if idx := strings.IndexByte(trim, ':'); idx > 0 {
			key := strings.TrimSpace(trim[:idx])
			val := strings.TrimSpace(trim[idx+1:])
			switch strings.ToLower(key) {
			case "name":
				if name == "" {
					name = val
				}
			case "version":
				if version == "" {
					version = val
				}
			}
		}
		if name != "" && version != "" {
			break
		}
		if err != nil {
			break
		}
	}
	return name, version
}

// sitePackagesProjectPath returns the site-packages-equivalent directory that
// owns the dist-info/egg-info, by stripping that one trailing component.
func sitePackagesProjectPath(metaDir string) string {
	return filepath.Dir(metaDir)
}
