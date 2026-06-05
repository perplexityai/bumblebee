// Package homebrew scans installed Homebrew formula and cask metadata.
//
// Homebrew records are derived from install metadata path shapes only. The
// scanner never executes `brew`; for casks installed from Ruby definitions it
// treats the saved .rb caskfile as an existence marker and does not open it.
package homebrew

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
)

const Ecosystem = model.EcosystemHomebrew

const (
	receiptFile       = "INSTALL_RECEIPT.json"
	packageManager    = "homebrew"
	formulaSourceType = "homebrew-formula-receipt"
	caskSourceType    = "homebrew-cask-metadata"
)

type Scanner struct {
	MaxFileSize int64
	Emit        func(model.Record)
	Diag        func(level, path, msg string)
}

// IsFormulaReceipt reports whether path is a Homebrew formula receipt under
// .../Cellar/<formula>/<version>/INSTALL_RECEIPT.json.
func IsFormulaReceipt(path string) (ok bool, name, version, cellarDir string) {
	if filepath.Base(path) != receiptFile {
		return false, "", "", ""
	}
	kegDir := filepath.Dir(path)
	rackDir := filepath.Dir(kegDir)
	cellarDir = filepath.Dir(rackDir)
	if filepath.Base(cellarDir) != "Cellar" {
		return false, "", "", ""
	}
	name = filepath.Base(rackDir)
	version = filepath.Base(kegDir)
	if invalidPathSegment(name) || invalidPathSegment(version) {
		return false, "", "", ""
	}
	return true, name, version, cellarDir
}

// IsCaskMetadataMarker reports whether path is the preferred installed-cask
// marker for .../Caskroom/<token>/.metadata/<version>/<timestamp>/Casks/.
func IsCaskMetadataMarker(path string) (ok bool, token, version, caskroomDir string) {
	m, ok := parseCaskMetadataPath(path)
	if !ok {
		return false, "", "", ""
	}
	preferred, ok := preferredCaskMarker(m.tokenDir, m.version, m.token)
	if !ok || filepath.Clean(preferred) != m.cleanPath {
		return false, "", "", ""
	}
	return true, m.token, m.version, m.caskroomDir
}

// LooksLikeCaskMetadataMarker reports whether path has the installed-cask
// metadata marker shape, before applying latest-timestamp/preferred-file
// selection.
func LooksLikeCaskMetadataMarker(path string) bool {
	_, ok := parseCaskMetadataPath(path)
	return ok
}

type caskMetadataPath struct {
	cleanPath   string
	token       string
	version     string
	tokenDir    string
	caskroomDir string
}

func parseCaskMetadataPath(path string) (caskMetadataPath, bool) {
	clean := filepath.Clean(path)
	base := filepath.Base(clean)
	markerToken, ok := caskTokenFromMarker(base)
	if !ok {
		return caskMetadataPath{}, false
	}
	casksDir := filepath.Dir(clean)
	timestampDir := filepath.Dir(casksDir)
	versionDir := filepath.Dir(timestampDir)
	metadataDir := filepath.Dir(versionDir)
	tokenDir := filepath.Dir(metadataDir)
	caskroomDir := filepath.Dir(tokenDir)

	if filepath.Base(casksDir) != "Casks" ||
		filepath.Base(metadataDir) != ".metadata" ||
		filepath.Base(caskroomDir) != "Caskroom" {
		return caskMetadataPath{}, false
	}
	token := filepath.Base(tokenDir)
	version := filepath.Base(versionDir)
	if invalidPathSegment(token) || invalidPathSegment(version) || invalidPathSegment(filepath.Base(timestampDir)) {
		return caskMetadataPath{}, false
	}
	if markerToken != token {
		return caskMetadataPath{}, false
	}
	return caskMetadataPath{
		cleanPath:   clean,
		token:       token,
		version:     version,
		tokenDir:    tokenDir,
		caskroomDir: caskroomDir,
	}, true
}

func (s *Scanner) ScanFormulaReceipt(path, name, version, cellarDir string, base model.Record) error {
	data, err := s.readBounded(path)
	if err != nil {
		return err
	}
	var receipt installReceipt
	if err := json.Unmarshal(data, &receipt); err != nil {
		if s.Diag != nil {
			s.Diag("warn", path, "skipping receipt fields: "+err.Error())
		}
		receipt = installReceipt{}
	}

	r := base
	r.Ecosystem = Ecosystem
	r.PackageName = name
	r.NormalizedName = strings.ToLower(strings.TrimSpace(name))
	r.Version = version
	r.ProjectPath = cellarDir
	r.RootKind = model.RootKindHomebrew
	r.PackageManager = packageManager
	r.SourceType = formulaSourceType
	r.SourceFile = path
	r.DirectDependency = receipt.InstalledOnRequest
	r.Confidence = "high"
	s.Emit(r)
	return nil
}

func (s *Scanner) ScanCaskMetadata(path, token, version, caskroomDir string, base model.Record) error {
	tokenDir := filepath.Join(caskroomDir, token)
	receipt := s.readCaskReceipt(filepath.Join(tokenDir, ".metadata", receiptFile))

	r := base
	r.Ecosystem = Ecosystem
	r.PackageName = token
	r.NormalizedName = strings.ToLower(strings.TrimSpace(token))
	r.Version = version
	r.ProjectPath = caskroomDir
	r.RootKind = model.RootKindHomebrew
	r.PackageManager = packageManager
	r.SourceType = caskSourceType
	r.SourceFile = path
	r.DirectDependency = receipt.InstalledOnRequest
	r.Confidence = "high"
	s.Emit(r)
	return nil
}

type installReceipt struct {
	InstalledOnRequest *bool `json:"installed_on_request"`
}

func invalidPathSegment(s string) bool {
	return s == "" || s == "." || s == ".."
}

func caskTokenFromMarker(base string) (string, bool) {
	for _, suffix := range []string{".internal.json", ".json", ".rb"} {
		if strings.HasSuffix(base, suffix) {
			token := strings.TrimSuffix(base, suffix)
			if token != "" {
				return token, true
			}
		}
	}
	return "", false
}

func preferredCaskMarker(tokenDir, version, token string) (string, bool) {
	versionDir := filepath.Join(tokenDir, ".metadata", version)
	entries, err := os.ReadDir(versionDir)
	if err != nil {
		return "", false
	}
	var timestamps []string
	for _, e := range entries {
		if e.IsDir() && !invalidPathSegment(e.Name()) {
			timestamps = append(timestamps, e.Name())
		}
	}
	sort.Strings(timestamps)
	for i := len(timestamps) - 1; i >= 0; i-- {
		casksDir := filepath.Join(versionDir, timestamps[i], "Casks")
		for _, suffix := range []string{".internal.json", ".json", ".rb"} {
			candidate := filepath.Join(casksDir, token+suffix)
			if fileExists(candidate) {
				return candidate, true
			}
		}
	}
	return "", false
}

func fileExists(path string) bool {
	info, err := os.Stat(path)
	return err == nil && !info.IsDir()
}

func (s *Scanner) readCaskReceipt(path string) installReceipt {
	data, ok := s.readOptional(path)
	if !ok {
		return installReceipt{}
	}
	var receipt installReceipt
	if err := json.Unmarshal(data, &receipt); err != nil {
		if s.Diag != nil {
			s.Diag("warn", path, "skipping receipt fields: "+err.Error())
		}
		receipt = installReceipt{}
	}
	return receipt
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
	data, err := s.readBounded(path)
	if err != nil {
		return nil, false
	}
	return data, true
}
