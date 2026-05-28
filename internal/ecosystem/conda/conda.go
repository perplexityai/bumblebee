// Package conda scans conda-format install metadata: the per-package
// JSON records that conda, mamba, micromamba, and pixi all write under
// `<env>/conda-meta/<name>-<version>-<build>.json` when a package is
// linked into an environment.
//
// These records carry exact name, version, and build-string fields
// emitted by the package builder, so a parsed record is high-confidence
// proof that the named package version is currently linked into the
// surrounding environment prefix.
//
// Read-only: no conda/mamba/pixi invocation. Per-file size capped by
// MaxFileSize. The pixi.lock and pixi.toml manifests are NOT parsed in
// this scanner; conda-meta is the authoritative installed-state source
// and is shared by every conda-compatible package manager.
package conda

import (
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

const Ecosystem = model.EcosystemConda

type Scanner struct {
	MaxFileSize int64
	Emit        func(model.Record)
	Diag        func(level, path, msg string)
}

// IsCondaMetaRecord returns (true, envRoot) when path is a per-package
// JSON record inside a `conda-meta/` directory. envRoot is the
// environment prefix that owns the record (the parent of the
// `conda-meta/` directory).
//
// The `history` file that conda also writes into `conda-meta/` is not
// JSON and is intentionally not matched here; the basename check filters
// it out alongside any other non-JSON sibling.
func IsCondaMetaRecord(path string) (bool, string) {
	base := filepath.Base(path)
	if !strings.HasSuffix(base, ".json") {
		return false, ""
	}
	dir := filepath.Dir(path)
	if filepath.Base(dir) != "conda-meta" {
		return false, ""
	}
	return true, filepath.Dir(dir)
}

// metadata is the subset of the conda-meta record schema bumblebee
// needs. The on-disk file has many additional fields (files, paths_data,
// link, depends, constrains, ...) which are deliberately not decoded.
type metadata struct {
	Name    string `json:"name"`
	Version string `json:"version"`
	// Schannel is the short channel name conda records ("conda-forge",
	// "bioconda", "pypi", "<unknown>"). When absent we fall back to the
	// final segment of `channel`, which is a URL like
	// `https://conda.anaconda.org/conda-forge/osx-arm64`.
	Schannel string `json:"schannel"`
	Channel  string `json:"channel"`
}

// ScanCondaMetaRecord parses one conda-meta install record and emits a
// package record. envRoot is the environment prefix (the parent of the
// conda-meta directory) and is stamped as ProjectPath so receivers can
// group records by environment.
func (s *Scanner) ScanCondaMetaRecord(path, envRoot string, base model.Record) error {
	data, err := s.readBounded(path)
	if err != nil {
		return err
	}
	var meta metadata
	if err := json.Unmarshal(data, &meta); err != nil {
		return fmt.Errorf("parse %s: %w", path, err)
	}
	if meta.Name == "" || meta.Version == "" {
		if s.Diag != nil {
			s.Diag("warn", path, "skipping: conda-meta record missing name and/or version")
		}
		return nil
	}

	r := base
	r.Ecosystem = Ecosystem
	r.PackageName = meta.Name
	r.NormalizedName = normalize.Conda(meta.Name)
	r.Version = meta.Version
	r.ProjectPath = envRoot
	r.PackageManager = packageManagerFor(meta)
	r.SourceType = "conda-meta"
	r.SourceFile = path
	r.Confidence = "high"
	s.Emit(r)
	return nil
}

// packageManagerFor maps the channel a conda-meta record was installed
// from to a short package_manager tag. Conda lets pip-installed
// packages live alongside conda-installed packages in the same env;
// when that happens the record's channel is the literal "pypi", so we
// surface it as `pip` to disambiguate the install source from a
// conda-forge / bioconda / arbitrary-channel install.
func packageManagerFor(meta metadata) string {
	ch := meta.Schannel
	if ch == "" {
		ch = channelFromURL(meta.Channel)
	}
	if strings.EqualFold(ch, "pypi") {
		return "pip"
	}
	return "conda"
}

// channelFromURL pulls the channel short name out of a conda channel URL
// like `https://conda.anaconda.org/conda-forge/osx-arm64`. The trailing
// segment is the subdir (linux-64, osx-arm64, noarch, ...); the segment
// before it is the channel.
func channelFromURL(u string) string {
	u = strings.TrimRight(u, "/")
	if u == "" {
		return ""
	}
	parts := strings.Split(u, "/")
	if len(parts) < 2 {
		return ""
	}
	return parts[len(parts)-2]
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
