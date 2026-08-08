package cargo

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
)

const Ecosystem = model.EcosystemCargo

type Scanner struct {
	MaxFileSize int64
	Emit        func(model.Record)
	Diag        func(level, path, msg string)
}

func IsCargoLock(base string) bool { return base == "Cargo.lock" }

func (s *Scanner) ScanCargoLock(path string, base model.Record) error {
	data, err := s.readBounded(path)
	if err != nil {
		return err
	}
	projectPath := filepath.Dir(path)

	sc := bufio.NewScanner(bytes.NewReader(data))
	sc.Buffer(make([]byte, 0, 64*1024), 4*1024*1024)

	var inPackage bool
	var name, version string

	emitCurrent := func() {
		if inPackage && name != "" && version != "" {
			r := base
			r.Ecosystem = Ecosystem
			r.PackageName = name
			r.NormalizedName = strings.ToLower(name)
			r.Version = version
			r.ProjectPath = projectPath
			r.PackageManager = "cargo"
			r.SourceType = "cargo-lock"
			r.SourceFile = path
			r.Confidence = "high"
			s.Emit(r)
		}
		inPackage = false
		name = ""
		version = ""
	}

	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "[[package]]" {
			emitCurrent()
			inPackage = true
			continue
		}
		if !inPackage {
			continue
		}
		if strings.HasPrefix(line, "name =") {
			name = unquote(strings.TrimSpace(strings.TrimPrefix(line, "name =")))
		} else if strings.HasPrefix(line, "version =") {
			version = unquote(strings.TrimSpace(strings.TrimPrefix(line, "version =")))
		}
	}
	emitCurrent()

	return nil
}

func unquote(s string) string {
	if len(s) >= 2 && s[0] == '"' && s[len(s)-1] == '"' {
		return s[1 : len(s)-1]
	}
	if len(s) >= 2 && s[0] == '\'' && s[len(s)-1] == '\'' {
		return s[1 : len(s)-1]
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
