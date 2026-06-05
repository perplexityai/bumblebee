// Package skills scans agent-skill lock files written by the
// skills.sh / vercel-labs/skills CLI.
//
// Two basenames are dispatched:
//
//   - .skill-lock.json: the global lock file at $XDG_STATE_HOME/skills/
//     or ~/.agents/.skill-lock.json
//   - skills-lock.json: project-local lock file at a repo root
//
// Both share the same envelope:
//
//	{
//	  "version": <int>,
//	  "skills": {
//	    "<local-name>": {
//	      "source":     "<owner/repo or path>",
//	      "sourceType": "github" | "mintlify" | "huggingface" | "local",
//	      "ref":        "<branch|tag|sha>",   // v3, optional
//	      "skillPath":  "<subdir>",           // v3, optional
//	      ...
//	    }, ...
//	  }
//	}
//
// One record is emitted per skill entry. PackageName is the upstream
// source slug (e.g. "vercel-labs/agent-skills"); the local alias is
// preserved in ServerName so a renamed install can still be attributed
// back to the slot in the lock file. The ref (when present) is carried
// in RequestedSpec alongside the sourceType — Version stays empty
// because refs may be branches, tags, or commit SHAs and the slim v0.1
// schema does not distinguish them. For sourceType="local", the path
// is intentionally not retained: only the local alias is recorded so
// the lock file's reference to an on-disk path cannot leak through.
//
// Unknown top-level fields and unknown schema versions are tolerated;
// the parser keys off the "skills" map and is lenient about everything
// else so a v4 schema bump does not break inventory.
package skills

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

const Ecosystem = model.EcosystemAgentSkill

type Scanner struct {
	MaxFileSize int64
	Emit        func(model.Record)
	Diag        func(level, path, msg string)
}

// IsKnownLockFile reports whether base names a recognized skills.sh lock
// file. The walker uses this to dispatch.
func IsKnownLockFile(base string) bool {
	switch base {
	case ".skill-lock.json", "skills-lock.json":
		return true
	}
	return false
}

type skillEntry struct {
	Source     string `json:"source"`
	SourceType string `json:"sourceType"`
	Ref        string `json:"ref,omitempty"`
	SkillPath  string `json:"skillPath,omitempty"`
}

type lockFile struct {
	Skills map[string]skillEntry `json:"skills"`
}

func (s *Scanner) ScanLockFile(path string, base model.Record) error {
	data, err := s.readBounded(path)
	if err != nil {
		return err
	}

	var lf lockFile
	if err := json.Unmarshal(data, &lf); err != nil {
		if s.Diag != nil {
			s.Diag("warn", path, "parse skill lock: "+err.Error())
		}
		return nil
	}
	if len(lf.Skills) == 0 {
		if s.Diag != nil {
			s.Diag("info", path, "no skills parsed")
		}
		return nil
	}

	ids := make([]string, 0, len(lf.Skills))
	for k := range lf.Skills {
		ids = append(ids, k)
	}
	sort.Strings(ids)
	for _, id := range ids {
		e := lf.Skills[id]
		r := base
		r.Ecosystem = Ecosystem
		r.PackageManager = "skills.sh"
		r.SourceType = "skill-lock"
		r.SourceFile = path
		r.ProjectPath = filepath.Dir(path)
		r.RootKind = model.RootKindAgentSkill
		r.ServerName = id
		r.Confidence = "low"

		// Local skills carry an on-disk path in `source`. We deliberately
		// do not record that path: only the local alias is preserved, so
		// the operator's filesystem layout cannot leak through inventory.
		if e.SourceType == "local" || e.Source == "" {
			r.PackageName = id
			r.NormalizedName = strings.ToLower(id)
			if e.SourceType != "" {
				r.RequestedSpec = e.SourceType + ":"
			}
			s.Emit(r)
			continue
		}

		r.PackageName = e.Source
		r.NormalizedName = strings.ToLower(e.Source)
		r.RequestedSpec = buildSpec(e.SourceType, e.Source, e.Ref, e.SkillPath)
		s.Emit(r)
	}
	return nil
}

// buildSpec composes a compact install-channel descriptor for the
// RequestedSpec field. Format: "<sourceType>:<source>[@<ref>][/<skillPath>]".
// A missing sourceType is omitted (so the spec starts at source); a
// missing ref / skillPath simply trims the corresponding segment.
func buildSpec(sourceType, source, ref, skillPath string) string {
	var sb strings.Builder
	if sourceType != "" {
		sb.WriteString(sourceType)
		sb.WriteString(":")
	}
	sb.WriteString(source)
	if ref != "" {
		sb.WriteString("@")
		sb.WriteString(ref)
	}
	if skillPath != "" {
		sb.WriteString("/")
		sb.WriteString(skillPath)
	}
	return sb.String()
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
