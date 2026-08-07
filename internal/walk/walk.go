// Package walk implements a bounded, safety-aware filesystem walker.
//
// The walker visits directories under configured roots, applying:
//   - exclude-directory matching by name
//   - symlink-loop protection via visited-inode tracking
//   - bounded recursion: it does not descend into node_modules subtrees
//     beyond what targeted scanners need (those scanners walk their own
//     bounded depth)
//
// File-size limits and per-file safety live in the scanners themselves.
package walk

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
)

// Default excludes target sensitive/credential dirs and high-cost caches that
// developer machines accumulate. The list is intentionally conservative.
//
// macOS-specific entries cover TCC-protected user trees that produce
// "operation not permitted" noise without yielding inventory, large media
// libraries that the OS itself walks lazily, and Apple intelligence /
// suggestion caches that frequently appear in permission-error reports.
// These apply even when an operator explicitly passes --root "$HOME";
// the excludes only narrow what is walked under each root.
var DefaultExcludes = []string{
	".git",
	".hg",
	".svn",
	".ssh",
	".gnupg",
	".aws",
	".azure",
	".config/gcloud",
	".kube",
	".docker",

	// macOS Library — caches, mail/messages, browser profiles, system
	// intelligence/suggestions, trial data, and weather caches. The
	// scanner does not need to read any of these and they routinely
	// produce TCC denials when scanned under a LaunchAgent.
	//
	// The curated default roots in cmd/bumblebee only include the
	// handful of Library subpaths the scanner actually wants (e.g.
	// Library/Python/<v>/site-packages via the Homebrew path, or
	// Library/Application Support/Claude for MCP configs). When an
	// operator explicitly passes --root "$HOME", these suffix-component
	// matches keep the walker out of every other Library subtree that
	// is either TCC-protected, OS-managed, or just irrelevant.
	"Library/Caches",
	"Library/Application Support/Google/Chrome",
	"Library/Application Support/Chromium",
	"Library/Application Support/Firefox",
	"Library/Application Support/BraveSoftware",
	"Library/Application Support/Microsoft Edge",
	"Library/Application Support/Vivaldi",
	"Library/Application Support/Arc",
	"Library/Safari",
	"Library/Containers",
	"Library/ContainerManager",
	"Library/Daemon Containers",
	"Library/Group Containers",
	"Library/Mail",
	"Library/Messages",
	"Library/Suggestions",
	"Library/Trial",
	"Library/Weather",
	"Library/Metadata",
	"Library/Biome",
	"Library/PersonalizationPortrait",
	"Library/CoreFollowUp",
	"Library/HomeKit",
	"Library/Mobile Documents",
	"Library/CloudStorage",
	"Library/com.apple.aiml.instrumentation",
	"Library/IdentityServices",
	"Library/Keychains",
	"Library/Cookies",
	"Library/HTTPStorages",
	"Library/WebKit",
	"Library/Autosave Information",
	"Library/Saved Application State",
	"Library/DoNotDisturb",
	"Library/DuetExpertCenter",
	"Library/IntelligencePlatform",
	"Library/Photos",
	"Library/Sharing",
	"Library/Shortcuts",
	"Library/StatusKit",
	"Library/Accounts",
	"Library/Assistant",
	"Library/CallServices",
	"Library/com.apple.icloud.searchpartyd",
	"Library/FaceTime",
	"Library/Family",
	"Library/FrontBoard",
	"Library/Reminders",
	"Library/Springboard",
	"Library/Sync Services",
	"Library/Voice Trigger",

	// macOS media libraries. These are large, OS-managed, and contain
	// nothing the package scanner can use.
	"Movies/TV",
	"Music/Music",
	"Pictures/Photos Library.photoslibrary",
	"Pictures/Photo Booth Library",

	// Generic caches and high-cost build/dependency cache trees.
	".cache",
	".npm/_cacache",
	".pnpm-store",
	".yarn/cache",
	".gradle",
	".m2",
	".ivy2",
	".sbt",
	"__pycache__",
	".pytest_cache",
	".mypy_cache",
	".ruff_cache",
	".tox",
	".venv-cache",
	".nox",
	".terraform",
	"node_modules/.cache",

	// Bazel: project-local and well-known user caches. The output_base
	// and disk_cache layouts hold many partial / synthesized fixture
	// METADATA files that look like Python dist-info but are not
	// installed packages.
	"bazel-cache",
	"bazel-out",
	"bazel-bin",
	"bazel-testlogs",
	".bazel-cache",
	".cache/bazel",

	// Editor remote-server runtime/state/log subtrees are excluded so the
	// per-user `extensions/` root remains scannable while server runtime
	// binaries, globalStorage tokens/blobs, logs, and caches are not walked.
	".vscode-server/data",
	".vscode-server/bin",
	".vscode-server/cli",
	".vscode-server/logs",
	".vscode-server-insiders/data",
	".vscode-server-insiders/bin",
	".vscode-server-insiders/cli",
	".vscode-server-insiders/logs",
	".cursor-server/data",
	".cursor-server/bin",
	".cursor-server/cli",
	".cursor-server/logs",
	".windsurf-server/data",
	".windsurf-server/bin",
	".windsurf-server/cli",
	".windsurf-server/logs",
}

// Visitor is called for every directory entry the walker decides to surface.
// The walker itself does not open files; scanners decide what to read.
type Visitor func(path string, d fs.DirEntry) error

type Options struct {
	Roots    []string
	Excludes []string

	// OnError receives non-fatal errors; the walker continues afterward.
	OnError func(path string, err error)
}

// ErrSkip can be returned by a Visitor to skip a directory subtree.
var ErrSkip = filepath.SkipDir

// Walk traverses Roots, invoking visit on every entry. Excluded directories
// (matched by basename or by suffix path component) are skipped entirely.
func Walk(opts Options, visit Visitor) error {
	excludes := normalizeExcludes(opts.Excludes)
	seen := make(map[dirIdent]struct{})

	for _, root := range opts.Roots {
		root = filepath.Clean(root)
		if err := walkOne(root, excludes, seen, opts.OnError, visit); err != nil {
			if opts.OnError != nil {
				opts.OnError(root, err)
			}
		}
	}
	return nil
}

func walkOne(root string, excludes excludeSet, seen map[dirIdent]struct{}, onErr func(string, error), visit Visitor) error {
	return filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			if onErr != nil {
				onErr(path, err)
			}
			// Skip unreadable directories outright, but continue elsewhere.
			if d != nil && d.IsDir() {
				return filepath.SkipDir
			}
			return nil
		}
		if d.IsDir() {
			if isExcluded(path, d.Name(), excludes) {
				return filepath.SkipDir
			}
			// Directory symlinks are never descended into. filepath.WalkDir
			// does not follow them on its own, and we explicitly skip any
			// directory-shaped symlink we encounter so the walker never
			// crosses into an unrelated subtree by indirection. Reuse this
			// Lstat result for the loop-guard key; do not stat again.
			info, lerr := os.Lstat(path)
			if lerr == nil && info.Mode()&os.ModeSymlink != 0 {
				return filepath.SkipDir
			}
			var key dirIdent
			var ok bool
			if lerr == nil {
				key, ok = dirKeyFromInfo(path, info)
			} else {
				key, ok = dirKey(path)
			}
			if ok {
				if _, dup := seen[key]; dup {
					return filepath.SkipDir
				}
				seen[key] = struct{}{}
			}
		}
		if verr := visit(path, d); verr != nil {
			if errors.Is(verr, filepath.SkipDir) {
				return filepath.SkipDir
			}
			if onErr != nil {
				onErr(path, verr)
			}
		}
		return nil
	})
}

// excludeSet holds normalized excludes indexed for O(1) directory checks:
// single-component entries match by basename; multi-component entries are
// indexed by their last component so only candidates whose tail already
// matches the directory name pay a suffix comparison.
type excludeSet struct {
	names    map[string]struct{}
	suffixes map[string][]string
}

func normalizeExcludes(in []string) excludeSet {
	out := excludeSet{
		names:    make(map[string]struct{}, len(in)),
		suffixes: make(map[string][]string),
	}
	for _, x := range in {
		x = strings.TrimSpace(x)
		if x == "" {
			continue
		}
		x = filepath.Clean(x)
		// A separator-only exclude has no usable suffix form; keep it
		// name-matched so it still matches a root whose base name is
		// the separator itself.
		if !strings.ContainsRune(x, filepath.Separator) || x == string(filepath.Separator) {
			out.names[x] = struct{}{}
			continue
		}
		last := filepath.Base(x)
		out.suffixes[last] = append(out.suffixes[last], string(filepath.Separator)+x)
	}
	return out
}

// isExcluded expects fullPath to be clean, which holds for every path
// filepath.WalkDir produces from the cleaned roots in Walk.
func isExcluded(fullPath, base string, excludes excludeSet) bool {
	if _, ok := excludes.names[base]; ok {
		return true
	}
	// Suffix-component match: an exclude like "Library/Caches" or
	// ".config/gcloud" matches any path ending in that sequence.
	for _, suf := range excludes.suffixes[base] {
		if strings.HasSuffix(fullPath, suf) {
			return true
		}
	}
	return false
}
