// Package walk implements a bounded, safety-aware filesystem walker.
//
// The walker visits directories under configured roots, applying:
//   - exclude-directory matching by name
//   - symlink-loop protection via visited-inode tracking
//   - symlink entries are never surfaced to the visitor (neither
//     directory-typed nor file-typed) so the walker never crosses into
//     an unrelated subtree by indirection
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
	seen := make(map[string]struct{})

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

func walkOne(root string, excludes map[string]struct{}, seen map[string]struct{}, onErr func(string, error), visit Visitor) error {
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
			// Symlink-loop guard via device+inode.
			if key, ok := dirKey(path); ok {
				if _, dup := seen[key]; dup {
					return filepath.SkipDir
				}
				seen[key] = struct{}{}
			}
		}
		// Symlink entries — directory-typed or file-typed — are never
		// surfaced to the visitor. filepath.WalkDir does not descend
		// into directory symlinks on its own, but it does report
		// file-typed symlinks as regular entries to the callback, and
		// scanners open files through os.Open which follows the link.
		// Without this guard, an attacker who can plant one symlink
		// inside a scan root (e.g. via a malicious package's postinstall
		// hook placing node_modules/<pkg>/package.json -> some other
		// JSON config under the user's home) can have the walker parse
		// that out-of-tree file and emit its fields under an unrelated
		// ecosystem — leaking the target file's contents through the
		// configured records sink. Skip every symlink-typed entry to
		// keep the "walker never crosses by indirection" invariant.
		if d.Type()&os.ModeSymlink != 0 {
			return nil
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

func normalizeExcludes(in []string) map[string]struct{} {
	out := make(map[string]struct{}, len(in))
	for _, x := range in {
		x = strings.TrimSpace(x)
		if x == "" {
			continue
		}
		out[filepath.Clean(x)] = struct{}{}
	}
	return out
}

func isExcluded(fullPath, base string, excludes map[string]struct{}) bool {
	if _, ok := excludes[base]; ok {
		return true
	}
	// Suffix-component match: an exclude like "Library/Caches" or
	// ".config/gcloud" matches any path ending in that sequence.
	for ex := range excludes {
		if !strings.ContainsRune(ex, filepath.Separator) {
			continue
		}
		if strings.HasSuffix(filepath.Clean(fullPath), string(filepath.Separator)+ex) {
			return true
		}
	}
	return false
}
