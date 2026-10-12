// Package roots provides profile-aware scan root resolution.
//
// Each profile selects a different population of roots:
//
//   - baseline  — bounded known package/tool roots only. Global/user
//     package-manager install locations, Homebrew lib prefixes, language
//     toolchains, editor-extension trees, MCP config directories.
//   - project   — configured developer/project roots. ~/code, ~/src,
//     ~/Developer, ~/Projects, ~/workspace, plus any explicit roots.
//   - deep      — incident-response exposure scan. Requires explicit roots.
package roots

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/perplexityai/bumblebee/internal/model"
	"github.com/perplexityai/bumblebee/internal/scanner"
)

// Opts groups the scoping inputs to Resolve.
type Opts struct {
	// AllUsers, when true on macOS, expands the baseline/project profile
	// defaults across every real user home under /Users instead of only
	// the current process owner's home. System/Homebrew roots are still
	// included exactly once.
	AllUsers bool

	// UsersDirOverride replaces /Users for testing or non-standard layouts.
	UsersDirOverride string
}

// Resolve picks the scan roots for the given profile. When the caller
// supplied explicit root entries, those are honored; otherwise the profile's
// curated defaults are returned.
func Resolve(profile string, explicit []string, opts Opts) (roots []scanner.Root, notes []string, err error) {
	switch profile {
	case model.ProfileBaseline, model.ProfileProject, model.ProfileDeep:
	case "":
		return nil, nil, fmt.Errorf("profile is required (one of: baseline, project, deep)")
	default:
		return nil, nil, fmt.Errorf("unknown profile %q (want: baseline, project, deep)", profile)
	}

	if opts.AllUsers && profile == model.ProfileDeep {
		return nil, nil, fmt.Errorf(
			"--all-users is not valid with --profile deep.\n" +
				"deep is the incident-response profile and intentionally requires explicit root paths.\n" +
				"To fan out a deep sweep across users, pass --root /Users/<name> per user.")
	}

	if len(explicit) > 0 {
		if opts.AllUsers {
			return nil, nil, fmt.Errorf(
				"--all-users cannot be combined with explicit root entries.\n" +
					"--all-users expands the profile's curated defaults across every user home.\n" +
					"Either drop --all-users and enumerate roots manually, or drop roots and let --all-users expand the defaults.")
		}
		roots = make([]scanner.Root, 0, len(explicit))
		for _, p := range explicit {
			kind := ClassifyRoot(p, profile)
			if IsBroadHomeRoot(p) && profile != model.ProfileDeep {
				return nil, nil, fmt.Errorf(
					"profile=%s refuses broad home/filesystem root %q.\n"+
						"baseline and project profiles are source/root-allowlist inventories — they do not walk bare home directories.\n"+
						"For an incident-response exposure scan that does walk home roots, re-run with --profile deep.",
					profile, p)
			}
			roots = append(roots, scanner.Root{Path: p, Kind: kind})
		}
		return roots, notes, nil
	}

	switch profile {
	case model.ProfileBaseline:
		roots, notes = BaselineDefaultRoots(opts)
	case model.ProfileProject:
		roots, notes = ProjectDefaultRoots(opts)
	case model.ProfileDeep:
		return nil, nil, fmt.Errorf(
			"profile=deep requires at least one explicit root.\n" +
				"deep is the incident-response profile and is intentionally not auto-configured.\n" +
				"Pass the home root(s) you want to scan, e.g. --root \"$HOME\" or --root /Users/<name>.")
	}

	if len(roots) == 0 {
		return nil, nil, fmt.Errorf(
			"profile=%s found no default roots on this host. Pass roots explicitly.", profile)
	}
	return roots, notes, nil
}

// ClassifyRoot infers a RootKind for an operator-supplied root path.
func ClassifyRoot(path, profile string) string {
	p := filepath.ToSlash(filepath.Clean(path))
	switch {
	case strings.HasSuffix(p, "/extensions") && containsAny(p, ".vscode", ".cursor", ".windsurf", ".vscodium"):
		return model.RootKindEditorExtension
	case (strings.HasSuffix(p, "/Extensions") || strings.HasSuffix(p, "/extensions")) &&
		containsAny(p, "Chrome", "Chromium", "Firefox", "BraveSoftware", "Microsoft Edge", "Vivaldi", "Arc", "Comet", "LibreWolf", "Waterfox", ".mozilla"):
		return model.RootKindBrowserExtension
	case strings.HasSuffix(p, "/Profiles") && containsAny(p, "Firefox", "LibreWolf", "Waterfox"):
		return model.RootKindBrowserExtension
	case strings.Contains(p, "Library/Application Support/Claude") ||
		strings.HasSuffix(p, "/.cursor") ||
		strings.HasSuffix(p, "/.codeium/windsurf") ||
		strings.HasSuffix(p, "/.claude") ||
		strings.HasSuffix(p, "/.codex") ||
		strings.HasSuffix(p, "/.gemini") ||
		strings.HasSuffix(p, "/.config/Claude") ||
		strings.HasSuffix(p, "/.config/Claude Code") ||
		strings.HasSuffix(p, "/.continue"):
		return model.RootKindMCPConfig
	case strings.HasSuffix(p, "/.agents") || strings.HasSuffix(p, "/.local/state/skills"):
		return model.RootKindAgentSkill
	case p == "/opt/homebrew/lib" ||
		p == "/usr/local/lib" ||
		strings.HasSuffix(p, "/Cellar") ||
		strings.HasSuffix(p, "/Caskroom") ||
		strings.HasSuffix(p, "/Library/Python"):
		return model.RootKindHomebrew
	case IsBroadHomeRoot(path):
		return model.RootKindDeepHome
	}
	if profile == model.ProfileBaseline {
		return model.RootKindUserPackage
	}
	if profile == model.ProfileProject {
		return model.RootKindProject
	}
	return model.RootKindUnknown
}

// IsBroadHomeRoot reports whether path resolves to a bare user home or
// filesystem root.
func IsBroadHomeRoot(path string) bool {
	if path == "" {
		return false
	}
	abs, err := filepath.Abs(path)
	if err != nil {
		abs = path
	}
	abs = filepath.Clean(abs)
	if abs == "/" {
		return true
	}
	if home, err := os.UserHomeDir(); err == nil && home != "" {
		if abs == filepath.Clean(home) {
			return true
		}
	}
	switch abs {
	case "/Users", "/home", "/root":
		return true
	}
	if dir, _ := filepath.Split(abs); dir == "/Users/" || dir == "/home/" {
		return true
	}
	return false
}

// BaselineDefaultRoots returns the curated set of global/user package-manager
// install roots, language toolchains, editor-extension trees, MCP config
// locations, and Homebrew lib prefixes.
func BaselineDefaultRoots(opts Opts) ([]scanner.Root, []string) {
	var candidates []scanner.Root
	var notes []string

	for _, home := range HomesForExpansion(opts) {
		candidates = append(candidates, BaselineHomeCandidates(home)...)
	}
	candidates = append(candidates, SystemRoots()...)

	present, filterNotes := FilterExistingRoots(candidates)
	notes = append(notes, filterNotes...)
	if opts.AllUsers && runtime.GOOS == "darwin" {
		homes := AllUsersHomes(opts.UsersDirOverride)
		notes = append(notes, fmt.Sprintf("--all-users expansion: %d home(s) under %s", len(homes), usersDirEffective(opts.UsersDirOverride)))
	} else if opts.AllUsers {
		notes = append(notes, fmt.Sprintf("--all-users expansion: not supported on %s; using current user's default roots", runtime.GOOS))
	}
	return present, notes
}

// ProjectDefaultRoots returns the curated set of developer/project trees.
func ProjectDefaultRoots(opts Opts) ([]scanner.Root, []string) {
	var candidates []scanner.Root
	for _, home := range HomesForExpansion(opts) {
		candidates = append(candidates, ProjectHomeCandidates(home)...)
	}
	present, notes := FilterExistingRoots(candidates)
	if opts.AllUsers && runtime.GOOS == "darwin" {
		homes := AllUsersHomes(opts.UsersDirOverride)
		notes = append(notes, fmt.Sprintf("--all-users expansion: %d home(s) under %s", len(homes), usersDirEffective(opts.UsersDirOverride)))
	} else if opts.AllUsers {
		notes = append(notes, fmt.Sprintf("--all-users expansion: not supported on %s; using current user's default roots", runtime.GOOS))
	}
	return present, notes
}

// HomesForExpansion returns the list of home directories to expand.
func HomesForExpansion(opts Opts) []string {
	if opts.AllUsers && runtime.GOOS == "darwin" {
		homes := AllUsersHomes(opts.UsersDirOverride)
		if len(homes) > 0 {
			return homes
		}
	}
	if home, _ := os.UserHomeDir(); home != "" {
		return []string{home}
	}
	return nil
}

// AllUsersHomes enumerates real per-user home directories under the given
// /Users-style parent. usersDir == "" defaults to /Users.
func AllUsersHomes(usersDir string) []string {
	if usersDir == "" {
		usersDir = "/Users"
	}
	entries, err := os.ReadDir(usersDir)
	if err != nil {
		return nil
	}
	var homes []string
	for _, e := range entries {
		name := e.Name()
		if !IsLikelyUserHomeName(name) {
			continue
		}
		full := filepath.Join(usersDir, name)
		info, err := os.Stat(full)
		if err != nil || !info.IsDir() {
			continue
		}
		homes = append(homes, full)
	}
	return homes
}

// IsLikelyUserHomeName returns true for a basename that looks like a real
// user home under /Users.
func IsLikelyUserHomeName(name string) bool {
	if name == "" || name == "." || name == ".." {
		return false
	}
	if strings.HasPrefix(name, ".") {
		return false
	}
	switch strings.ToLower(name) {
	case "shared", "guest", "root", "deleted users":
		return false
	}
	return true
}

// BaselineHomeCandidates returns the per-home set of curated baseline root
// candidates for one home directory.
func BaselineHomeCandidates(home string) []scanner.Root {
	if home == "" {
		return nil
	}
	var out []scanner.Root
	add := func(p, kind string) { out = append(out, scanner.Root{Path: p, Kind: kind}) }

	add(filepath.Join(home, "go"), model.RootKindUserPackage)
	add(filepath.Join(home, ".cargo"), model.RootKindUserPackage)
	add(filepath.Join(home, ".rbenv"), model.RootKindUserPackage)
	add(filepath.Join(home, ".rvm"), model.RootKindUserPackage)
	add(filepath.Join(home, ".pyenv", "versions"), model.RootKindUserPackage)
	add(filepath.Join(home, ".asdf", "installs"), model.RootKindUserPackage)
	add(filepath.Join(home, ".nvm", "versions"), model.RootKindUserPackage)
	for _, p := range globExistingDirs(filepath.Join(home, ".local", "lib", "python*")) {
		add(p, model.RootKindUserPackage)
	}
	add(filepath.Join(home, ".local", "share", "pipx", "venvs"), model.RootKindUserPackage)

	for _, seg := range []string{
		".vscode/extensions",
		".vscode-insiders/extensions",
		".vscode-server/extensions",
		".cursor/extensions",
		".cursor-server/extensions",
		".windsurf/extensions",
		".windsurf-server/extensions",
		".vscodium/extensions",
	} {
		add(filepath.Join(home, filepath.FromSlash(seg)), model.RootKindEditorExtension)
	}

	add(filepath.Join(home, ".cursor"), model.RootKindMCPConfig)
	add(filepath.Join(home, ".codeium", "windsurf"), model.RootKindMCPConfig)
	add(filepath.Join(home, ".claude"), model.RootKindMCPConfig)
	add(filepath.Join(home, ".claude.json"), model.RootKindMCPConfig)
	add(filepath.Join(home, ".codex"), model.RootKindMCPConfig)
	add(filepath.Join(home, ".gemini"), model.RootKindMCPConfig)
	switch runtime.GOOS {
	case "darwin":
		add(filepath.Join(home, "Library", "Application Support", "Claude"), model.RootKindMCPConfig)
	case "linux":
		add(filepath.Join(home, ".config", "Claude"), model.RootKindMCPConfig)
		add(filepath.Join(home, ".config", "Claude Code"), model.RootKindMCPConfig)
		add(filepath.Join(home, ".continue"), model.RootKindMCPConfig)
	}

	add(filepath.Join(home, ".agents"), model.RootKindAgentSkill)
	if xdg := os.Getenv("XDG_STATE_HOME"); xdg != "" {
		add(filepath.Join(xdg, "skills"), model.RootKindAgentSkill)
	}

	for _, r := range BrowserExtensionCandidateRoots(home) {
		add(r, model.RootKindBrowserExtension)
	}
	return out
}

// ProjectHomeCandidates returns the per-home set of curated project root
// candidates for one home directory.
func ProjectHomeCandidates(home string) []scanner.Root {
	if home == "" {
		return nil
	}
	var out []scanner.Root
	for _, sub := range []string{"code", "src", "Developer", "Projects", "workspace"} {
		out = append(out, scanner.Root{
			Path: filepath.Join(home, sub),
			Kind: model.RootKindProject,
		})
	}
	return out
}

// SystemRoots returns the OS-specific system/Homebrew install prefixes.
func SystemRoots() []scanner.Root {
	switch runtime.GOOS {
	case "darwin":
		return []scanner.Root{
			{Path: "/opt/homebrew/Cellar", Kind: model.RootKindHomebrew},
			{Path: "/opt/homebrew/Caskroom", Kind: model.RootKindHomebrew},
			{Path: "/opt/homebrew/lib", Kind: model.RootKindHomebrew},
			{Path: "/usr/local/Cellar", Kind: model.RootKindHomebrew},
			{Path: "/usr/local/Caskroom", Kind: model.RootKindHomebrew},
			{Path: "/usr/local/lib", Kind: model.RootKindHomebrew},
			{Path: "/Library/Python", Kind: model.RootKindHomebrew},
		}
	case "linux":
		roots := []scanner.Root{
			{Path: "/usr/local/lib", Kind: model.RootKindGlobalPackage},
			{Path: "/home/linuxbrew/.linuxbrew/Cellar", Kind: model.RootKindHomebrew},
			{Path: "/home/linuxbrew/.linuxbrew/Caskroom", Kind: model.RootKindHomebrew},
		}
		for _, p := range globExistingDirs("/usr/lib/python*") {
			roots = append(roots, scanner.Root{Path: p, Kind: model.RootKindGlobalPackage})
		}
		return roots
	}
	return nil
}

// BrowserExtensionCandidateRoots returns per-profile extension directories.
func BrowserExtensionCandidateRoots(home string) []string {
	var roots []string
	chromiumProfiles := []string{"Default", "Profile 1", "Profile 2", "Profile 3", "Profile 4", "Profile 5", "Profile 6", "Profile 7", "Profile 8", "Profile 9"}

	chromiumBases := map[string][]string{}
	switch runtime.GOOS {
	case "darwin":
		appSupport := filepath.Join(home, "Library", "Application Support")
		chromiumBases["chrome"] = []string{filepath.Join(appSupport, "Google", "Chrome")}
		chromiumBases["chromium"] = []string{filepath.Join(appSupport, "Chromium")}
		chromiumBases["brave"] = []string{filepath.Join(appSupport, "BraveSoftware", "Brave-Browser")}
		chromiumBases["edge"] = []string{filepath.Join(appSupport, "Microsoft Edge")}
		chromiumBases["vivaldi"] = []string{filepath.Join(appSupport, "Vivaldi")}
		chromiumBases["arc"] = []string{filepath.Join(appSupport, "Arc", "User Data")}
		chromiumBases["comet"] = []string{filepath.Join(appSupport, "Comet")}
	case "linux":
		cfg := filepath.Join(home, ".config")
		chromiumBases["chrome"] = []string{filepath.Join(cfg, "google-chrome")}
		chromiumBases["chromium"] = []string{
			filepath.Join(cfg, "chromium"),
			filepath.Join(home, "snap", "chromium", "common", "chromium"),
			filepath.Join(home, ".var", "app", "org.chromium.Chromium", "config", "chromium"),
		}
		chromiumBases["brave"] = []string{
			filepath.Join(cfg, "BraveSoftware", "Brave-Browser"),
			filepath.Join(home, ".var", "app", "com.brave.Browser", "config", "BraveSoftware", "Brave-Browser"),
		}
		chromiumBases["edge"] = []string{
			filepath.Join(cfg, "microsoft-edge"),
			filepath.Join(home, ".var", "app", "com.microsoft.Edge", "config", "microsoft-edge"),
		}
		chromiumBases["vivaldi"] = []string{filepath.Join(cfg, "vivaldi")}
	}
	for _, bases := range chromiumBases {
		for _, b := range bases {
			for _, prof := range chromiumProfiles {
				roots = append(roots, filepath.Join(b, prof, "Extensions"))
			}
		}
	}

	switch runtime.GOOS {
	case "darwin":
		appSupport := filepath.Join(home, "Library", "Application Support")
		roots = append(roots,
			filepath.Join(appSupport, "Firefox", "Profiles"),
			filepath.Join(appSupport, "LibreWolf", "Profiles"),
			filepath.Join(appSupport, "Waterfox", "Profiles"),
		)
	case "linux":
		roots = append(roots,
			filepath.Join(home, ".mozilla", "firefox"),
			filepath.Join(home, "snap", "firefox", "common", ".mozilla", "firefox"),
			filepath.Join(home, ".var", "app", "org.mozilla.firefox", ".mozilla", "firefox"),
			filepath.Join(home, ".librewolf"),
			filepath.Join(home, ".var", "app", "io.gitlab.librewolf-community", ".librewolf"),
			filepath.Join(home, ".waterfox"),
		)
	}
	return roots
}

// FilterExistingRoots returns the subset of candidate roots that exist.
func FilterExistingRoots(candidates []scanner.Root) ([]scanner.Root, []string) {
	var present []scanner.Root
	skipped := 0
	for _, c := range candidates {
		info, err := os.Stat(c.Path)
		if err != nil || (!info.IsDir() && !info.Mode().IsRegular()) {
			skipped++
			continue
		}
		present = append(present, c)
	}
	if len(present) == 0 {
		return nil, nil
	}
	if skipped == 0 {
		return present, nil
	}
	return present, []string{
		fmt.Sprintf("default roots: %d present, %d candidate paths absent (use --root to override)",
			len(present), skipped),
	}
}

func usersDirEffective(override string) string {
	if override != "" {
		return override
	}
	return "/Users"
}

func containsAny(s string, subs ...string) bool {
	for _, sub := range subs {
		if strings.Contains(s, sub) {
			return true
		}
	}
	return false
}

func globExistingDirs(pattern string) []string {
	matches, err := filepath.Glob(pattern)
	if err != nil {
		return nil
	}
	var out []string
	for _, p := range matches {
		if info, err := os.Stat(p); err == nil && info.IsDir() {
			out = append(out, p)
		}
	}
	return out
}
