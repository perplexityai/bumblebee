package main

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/perplexityai/bumblebee/internal/model"
)

func TestResolveDeviceIDUnsetFlag(t *testing.T) {
	id, warn := resolveDeviceID("")
	if id != "" || warn != "" {
		t.Fatalf("want empty/empty, got id=%q warn=%q", id, warn)
	}
}

func TestResolveDeviceIDFromEnv(t *testing.T) {
	t.Setenv("BUMBLEBEE_TEST_DEVICE_ID", "  abc-123  ")
	id, warn := resolveDeviceID("BUMBLEBEE_TEST_DEVICE_ID")
	if id != "abc-123" {
		t.Fatalf("id = %q, want trimmed %q", id, "abc-123")
	}
	if warn != "" {
		t.Fatalf("unexpected warn: %q", warn)
	}
}

func TestResolveDeviceIDMissingEnv(t *testing.T) {
	const name = "BUMBLEBEE_TEST_DEVICE_ID_MISSING"
	id, warn := resolveDeviceID(name)
	if id != "" {
		t.Fatalf("id = %q, want empty", id)
	}
	if !strings.Contains(warn, name) || !strings.Contains(warn, "not set") {
		t.Fatalf("warn = %q, want mention of env name and 'not set'", warn)
	}
}

func TestResolveDeviceIDEmptyEnv(t *testing.T) {
	t.Setenv("BUMBLEBEE_TEST_DEVICE_ID_EMPTY", "   ")
	id, warn := resolveDeviceID("BUMBLEBEE_TEST_DEVICE_ID_EMPTY")
	if id != "" {
		t.Fatalf("id = %q, want empty", id)
	}
	if !strings.Contains(warn, "empty/whitespace") {
		t.Fatalf("warn = %q, want mention of empty/whitespace", warn)
	}
}

func TestIsBroadHomeRoot(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)

	broad := []string{
		home,
		home + "/",
		"/",
		"/Users",
		"/Users/someone",
		"/home",
		"/home/someone",
		"/root",
	}
	for _, p := range broad {
		if !isBroadHomeRoot(p) {
			t.Errorf("isBroadHomeRoot(%q) = false, want true", p)
		}
	}

	narrow := []string{
		filepath.Join(home, "code"),
		filepath.Join(home, "Developer"),
		filepath.Join(home, ".vscode", "extensions"),
		"/usr/local/lib",
		"/opt/homebrew/lib",
		"/Users/someone/code",
		"/home/someone/code",
	}
	for _, p := range narrow {
		if isBroadHomeRoot(p) {
			t.Errorf("isBroadHomeRoot(%q) = true, want false", p)
		}
	}
}

// TestResolveRootsBaselineExcludesProjectTrees verifies the baseline
// profile's curated defaults do not include developer/project trees —
// those belong to the project profile.
func TestResolveRootsBaselineExcludesProjectTrees(t *testing.T) {
	if runtime.GOOS != "darwin" && runtime.GOOS != "linux" {
		t.Skipf("profile defaults are darwin/linux specific")
	}
	home := t.TempDir()
	t.Setenv("HOME", home)
	codeDir := filepath.Join(home, "code")
	if err := os.MkdirAll(codeDir, 0o755); err != nil {
		t.Fatal(err)
	}
	goDir := filepath.Join(home, "go")
	if err := os.MkdirAll(goDir, 0o755); err != nil {
		t.Fatal(err)
	}
	roots, _, err := resolveRoots(model.ProfileBaseline, nil, rootsOpts{})
	if err != nil {
		t.Fatalf("resolveRoots baseline: %v", err)
	}
	for _, r := range roots {
		if r.Path == codeDir {
			t.Errorf("baseline profile must not include project tree %q (that is the project profile)", codeDir)
		}
	}
}

func TestResolveRootsProjectIncludesCodeDir(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	codeDir := filepath.Join(home, "code")
	if err := os.MkdirAll(codeDir, 0o755); err != nil {
		t.Fatal(err)
	}
	roots, _, err := resolveRoots(model.ProfileProject, nil, rootsOpts{})
	if err != nil {
		t.Fatalf("resolveRoots project: %v", err)
	}
	found := false
	for _, r := range roots {
		if r.Path == codeDir && r.Kind == model.RootKindProject {
			found = true
		}
	}
	if !found {
		t.Fatalf("project profile did not include %q, got %v", codeDir, roots)
	}
}

func TestResolveRootsBaselineIncludesUserLocalPython(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	pyRoot := filepath.Join(home, ".local", "lib", "python3.12")
	if err := os.MkdirAll(filepath.Join(pyRoot, "site-packages"), 0o755); err != nil {
		t.Fatal(err)
	}
	roots, _, err := resolveRoots(model.ProfileBaseline, nil, rootsOpts{})
	if err != nil {
		t.Fatalf("resolveRoots baseline: %v", err)
	}
	found := false
	for _, r := range roots {
		if r.Path == pyRoot && r.Kind == model.RootKindUserPackage {
			found = true
		}
	}
	if !found {
		t.Fatalf("baseline profile did not include user-local Python root %q, got %v", pyRoot, roots)
	}
}

// TestResolveRootsBaselineIncludesClaudeAndCodexMCPRoots verifies that the
// cross-platform Claude/Codex/Gemini user-home dotfiles are included in
// baseline MCP roots when present, and dropped when absent.
func TestResolveRootsBaselineIncludesClaudeAndCodexMCPRoots(t *testing.T) {
	if runtime.GOOS != "darwin" && runtime.GOOS != "linux" {
		t.Skipf("profile defaults are darwin/linux specific")
	}
	home := t.TempDir()
	t.Setenv("HOME", home)
	want := []string{
		filepath.Join(home, ".claude"),
		filepath.Join(home, ".codex"),
		filepath.Join(home, ".gemini"),
	}
	for _, p := range want {
		if err := os.MkdirAll(p, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	roots, _, err := resolveRoots(model.ProfileBaseline, nil, rootsOpts{})
	if err != nil {
		t.Fatalf("resolveRoots baseline: %v", err)
	}
	got := map[string]string{}
	for _, r := range roots {
		got[r.Path] = r.Kind
	}
	for _, p := range want {
		kind, ok := got[p]
		if !ok {
			t.Errorf("baseline missing MCP root %q (got %v)", p, roots)
			continue
		}
		if kind != model.RootKindMCPConfig {
			t.Errorf("baseline root %q kind = %q, want %q", p, kind, model.RootKindMCPConfig)
		}
	}
}

// TestResolveRootsBaselineSkipsAbsentClaudeCodexRoots verifies absent
// candidates are dropped by filterExistingRoots rather than emitted.
//
// We create an unrelated default root (`~/go`) so resolveRoots has at
// least one survivor and returns a non-empty root list — the assertion
// we actually want to make is "absent Claude/Codex dirs do NOT appear"
// and short-circuiting on an empty-defaults error would let regressions
// slip through silently.
func TestResolveRootsBaselineSkipsAbsentClaudeCodexRoots(t *testing.T) {
	if runtime.GOOS != "darwin" && runtime.GOOS != "linux" {
		t.Skipf("profile defaults are darwin/linux specific")
	}
	home := t.TempDir()
	t.Setenv("HOME", home)
	// Provide one unrelated default so the baseline run does not fail
	// with "no default roots". `~/go` is not one of the MCP candidates
	// under test, so its presence cannot mask the assertion below.
	if err := os.MkdirAll(filepath.Join(home, "go"), 0o755); err != nil {
		t.Fatal(err)
	}
	roots, _, err := resolveRoots(model.ProfileBaseline, nil, rootsOpts{})
	if err != nil {
		t.Fatalf("resolveRoots baseline: %v", err)
	}
	absent := []string{
		filepath.Join(home, ".claude"),
		filepath.Join(home, ".codex"),
		filepath.Join(home, ".gemini"),
	}
	gotPaths := map[string]bool{}
	for _, r := range roots {
		gotPaths[r.Path] = true
	}
	for _, p := range absent {
		if gotPaths[p] {
			t.Errorf("baseline emitted absent candidate %q (roots=%v)", p, roots)
		}
	}
}

// TestResolveRootsBaselineIncludesAgentSkillRoot verifies that ~/.agents
// (and the XDG override) are picked up by baseline when present.
func TestResolveRootsBaselineIncludesAgentSkillRoot(t *testing.T) {
	if runtime.GOOS != "darwin" && runtime.GOOS != "linux" {
		t.Skipf("profile defaults are darwin/linux specific")
	}
	home := t.TempDir()
	xdg := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("XDG_STATE_HOME", xdg)

	agents := filepath.Join(home, ".agents")
	xdgSkills := filepath.Join(xdg, "skills")
	for _, p := range []string{agents, xdgSkills} {
		if err := os.MkdirAll(p, 0o755); err != nil {
			t.Fatal(err)
		}
	}

	roots, _, err := resolveRoots(model.ProfileBaseline, nil, rootsOpts{})
	if err != nil {
		t.Fatalf("resolveRoots baseline: %v", err)
	}
	got := map[string]string{}
	for _, r := range roots {
		got[r.Path] = r.Kind
	}
	for _, p := range []string{agents, xdgSkills} {
		kind, ok := got[p]
		if !ok {
			t.Errorf("baseline missing agent-skill root %q (got %v)", p, roots)
			continue
		}
		if kind != model.RootKindAgentSkill {
			t.Errorf("baseline root %q kind = %q, want %q", p, kind, model.RootKindAgentSkill)
		}
	}
}

func TestClassifyRootAgentSkill(t *testing.T) {
	cases := []string{
		"/Users/alice/.agents",
		"/home/alice/.agents",
		"/home/alice/.local/state/skills",
	}
	for _, p := range cases {
		if got := classifyRoot(p, model.ProfileBaseline); got != model.RootKindAgentSkill {
			t.Errorf("classifyRoot(%q) = %q, want %q", p, got, model.RootKindAgentSkill)
		}
	}
}

// TestResolveRootsBaselineIncludesClaudeJSONFileRoot verifies that the
// `~/.claude.json` config file is included as a baseline MCP root when
// present. Unlike the other MCP candidates it is a regular file, not a
// directory, so this also exercises filterExistingRoots keeping files.
func TestResolveRootsBaselineIncludesClaudeJSONFileRoot(t *testing.T) {
	if runtime.GOOS != "darwin" && runtime.GOOS != "linux" {
		t.Skipf("profile defaults are darwin/linux specific")
	}
	home := t.TempDir()
	t.Setenv("HOME", home)
	claudeJSON := filepath.Join(home, ".claude.json")
	if err := os.WriteFile(claudeJSON, []byte(`{"mcpServers":{}}`), 0o644); err != nil {
		t.Fatal(err)
	}
	roots, _, err := resolveRoots(model.ProfileBaseline, nil, rootsOpts{})
	if err != nil {
		t.Fatalf("resolveRoots baseline: %v", err)
	}
	for _, r := range roots {
		if r.Path == claudeJSON {
			if r.Kind != model.RootKindMCPConfig {
				t.Errorf("~/.claude.json root kind = %q, want %q", r.Kind, model.RootKindMCPConfig)
			}
			return
		}
	}
	t.Errorf("baseline did not include file root %q (got %v)", claudeJSON, roots)
}

func TestClassifyRootClaudeCodexMCP(t *testing.T) {
	cases := []string{
		"/Users/alice/.claude",
		"/Users/alice/.codex",
		"/Users/alice/.gemini",
		"/home/alice/.claude",
		"/home/alice/.codex",
		"/home/alice/.gemini",
		// Linux MCP dirs added to baselineHomeCandidates must classify
		// the same way when passed as explicit --root entries; otherwise
		// receivers see the same path tagged differently depending on
		// whether the operator typed it or the baseline picked it up.
		"/home/alice/.config/Claude",
		"/home/alice/.config/Claude Code",
		"/home/alice/.continue",
	}
	for _, p := range cases {
		if got := classifyRoot(p, model.ProfileBaseline); got != model.RootKindMCPConfig {
			t.Errorf("classifyRoot(%q) = %q, want %q", p, got, model.RootKindMCPConfig)
		}
	}
}

func TestResolveRootsBaselineRefusesBroadHome(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	_, _, err := resolveRoots(model.ProfileBaseline, []string{home}, rootsOpts{})
	if err == nil {
		t.Fatalf("expected refusal for baseline+%q", home)
	}
	if !strings.Contains(err.Error(), "broad home") {
		t.Errorf("error should mention broad home: %v", err)
	}
}

func TestResolveRootsProjectRefusesBroadHome(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	_, _, err := resolveRoots(model.ProfileProject, []string{home}, rootsOpts{})
	if err == nil {
		t.Fatalf("expected refusal for project+%q", home)
	}
}

func TestResolveRootsDeepAllowsBroadHome(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	roots, _, err := resolveRoots(model.ProfileDeep, []string{home}, rootsOpts{})
	if err != nil {
		t.Fatalf("deep should accept broad home root: %v", err)
	}
	if len(roots) != 1 || roots[0].Path != home {
		t.Fatalf("deep roots = %v", roots)
	}
	if roots[0].Kind != model.RootKindDeepHome {
		t.Errorf("deep home root should be tagged %q, got %q", model.RootKindDeepHome, roots[0].Kind)
	}
}

func TestResolveRootsDeepRequiresExplicitRoot(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	_, _, err := resolveRoots(model.ProfileDeep, nil, rootsOpts{})
	if err == nil {
		t.Fatalf("deep with no roots should error")
	}
	if !strings.Contains(err.Error(), "deep") {
		t.Errorf("error should explain that deep needs an explicit root: %v", err)
	}
}

func TestResolveRootsRejectsUnknownProfile(t *testing.T) {
	_, _, err := resolveRoots("nonsense", nil, rootsOpts{})
	if err == nil {
		t.Fatalf("expected error for unknown profile")
	}
}

func TestClassifyRootEditorExtension(t *testing.T) {
	got := classifyRoot("/Users/alice/.vscode/extensions", model.ProfileBaseline)
	if got != model.RootKindEditorExtension {
		t.Errorf("classifyRoot vscode extensions = %q, want %q", got, model.RootKindEditorExtension)
	}
	got = classifyRoot("/Users/alice/.cursor-server/extensions", model.ProfileBaseline)
	if got != model.RootKindEditorExtension {
		t.Errorf("classifyRoot cursor extensions = %q", got)
	}
}

func TestClassifyRootHomebrewCellarAndCaskroom(t *testing.T) {
	for _, p := range []string{
		"/opt/homebrew/Cellar",
		"/opt/homebrew/Caskroom",
		"/usr/local/Cellar",
		"/usr/local/Caskroom",
		"/home/linuxbrew/.linuxbrew/Cellar",
		"/home/linuxbrew/.linuxbrew/Caskroom",
		"/custom/prefix/Cellar",
		"/custom/prefix/Caskroom",
	} {
		if got := classifyRoot(p, model.ProfileBaseline); got != model.RootKindHomebrew {
			t.Errorf("classifyRoot(%q) = %q, want %q", p, got, model.RootKindHomebrew)
		}
	}
}

func TestIsLikelyUserHomeName(t *testing.T) {
	keep := []string{"alice", "bob", "Alice", "user1", "first.last"}
	drop := []string{"", ".", "..", ".DS_Store", ".localized", "Shared", "shared", "Guest", "guest", "root", "Deleted Users"}
	for _, n := range keep {
		if !isLikelyUserHomeName(n) {
			t.Errorf("isLikelyUserHomeName(%q) = false, want true", n)
		}
	}
	for _, n := range drop {
		if isLikelyUserHomeName(n) {
			t.Errorf("isLikelyUserHomeName(%q) = true, want false", n)
		}
	}
}

// fakeUsersDir builds a /Users-shaped tree under t.TempDir() with the
// given user names and any service entries the caller wants present.
// It returns the absolute parent path (BUMBLEBEE_USERS_DIR value) and
// the list of real user home paths.
func fakeUsersDir(t *testing.T, users []string, services []string) (string, []string) {
	t.Helper()
	root := t.TempDir()
	var realHomes []string
	for _, u := range users {
		p := filepath.Join(root, u)
		if err := os.MkdirAll(p, 0o755); err != nil {
			t.Fatal(err)
		}
		realHomes = append(realHomes, p)
	}
	for _, s := range services {
		p := filepath.Join(root, s)
		if err := os.MkdirAll(p, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	// Add a non-directory entry to ensure it is filtered.
	if err := os.WriteFile(filepath.Join(root, ".DS_Store"), []byte{}, 0o644); err != nil {
		t.Fatal(err)
	}
	return root, realHomes
}

func TestAllUsersHomesFiltersServiceAndHiddenEntries(t *testing.T) {
	usersDir, realHomes := fakeUsersDir(t,
		[]string{"alice", "bob"},
		[]string{"Shared", "Guest", "root", "Deleted Users", ".localized"})
	got := allUsersHomes(usersDir)
	if len(got) != len(realHomes) {
		t.Fatalf("allUsersHomes returned %d entries, want %d (got=%v real=%v)", len(got), len(realHomes), got, realHomes)
	}
	want := map[string]bool{}
	for _, h := range realHomes {
		want[h] = true
	}
	for _, g := range got {
		if !want[g] {
			t.Errorf("unexpected home %q", g)
		}
	}
}

func TestAllUsersHomesEmptyOrMissing(t *testing.T) {
	if got := allUsersHomes(filepath.Join(t.TempDir(), "does-not-exist")); got != nil {
		t.Errorf("missing /Users should yield nil, got %v", got)
	}
	empty := t.TempDir()
	if got := allUsersHomes(empty); got != nil {
		t.Errorf("empty /Users should yield nil, got %v", got)
	}
}

// TestResolveRootsBaselineAllUsersExpansion verifies that --all-users
// expands per-user known subdirectories across /Users/<name>/, includes
// system roots once, and never adds a bare /Users/<name>/ as a root.
func TestResolveRootsBaselineAllUsersExpansion(t *testing.T) {
	if runtime.GOOS != "darwin" {
		t.Skip("--all-users expansion is darwin-only")
	}
	usersDir, realHomes := fakeUsersDir(t,
		[]string{"alice", "bob"},
		[]string{"Shared", "Guest", "root"})
	t.Setenv("BUMBLEBEE_USERS_DIR", usersDir)
	// Make sure UserHomeDir() still resolves to something deterministic.
	t.Setenv("HOME", realHomes[0])

	// Create a small set of known per-user dirs that should be picked up.
	mustMkdir := func(p string) {
		if err := os.MkdirAll(p, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	for _, h := range realHomes {
		mustMkdir(filepath.Join(h, ".nvm", "versions"))
		mustMkdir(filepath.Join(h, ".vscode", "extensions"))
		mustMkdir(filepath.Join(h, "Library", "Application Support", "Claude"))
	}

	roots, _, err := resolveRoots(model.ProfileBaseline, nil, rootsOpts{AllUsers: true})
	if err != nil {
		t.Fatalf("resolveRoots baseline --all-users: %v", err)
	}

	gotPaths := map[string]string{}
	for _, r := range roots {
		gotPaths[r.Path] = r.Kind
	}

	// Each created per-user dir must be present.
	for _, h := range realHomes {
		for _, sub := range []string{
			filepath.Join(h, ".nvm", "versions"),
			filepath.Join(h, ".vscode", "extensions"),
			filepath.Join(h, "Library", "Application Support", "Claude"),
		} {
			if _, ok := gotPaths[sub]; !ok {
				t.Errorf("expected per-user root %q to be expanded, got=%v", sub, gotPaths)
			}
		}
	}

	// Bare /Users/<name>/ must never appear as a root.
	for _, h := range realHomes {
		if _, ok := gotPaths[h]; ok {
			t.Errorf("bare home %q was added as a root; --all-users must only add known subdirectories", h)
		}
	}

	// Service entries must not produce any root under their path.
	for _, name := range []string{"Shared", "Guest", "root"} {
		bad := filepath.Join(usersDir, name)
		for p := range gotPaths {
			if strings.HasPrefix(p, bad+string(filepath.Separator)) {
				t.Errorf("service user %q produced root %q", name, p)
			}
		}
	}
}

// TestResolveRootsBaselineAllUsersIncludesSystemRoots verifies system /
// Homebrew roots are still included under --all-users and only once.
func TestResolveRootsBaselineAllUsersIncludesSystemRoots(t *testing.T) {
	if runtime.GOOS != "darwin" {
		t.Skip("system root layout asserted here is darwin-shaped")
	}
	usersDir, realHomes := fakeUsersDir(t, []string{"alice", "bob"}, nil)
	t.Setenv("BUMBLEBEE_USERS_DIR", usersDir)
	t.Setenv("HOME", realHomes[0])

	roots, _, err := resolveRoots(model.ProfileBaseline, nil, rootsOpts{AllUsers: true})
	if err != nil {
		// If no system roots exist on this host either, the call may
		// error with "no default roots". Create one to ensure at least
		// one survives filterExistingRoots.
		t.Skipf("baseline --all-users yielded no roots on this host: %v", err)
	}

	// Build a count of how often each path appears (must be 1).
	counts := map[string]int{}
	for _, r := range roots {
		counts[r.Path]++
	}
	for p, c := range counts {
		if c > 1 {
			t.Errorf("root %q appeared %d times under --all-users; system roots must be deduplicated", p, c)
		}
	}
}

func TestResolveRootsAllUsersRejectsExplicitRoot(t *testing.T) {
	_, _, err := resolveRoots(model.ProfileBaseline, []string{"/opt/homebrew/lib"}, rootsOpts{AllUsers: true})
	if err == nil {
		t.Fatalf("--all-users combined with explicit --root should error")
	}
	if !strings.Contains(err.Error(), "--all-users") {
		t.Errorf("error should mention --all-users: %v", err)
	}
}

func TestResolveRootsAllUsersRejectsDeepProfile(t *testing.T) {
	_, _, err := resolveRoots(model.ProfileDeep, nil, rootsOpts{AllUsers: true})
	if err == nil {
		t.Fatalf("--all-users with deep profile should error")
	}
	if !strings.Contains(err.Error(), "--all-users") {
		t.Errorf("error should mention --all-users: %v", err)
	}
}

func TestResolveRootsAllUsersUnsupportedPlatformsNote(t *testing.T) {
	if runtime.GOOS == "darwin" {
		t.Skip("--all-users expands on darwin")
	}
	home := t.TempDir()
	t.Setenv("HOME", home)
	pyRoot := filepath.Join(home, ".local", "lib", "python3.12")
	if err := os.MkdirAll(pyRoot, 0o755); err != nil {
		t.Fatal(err)
	}
	_, notes, err := resolveRoots(model.ProfileBaseline, nil, rootsOpts{AllUsers: true})
	if err != nil {
		t.Fatalf("resolveRoots baseline --all-users: %v", err)
	}
	found := false
	for _, n := range notes {
		if strings.Contains(n, "--all-users") && strings.Contains(n, "not supported") {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected unsupported --all-users note on %s, got %v", runtime.GOOS, notes)
	}
}

func TestResolveRootsProjectAllUsersExpansion(t *testing.T) {
	if runtime.GOOS != "darwin" {
		t.Skip("--all-users expansion is darwin-only")
	}
	usersDir, realHomes := fakeUsersDir(t, []string{"alice", "bob"}, nil)
	t.Setenv("BUMBLEBEE_USERS_DIR", usersDir)
	t.Setenv("HOME", realHomes[0])

	for _, h := range realHomes {
		if err := os.MkdirAll(filepath.Join(h, "code"), 0o755); err != nil {
			t.Fatal(err)
		}
	}

	roots, _, err := resolveRoots(model.ProfileProject, nil, rootsOpts{AllUsers: true})
	if err != nil {
		t.Fatalf("resolveRoots project --all-users: %v", err)
	}
	want := map[string]bool{}
	for _, h := range realHomes {
		want[filepath.Join(h, "code")] = true
	}
	for _, r := range roots {
		delete(want, r.Path)
	}
	if len(want) > 0 {
		t.Errorf("project --all-users missed: %v", want)
	}
}

func TestCurrentVersionFallbackIsNonEmpty(t *testing.T) {
	if v := currentVersion(); v == "" {
		t.Fatal("currentVersion returned empty string")
	}
}

func TestVersionStringShape(t *testing.T) {
	s := versionString()
	if !strings.HasPrefix(s, "bumblebee ") {
		t.Errorf("versionString = %q, want 'bumblebee ' prefix", s)
	}
	for _, needle := range []string{"\ncommit:", "\nbuilt: ", "\ngo:    "} {
		if !strings.Contains(s, needle) {
			t.Errorf("versionString missing %q in output:\n%s", needle, s)
		}
	}
	if !strings.Contains(s, runtime.Version()) {
		t.Errorf("versionString should include go runtime version %q, got:\n%s", runtime.Version(), s)
	}
}

func TestNormalizeProfileAccepted(t *testing.T) {
	for _, want := range []string{model.ProfileBaseline, model.ProfileProject, model.ProfileDeep} {
		got, err := normalizeProfile(want)
		if err != nil || got != want {
			t.Fatalf("normalizeProfile(%q) = (%q,%v), want (%q,nil)", want, got, err, want)
		}
	}
	// Empty input defaults to baseline.
	got, err := normalizeProfile("")
	if err != nil || got != model.ProfileBaseline {
		t.Fatalf("normalizeProfile(\"\") = (%q,%v), want (baseline,nil)", got, err)
	}
}

func TestNormalizeProfileRejectsUnknown(t *testing.T) {
	for _, bad := range []string{"scheduled", "incident", "fast", "ALL"} {
		if _, err := normalizeProfile(bad); err == nil {
			t.Errorf("normalizeProfile(%q) accepted, want error", bad)
		}
	}
}

func TestParseEcosystemFilter(t *testing.T) {
	filter, err := parseEcosystemFilter([]string{"go,npm", "browser-extension"})
	if err != nil {
		t.Fatalf("parseEcosystemFilter: %v", err)
	}
	for _, ecosystem := range []string{model.EcosystemGo, model.EcosystemNPM, model.EcosystemBrowserExtension} {
		if !filter[ecosystem] {
			t.Fatalf("missing ecosystem %q from filter %v", ecosystem, filter)
		}
	}
}

func TestParseEcosystemFilterRejectsInvalid(t *testing.T) {
	if _, err := parseEcosystemFilter([]string{"npm,unknown"}); err == nil {
		t.Fatal("expected invalid ecosystem error")
	}
}

func TestRunScanFindingsOnlyRequiresExposureCatalog(t *testing.T) {
	code := runScan([]string{"--profile", "deep", "--root", t.TempDir(), "--findings-only"})
	if code != 2 {
		t.Fatalf("runScan exit code = %d, want 2", code)
	}
}

func TestRunScanRejectsInvalidEcosystem(t *testing.T) {
	code := runScan([]string{"--profile", "baseline", "--ecosystem", "unknown"})
	if code != 2 {
		t.Fatalf("runScan exit code = %d, want 2", code)
	}
}

func TestRunRootsRejectsUnknownProfile(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	code := runRoots([]string{"--profile", "scheduled"})
	if code != 2 {
		t.Fatalf("runRoots --profile=scheduled exit = %d, want 2 (unknown profile)", code)
	}
}
