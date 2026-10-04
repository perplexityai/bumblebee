package walk

import (
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

// TestDefaultExcludesCoverProtectedMacOSLibraryPaths ensures the macOS
// Library subtrees that routinely produce TCC denials under broad
// $HOME scans are matched by the default suffix-component excludes.
// Adding new paths to DefaultExcludes is cheap; regressing one of
// these silently is what makes the diagnostics output scary.
func TestDefaultExcludesCoverProtectedMacOSLibraryPaths(t *testing.T) {
	want := []string{
		"Library/ContainerManager",
		"Library/Daemon Containers",
		"Library/DoNotDisturb",
		"Library/DuetExpertCenter",
		"Library/IntelligencePlatform",
		"Library/Photos",
		"Library/Sharing",
		"Library/Shortcuts",
		"Library/StatusKit",
	}
	have := make(map[string]bool, len(DefaultExcludes))
	for _, x := range DefaultExcludes {
		have[x] = true
	}
	for _, w := range want {
		if !have[w] {
			t.Errorf("DefaultExcludes missing %q", w)
		}
	}
}

// TestWalkSkipsExcludedLibrarySubtrees verifies that an exclude with
// a "/"-separated suffix (e.g. "Library/ContainerManager") prunes a
// matching directory anywhere under any root, while a sibling
// directory that does not match continues to be walked.
func TestWalkSkipsExcludedLibrarySubtrees(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("path-separator semantics differ on Windows")
	}
	root := t.TempDir()
	// Simulate a $HOME-shaped tree.
	mustMkdir(t, filepath.Join(root, "Library", "ContainerManager", "deep"))
	mustMkdir(t, filepath.Join(root, "Library", "StatusKit"))
	mustMkdir(t, filepath.Join(root, "code", "proj"))

	// Drop sentinel files we can detect from the visitor.
	mustWrite(t, filepath.Join(root, "Library", "ContainerManager", "deep", "secret.json"), "{}")
	mustWrite(t, filepath.Join(root, "Library", "StatusKit", "x"), "{}")
	mustWrite(t, filepath.Join(root, "code", "proj", "package-lock.json"), "{}")

	excludes := append([]string{}, DefaultExcludes...)

	var seen []string
	err := Walk(Options{
		Roots:    []string{root},
		Excludes: excludes,
	}, func(path string, d fs.DirEntry) error {
		if !d.IsDir() {
			seen = append(seen, path)
		}
		return nil
	})
	if err != nil {
		t.Fatalf("Walk: %v", err)
	}
	for _, p := range seen {
		if filepath.Base(filepath.Dir(p)) == "deep" || filepath.Base(filepath.Dir(p)) == "StatusKit" {
			t.Errorf("excluded path was visited: %s", p)
		}
	}
	want := filepath.Join(root, "code", "proj", "package-lock.json")
	found := false
	for _, p := range seen {
		if p == want {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("expected to visit %q; saw %v", want, seen)
	}
}

// TestWalkSkipsXcodeBuildOutputButKeepsSourcePackages verifies that the
// default excludes prune Xcode DerivedData build output and caches while
// Swift package checkouts, which carry lockfiles, are still walked.
func TestWalkSkipsXcodeBuildOutputButKeepsSourcePackages(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("path-separator semantics differ on Windows")
	}
	root := t.TempDir()
	derived := filepath.Join(root, "src", "app", "DerivedData", "App")
	skipped := []string{
		filepath.Join(derived, "Build", "Intermediates.noindex", "App.build", "package-lock.json"),
		filepath.Join(derived, "Build", "Products", "Debug", "App.app", "package-lock.json"),
		filepath.Join(derived, "Index.noindex", "DataStore", "package-lock.json"),
		filepath.Join(root, "src", "app", "DerivedData", "ModuleCache.noindex", "package-lock.json"),
		filepath.Join(root, "Library", "Developer", "CoreSimulator", "Devices", "1", "package-lock.json"),
	}
	kept := filepath.Join(derived, "SourcePackages", "checkouts", "dep", "Gemfile.lock")
	for _, p := range append(skipped, kept) {
		mustMkdir(t, filepath.Dir(p))
		mustWrite(t, p, "{}")
	}

	visited := make(map[string]bool)
	err := Walk(Options{
		Roots:    []string{root},
		Excludes: DefaultExcludes,
	}, func(path string, d fs.DirEntry) error {
		if !d.IsDir() {
			visited[path] = true
		}
		return nil
	})
	if err != nil {
		t.Fatalf("Walk: %v", err)
	}
	for _, p := range skipped {
		if visited[p] {
			t.Errorf("excluded path was visited: %s", p)
		}
	}
	if !visited[kept] {
		t.Errorf("expected to visit %q", kept)
	}
}

func mustMkdir(t *testing.T, p string) {
	t.Helper()
	if err := os.MkdirAll(p, 0o755); err != nil {
		t.Fatal(err)
	}
}

func mustWrite(t *testing.T, p, body string) {
	t.Helper()
	if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
}
