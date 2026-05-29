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

// TestWalkSkipsFileSymlinks verifies that file-typed symlinks under a
// scan root are not surfaced to the visitor. Without this, a single
// planted symlink at, say, node_modules/<pkg>/package.json pointing at
// an unrelated JSON file outside the scan root would be parsed by the
// ecosystem scanners (which open through os.Open and follow the link),
// causing the target file's name/version-shaped fields to be emitted as
// if they belonged to a real installed package. The walker's contract
// is that it never crosses into an unrelated subtree by indirection.
func TestWalkSkipsFileSymlinks(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("symlinks require admin on Windows")
	}
	root := t.TempDir()
	// In-scope regular file the walker should visit.
	inScope := filepath.Join(root, "proj", "package-lock.json")
	mustMkdir(t, filepath.Dir(inScope))
	mustWrite(t, inScope, "{}")

	// Out-of-scope target the symlink will point at.
	outOfScope := filepath.Join(root, "elsewhere", "target.json")
	mustMkdir(t, filepath.Dir(outOfScope))
	mustWrite(t, outOfScope, `{"name":"out-of-scope","version":"1.0.0"}`)

	// Plant a file-typed symlink inside the scan root pointing at the
	// out-of-scope target.
	symlinkPath := filepath.Join(root, "proj", "node_modules", "evil", "package.json")
	mustMkdir(t, filepath.Dir(symlinkPath))
	if err := os.Symlink(outOfScope, symlinkPath); err != nil {
		t.Skipf("symlink unsupported: %v", err)
	}

	scanRoot := filepath.Join(root, "proj")
	var seen []string
	err := Walk(Options{Roots: []string{scanRoot}}, func(path string, d fs.DirEntry) error {
		if !d.IsDir() {
			seen = append(seen, path)
		}
		return nil
	})
	if err != nil {
		t.Fatalf("Walk: %v", err)
	}

	for _, p := range seen {
		if p == symlinkPath {
			t.Errorf("file-typed symlink was surfaced to visitor: %q", p)
		}
	}

	foundInScope := false
	for _, p := range seen {
		if p == inScope {
			foundInScope = true
			break
		}
	}
	if !foundInScope {
		t.Errorf("expected to visit %q; saw %v", inScope, seen)
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
