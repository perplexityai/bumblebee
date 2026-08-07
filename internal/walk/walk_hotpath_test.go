package walk

import (
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

// TestSuffixExcludeRequiresFullSuffix pins the exclusion contract that a
// multi-component exclude matches only the full "/"-joined suffix, never
// the basename alone. A directory named "Caches" outside "Library" must
// still be walked even though "Library/Caches" is excluded.
func TestSuffixExcludeRequiresFullSuffix(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("path-separator semantics differ on Windows")
	}
	root := t.TempDir()
	mustMkdir(t, filepath.Join(root, "Library", "Caches"))
	mustMkdir(t, filepath.Join(root, "proj", "Caches"))
	mustWrite(t, filepath.Join(root, "Library", "Caches", "x"), "{}")
	mustWrite(t, filepath.Join(root, "proj", "Caches", "package-lock.json"), "{}")

	var files []string
	err := Walk(Options{
		Roots:    []string{root},
		Excludes: []string{"Library/Caches"},
	}, func(path string, d fs.DirEntry) error {
		if !d.IsDir() {
			files = append(files, path)
		}
		return nil
	})
	if err != nil {
		t.Fatalf("Walk: %v", err)
	}
	excluded := filepath.Join(root, "Library", "Caches", "x")
	wanted := filepath.Join(root, "proj", "Caches", "package-lock.json")
	sawWanted := false
	for _, p := range files {
		if p == excluded {
			t.Errorf("excluded subtree was visited: %s", p)
		}
		if p == wanted {
			sawWanted = true
		}
	}
	if !sawWanted {
		t.Errorf("basename-collision directory was wrongly pruned; saw %v", files)
	}
}

// TestSymlinkedDirectoryNeverDescended pins that a directory-shaped
// symlink is surfaced as a single non-directory entry and its target
// subtree is never entered.
func TestSymlinkedDirectoryNeverDescended(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("symlink semantics differ on Windows")
	}
	root := t.TempDir()
	target := t.TempDir()
	mustWrite(t, filepath.Join(target, "package-lock.json"), "{}")
	link := filepath.Join(root, "link")
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}

	var files []string
	err := Walk(Options{Roots: []string{root}}, func(path string, d fs.DirEntry) error {
		if !d.IsDir() {
			files = append(files, path)
		}
		return nil
	})
	if err != nil {
		t.Fatalf("Walk: %v", err)
	}
	for _, p := range files {
		if p != link {
			t.Errorf("walker crossed a directory symlink: %v", p)
		}
	}
}

// TestOverlappingRootsVisitOnce pins the dev+inode dedup: when one root
// encloses another, the inner subtree is visited exactly once.
func TestOverlappingRootsVisitOnce(t *testing.T) {
	root := t.TempDir()
	inner := filepath.Join(root, "inner")
	mustMkdir(t, inner)
	mustWrite(t, filepath.Join(inner, "package-lock.json"), "{}")

	counts := map[string]int{}
	err := Walk(Options{Roots: []string{root, inner}}, func(path string, d fs.DirEntry) error {
		if !d.IsDir() {
			counts[path]++
		}
		return nil
	})
	if err != nil {
		t.Fatalf("Walk: %v", err)
	}
	for p, n := range counts {
		if n != 1 {
			t.Errorf("visited %d times (want 1): %s", n, p)
		}
	}
	if len(counts) == 0 {
		t.Error("no files visited")
	}
}

// TestDirKeyFromInfoMatchesDirKey pins that the FileInfo-based key is
// identical to the path-based key for the same directory.
func TestDirKeyFromInfoMatchesDirKey(t *testing.T) {
	dir := t.TempDir()
	want, ok := dirKey(dir)
	if !ok {
		t.Fatalf("dirKey(%q) not ok", dir)
	}
	info, err := os.Lstat(dir)
	if err != nil {
		t.Fatal(err)
	}
	got, ok := dirKeyFromInfo(dir, info)
	if !ok {
		t.Fatalf("dirKeyFromInfo not ok")
	}
	if got != want {
		t.Errorf("dirKeyFromInfo = %v, dirKey = %v", got, want)
	}
}

// TestSeparatorOnlyExcludeMatchesRootByName pins that an exclude which
// cleans to the bare separator ("/", "//") stays a name-matched entry:
// it matches a root directory whose base name is the separator, exactly
// as it did when all excludes lived in one flat map.
func TestSeparatorOnlyExcludeMatchesRootByName(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("path-separator semantics differ on Windows")
	}
	for _, raw := range []string{"/", "//"} {
		ex := normalizeExcludes([]string{raw})
		if !isExcluded("/", "/", ex) {
			t.Errorf("exclude %q does not match the root path", raw)
		}
		if isExcluded("/Users/u/proj", "proj", ex) {
			t.Errorf("exclude %q wrongly matches a non-root directory", raw)
		}
	}
}

// benchTree builds a deterministic tree of dirs directories with files
// plain files each.
func benchTree(b *testing.B, dirs, files int) string {
	b.Helper()
	root := b.TempDir()
	for i := 0; i < dirs; i++ {
		d := filepath.Join(root, fmt.Sprintf("d%03d", i/50), fmt.Sprintf("dir%05d", i))
		if err := os.MkdirAll(d, 0o755); err != nil {
			b.Fatal(err)
		}
		for j := 0; j < files; j++ {
			if err := os.WriteFile(filepath.Join(d, fmt.Sprintf("f%d.txt", j)), []byte("x"), 0o644); err != nil {
				b.Fatal(err)
			}
		}
	}
	return root
}

func BenchmarkWalkDefaultExcludes(b *testing.B) {
	root := benchTree(b, 2000, 5)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		n := 0
		err := Walk(Options{Roots: []string{root}, Excludes: DefaultExcludes}, func(path string, d fs.DirEntry) error {
			if !d.IsDir() {
				n++
			}
			return nil
		})
		if err != nil {
			b.Fatal(err)
		}
		if n != 10000 {
			b.Fatalf("visited %d files, want 10000", n)
		}
	}
}

func BenchmarkIsExcluded(b *testing.B) {
	excludes := normalizeExcludes(DefaultExcludes)
	path := "/Users/u/some/project/tree/depth/dir"
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if isExcluded(path, "dir", excludes) {
			b.Fatal("unexpected exclusion")
		}
	}
}
