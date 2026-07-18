package scanner

import (
	"fmt"
	"path/filepath"
	"testing"

	"github.com/perplexityai/bumblebee/internal/model"
)

func TestNewRootKindLookup(t *testing.T) {
	sep := string(filepath.Separator)
	homeUser := filepath.Join(sep+"home", "alice")
	homeProj := filepath.Join(homeUser, "src", "proj")
	system := filepath.Join(sep+"usr", "local")

	roots := []Root{
		{Path: homeUser, Kind: model.RootKindUserPackage},
		{Path: homeProj, Kind: model.RootKindProject},
		{Path: system, Kind: model.RootKindHomebrew},
		{Path: "", Kind: "ignored"},
	}
	lookup := newRootKindLookup(roots)

	tests := []struct {
		name string
		path string
		want string
	}{
		{"empty path", "", model.RootKindUnknown},
		{"exact match user home", homeUser, model.RootKindUserPackage},
		{"deep under user home", filepath.Join(homeUser, "Library", "Caches"), model.RootKindUserPackage},
		{"longest-match wins", filepath.Join(homeProj, "package.json"), model.RootKindProject},
		{"system root", filepath.Join(system, "bin", "go"), model.RootKindHomebrew},
		{"outside all roots", filepath.Join(sep+"var", "log", "x"), model.RootKindUnknown},
		{"prefix overlap without separator is not a match", homeUser + "extra", model.RootKindUnknown},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := lookup(tc.path); got != tc.want {
				t.Fatalf("lookup(%q) = %q, want %q", tc.path, got, tc.want)
			}
		})
	}
}

func BenchmarkNewRootKindLookup(b *testing.B) {
	sep := string(filepath.Separator)
	roots := []Root{
		{Path: filepath.Join(sep+"home", "alice"), Kind: model.RootKindUserPackage},
		{Path: filepath.Join(sep+"home", "alice", "src", "proj"), Kind: model.RootKindProject},
		{Path: filepath.Join(sep+"home", "alice", "src", "other"), Kind: model.RootKindProject},
		{Path: filepath.Join(sep+"usr", "local"), Kind: model.RootKindHomebrew},
		{Path: filepath.Join(sep+"opt", "homebrew"), Kind: model.RootKindHomebrew},
		{Path: filepath.Join(sep+"Applications"), Kind: model.RootKindHomebrew},
	}
	lookup := newRootKindLookup(roots)

	paths := make([]string, 0, 64)
	for i := range 16 {
		paths = append(paths,
			filepath.Join(sep+"home", "alice", "src", "proj", "node_modules", "dep", fmt.Sprintf("file-%d.json", i)),
			filepath.Join(sep+"home", "alice", "Library", "Caches", fmt.Sprintf("pkg-%d.json", i)),
			filepath.Join(sep+"usr", "local", "lib", fmt.Sprintf("x-%d.json", i)),
			filepath.Join(sep+"var", "log", fmt.Sprintf("y-%d.json", i)),
		)
	}

	b.ReportAllocs()
	var sink string
	for b.Loop() {
		for _, p := range paths {
			sink = lookup(p)
		}
	}
	_ = sink
}
