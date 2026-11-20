package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func readRepoFile(t *testing.T, rel string) string {
	t.Helper()
	path := filepath.Join("..", "..", rel)
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", rel, err)
	}
	return string(data)
}

func TestReleasePolicyNoLatestInstallPaths(t *testing.T) {
	readme := readRepoFile(t, "README.md")
	if strings.Contains(readme, "go install github.com/perplexityai/bumblebee/cmd/bumblebee@latest") {
		t.Fatal("README still advertises an unpinned @latest install path")
	}
	ci := readRepoFile(t, ".github/workflows/ci.yml")
	if strings.Contains(ci, "golang.org/x/vuln/cmd/govulncheck@latest") {
		t.Fatal("CI still installs govulncheck from @latest")
	}
}

func TestReleasePolicySBOMConfigured(t *testing.T) {
	goreleaser := readRepoFile(t, ".goreleaser.yaml")
	for _, want := range []string{
		"sboms:",
		"disable: false",
		"artifacts: archive",
	} {
		if !strings.Contains(goreleaser, want) {
			t.Fatalf(".goreleaser.yaml missing %q", want)
		}
	}
}
