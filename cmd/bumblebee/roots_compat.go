package main

import (
	"github.com/perplexityai/bumblebee/internal/roots"
	"github.com/perplexityai/bumblebee/internal/scanner"
)

func classifyRoot(path, profile string) string {
	return roots.ClassifyRoot(path, profile)
}

func isBroadHomeRoot(path string) bool {
	return roots.IsBroadHomeRoot(path)
}

func isLikelyUserHomeName(name string) bool {
	return roots.IsLikelyUserHomeName(name)
}

func allUsersHomes(usersDir string) []string {
	return roots.AllUsersHomes(usersDir)
}

func baselineHomeCandidates(home string) []scanner.Root {
	return roots.BaselineHomeCandidates(home)
}

func filterExistingRoots(candidates []scanner.Root) ([]scanner.Root, []string) {
	return roots.FilterExistingRoots(candidates)
}
