// Profile-aware scan root resolution — delegates to internal/roots.
package main

import (
	"os"
	"strings"

	"github.com/perplexityai/bumblebee/internal/roots"
	"github.com/perplexityai/bumblebee/internal/scanner"
)

// rootsOpts groups the scoping inputs to resolveRoots.
type rootsOpts struct {
	AllUsers bool
}

func resolveRoots(profile string, explicit []string, opts rootsOpts) ([]scanner.Root, []string, error) {
	return roots.Resolve(profile, explicit, roots.Opts{
		AllUsers:         opts.AllUsers,
		UsersDirOverride: usersDirOverride(),
	})
}

func usersDirOverride() string {
	return strings.TrimSpace(os.Getenv("BUMBLEBEE_USERS_DIR"))
}
