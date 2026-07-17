package main

import (
	"fmt"
	"runtime"
	"runtime/debug"
	"strings"
)

// Version is the scanner's released version. Precedence:
//
//  1. -ldflags "-X main.Version=..." set at build time.
//  2. The module version recorded by go install / go build in the binary's
//     build info, for example v0.1.1 when installed by tag.
//  3. The compiled-in default, which tracks the repo's VERSION file.
var Version = ""

// currentVersion returns the resolved version string (no commit / build
// info). Used by callers that need a single token, such as the records'
// scanner_version field and the HTTP sink's User-Agent.
func currentVersion() string {
	const fileDefault = "0.1.6"
	if v := strings.TrimSpace(Version); v != "" {
		return v
	}
	bi, ok := debug.ReadBuildInfo()
	if !ok {
		return fileDefault
	}
	v := strings.TrimSpace(bi.Main.Version)
	if v == "" || v == "(devel)" {
		return fileDefault
	}
	return v
}

// versionString returns the multi-line output for `bumblebee version`.
// It includes the version, VCS revision, build time, and Go runtime so
// operators triaging an emitted finding can identify the exact binary
// that produced it.
func versionString() string {
	revision := "unknown"
	built := "unknown"
	if bi, ok := debug.ReadBuildInfo(); ok {
		var modified bool
		for _, s := range bi.Settings {
			switch s.Key {
			case "vcs.revision":
				if s.Value != "" {
					revision = s.Value
				}
			case "vcs.time":
				if s.Value != "" {
					built = s.Value
				}
			case "vcs.modified":
				modified = s.Value == "true"
			}
		}
		if modified && revision != "unknown" {
			revision += "-dirty"
		}
	}
	return fmt.Sprintf(
		"bumblebee %s\ncommit: %s\nbuilt:  %s\ngo:     %s",
		currentVersion(), revision, built, runtime.Version(),
	)
}
