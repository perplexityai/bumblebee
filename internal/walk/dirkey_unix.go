//go:build unix

package walk

import (
	"io/fs"
	"os"
	"syscall"
)

// dirIdent identifies a directory by device and inode for symlink-loop
// and overlapping-root dedup.
type dirIdent struct {
	dev uint64
	ino uint64
}

func dirKey(path string) (dirIdent, bool) {
	info, err := os.Stat(path)
	if err != nil {
		return dirIdent{}, false
	}
	return dirKeyFromInfo(path, info)
}

func dirKeyFromInfo(_ string, info fs.FileInfo) (dirIdent, bool) {
	sys, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return dirIdent{}, false
	}
	return dirIdent{dev: uint64(sys.Dev), ino: uint64(sys.Ino)}, true
}
