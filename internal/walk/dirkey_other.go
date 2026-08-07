//go:build !unix

package walk

import "io/fs"

// dirIdent identifies a directory by cleaned path on platforms without
// stable device+inode identity.
type dirIdent string

func dirKey(path string) (dirIdent, bool) {
	return dirIdent(path), true
}

func dirKeyFromInfo(path string, _ fs.FileInfo) (dirIdent, bool) {
	return dirIdent(path), true
}
