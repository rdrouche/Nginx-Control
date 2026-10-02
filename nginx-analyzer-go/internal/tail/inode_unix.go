//go:build linux || darwin

package tail

import (
	"os"
	"syscall"
)

// inodeOf extrait le numero d inode d un os.FileInfo (Linux/macOS). Le deploiement cible de
// ce projet est Docker/Alpine (Linux), mais darwin est inclus pour permettre les tests locaux
// sur macOS.
func inodeOf(fi os.FileInfo) uint64 {
	if st, ok := fi.Sys().(*syscall.Stat_t); ok {
		return uint64(st.Ino)
	}
	return 0
}
