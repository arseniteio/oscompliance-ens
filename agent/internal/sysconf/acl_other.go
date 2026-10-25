//go:build !linux

package sysconf

// getACL: POSIX ACLs are read on Linux only; elsewhere none is reported.
func getACL(path, name string) ([]byte, error) {
	return nil, nil
}
