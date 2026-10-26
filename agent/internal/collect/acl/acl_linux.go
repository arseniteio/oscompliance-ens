package acl

import (
	"errors"
	"syscall"
)

// getACL reads one ACL attribute; nil when the path has none or the file
// system has no ACLs.
func getACL(path, name string) ([]byte, error) {

	size, err := syscall.Getxattr(path, name, nil)

	if errors.Is(err, syscall.ENODATA) || errors.Is(err, syscall.ENOTSUP) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}

	buf := make([]byte, size)
	n, err := syscall.Getxattr(path, name, buf)
	if err != nil {
		return nil, err
	}

	return buf[:n], nil
}
