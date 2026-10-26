//go:build !linux

package acl

func getACL(path, name string) ([]byte, error) {
	return nil, nil
}
