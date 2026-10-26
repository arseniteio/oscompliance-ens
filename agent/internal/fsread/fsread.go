// Package fsread opens the files the agent reads. The agent runs as root and
// reads paths users control (authorized_keys) or the manager names (service
// logs): a FIFO or a device there must not block or feed it forever.
package fsread

import (
	"fmt"
	"io"
	"os"
	"syscall"
)

// MaxFile bounds what ReadFile loads: configuration and account files are
// far smaller.
const MaxFile = 16 << 20

// Open opens a regular file for reading. It opens without blocking, so a
// FIFO cannot hold the agent, and refuses anything that is not a regular
// file.
func Open(path string) (*os.File, error) {

	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NONBLOCK|syscall.O_NOCTTY, 0)
	if err != nil {
		return nil, err
	}

	info, err := f.Stat()
	if err != nil {
		f.Close()
		return nil, err
	}

	if !info.Mode().IsRegular() {
		f.Close()
		return nil, fmt.Errorf("%s: not a regular file", path)
	}

	return f, nil
}

// ReadFile reads a regular file of at most MaxFile bytes.
func ReadFile(path string) ([]byte, error) {

	f, err := Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	data, err := io.ReadAll(io.LimitReader(f, MaxFile+1))
	if err != nil {
		return nil, err
	}
	if len(data) > MaxFile {
		return nil, fmt.Errorf("%s: larger than %d bytes", path, MaxFile)
	}

	return data, nil
}
