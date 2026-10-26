package fsread

import (
	"fmt"
	"io"
	"os"
	"syscall"
)

const MaxFile = 16 << 20

func Open(path string) (*os.File, error) {

	// Non-blocking, so a FIFO planted in a read path cannot hang the agent.
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
