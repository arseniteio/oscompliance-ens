package winps

import (
	"encoding/json"
	"errors"
	"fmt"
	"time"
)

type Runner func(script string) ([]byte, error)

const Timeout = 3 * time.Minute

var ErrUnsupported = errors.New("PowerShell collectors run only on Windows")

func Decode[T any](run Runner, script string) (T, error) {

	var out T

	raw, err := run(script)
	if err != nil {
		return out, err
	}

	if err := json.Unmarshal(trimBOM(raw), &out); err != nil {
		return out, fmt.Errorf("powershell output: %w", err)
	}
	return out, nil
}

func trimBOM(b []byte) []byte {
	if len(b) >= 3 && b[0] == 0xef && b[1] == 0xbb && b[2] == 0xbf {
		return b[3:]
	}
	return b
}

func Static(output string) Runner {
	return func(string) ([]byte, error) { return []byte(output), nil }
}

func Failing(err error) Runner {
	return func(string) ([]byte, error) { return nil, err }
}
