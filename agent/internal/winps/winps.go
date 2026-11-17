package winps

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"time"
)

type Runner func(script string) ([]byte, error)

const Timeout = 3 * time.Minute

var ErrUnsupported = errors.New("PowerShell collectors run only on Windows")

// WithInput hands v to the script as $in. Base64 keeps quotes and other
// characters of the value out of the PowerShell parser.
func WithInput(v any, script string) (string, error) {
	data, err := json.Marshal(v)
	if err != nil {
		return "", err
	}
	return "$in = [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('" + base64.StdEncoding.EncodeToString(data) + "')) | ConvertFrom-Json\n" + script, nil
}

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
