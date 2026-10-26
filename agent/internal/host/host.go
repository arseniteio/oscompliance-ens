package host

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"strings"
	"time"
)

const CommandTimeout = 10 * time.Second

func Run(name string, args ...string) (string, error) {

	ctx, cancel := context.WithTimeout(context.Background(), CommandTimeout)
	defer cancel()

	out, err := exec.CommandContext(ctx, name, args...).CombinedOutput()

	if err != nil {
		return "", fmt.Errorf("%s %s: %w: %s", name, strings.Join(args, " "), err, strings.TrimSpace(string(out)))
	}

	return string(out), nil
}

func Exists(path string) bool {
	_, err := os.Stat(path)
	return path != "" && !errors.Is(err, fs.ErrNotExist) && err == nil
}
