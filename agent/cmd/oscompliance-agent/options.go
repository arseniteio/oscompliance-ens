package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io/fs"
	"os"
	"slices"
	"strings"
	"time"
)

const defaultConfigPath = "/etc/oscompliance/agent.json"

type options struct {
	Output       string   `json:"output"`
	Host         string   `json:"host"`
	State        string   `json:"state"`
	Collectors   []string `json:"collectors"`
	SweepTimeout duration `json:"sweep_timeout"`
	Paths        paths    `json:"paths"`

	full     bool
	selected map[string]bool
}

type paths struct {
	Passwd  string `json:"passwd"`
	Shadow  string `json:"shadow"`
	Group   string `json:"group"`
	SSHD    string `json:"sshd"`
	Sudoers string `json:"sudoers"`
	PAMDir  string `json:"pam_dir"`
}

type duration struct{ time.Duration }

func (d *duration) UnmarshalJSON(b []byte) error {
	var s string
	if err := json.Unmarshal(b, &s); err != nil {
		return fmt.Errorf("a duration is a string such as \"15m\": %w", err)
	}
	parsed, err := time.ParseDuration(s)
	d.Duration = parsed
	return err
}

func defaultOptions() options {
	return options{
		Output:       "/var/log/oscompliance/facts.ndjson",
		State:        "/var/lib/oscompliance/state.json",
		Collectors:   slices.DeleteFunc(slices.Clone(allCollectors), func(c string) bool { return c == "sweep" }),
		SweepTimeout: duration{15 * time.Minute},
		Paths: paths{
			Passwd:  "/etc/passwd",
			Shadow:  "/etc/shadow",
			Group:   "/etc/group",
			SSHD:    "/usr/sbin/sshd",
			Sudoers: "/etc/sudoers",
			PAMDir:  "/etc/pam.d",
		},
	}
}

func parseOptions() (options, error) {

	configPath := flag.String("config", defaultConfigPath, "configuration file; without it the defaults apply")
	collect := flag.String("collect", "", "comma-separated collectors for this run, instead of the configured ones (cron runs sweep daily with -collect sweep)")
	full := flag.Bool("full", false, "send everything even when nothing changed")
	flag.Parse()

	opts, err := loadOptions(*configPath, *configPath != defaultConfigPath)
	if err != nil {
		return opts, err
	}
	opts.full = *full

	if *collect != "" {
		opts.Collectors = strings.Split(*collect, ",")
	}
	if opts.selected, err = selectCollectors(opts.Collectors); err != nil {
		return opts, err
	}

	if opts.Host == "" {
		if opts.Host, err = os.Hostname(); err != nil {
			return opts, fmt.Errorf("hostname: %w", err)
		}
	}

	return opts, nil
}

func loadOptions(path string, required bool) (options, error) {

	opts := defaultOptions()

	data, err := os.ReadFile(path)
	switch {
	case errors.Is(err, fs.ErrNotExist) && !required:
		return opts, nil
	case err != nil:
		return opts, fmt.Errorf("configuration: %w", err)
	}

	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&opts); err != nil {
		return opts, fmt.Errorf("configuration %s: %w", path, err)
	}

	return opts, nil
}

func selectCollectors(names []string) (map[string]bool, error) {

	selected := map[string]bool{}
	for _, name := range names {
		name = strings.TrimSpace(name)
		if !slices.Contains(allCollectors, name) {
			return nil, fmt.Errorf("unknown collector %q (known: %s)", name, strings.Join(allCollectors, ", "))
		}
		selected[name] = true
	}

	return selected, nil
}
