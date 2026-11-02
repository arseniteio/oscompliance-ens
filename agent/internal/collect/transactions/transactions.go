package transactions

import (
	"bufio"
	"errors"
	"io/fs"
	"strings"
	"time"

	"github.com/arseniteio/oscompliance-ens/agent/internal/emit"
	"github.com/arseniteio/oscompliance-ens/agent/internal/fsread"
	"github.com/arseniteio/oscompliance-ens/catalog/fact"
)

type Config struct {
	History string
}

var Default = Config{History: "/var/log/apt/history.log"}

func Collect(e *emit.Emitter, cfg Config) error {

	s := fact.TransactionSnapshot{Envelope: e.Envelope(fact.TransactionSnapshotFact), Manager: "apt", Status: fact.SourceRead}

	data, err := fsread.ReadFile(cfg.History)
	switch {
	case errors.Is(err, fs.ErrNotExist):
		s.Manager, s.Status = "none", fact.SourceAbsent
		return e.Emit(s)
	case err != nil:
		s.Status, s.Error = fact.SourceUnreadable, err.Error()
		return e.Emit(s)
	}

	for _, t := range Parse(string(data)) {
		t.Envelope = e.Envelope(fact.PackageTransactionFact)
		if err := e.Emit(t); err != nil {
			return err
		}
		s.RecordsEmitted++
	}

	return e.Emit(s)
}

const historyTime = "2006-01-02  15:04:05"

func Parse(log string) []fact.PackageTransaction {

	var out []fact.PackageTransaction
	var t *fact.PackageTransaction

	lines := bufio.NewScanner(strings.NewReader(log))
	lines.Buffer(make([]byte, 0, 64*1024), 4*1024*1024)
	for lines.Scan() {
		key, value, ok := strings.Cut(lines.Text(), ": ")
		if !ok {
			continue
		}
		value = strings.TrimSpace(value)
		switch key {
		case "Start-Date":
			out = append(out, fact.PackageTransaction{Start: stamp(value)})
			t = &out[len(out)-1]
		case "End-Date":
			if t != nil {
				t.End = stamp(value)
			}
		case "Commandline":
			if t != nil {
				t.Command = value
			}
		case "Requested-By":
			if t != nil {
				name, _, _ := strings.Cut(value, " (")
				t.Actor = name
			}
		case "Install":
			if t != nil {
				t.Installed = packages(value)
			}
		case "Upgrade":
			if t != nil {
				t.Upgraded = packages(value)
			}
		case "Remove", "Purge":
			if t != nil {
				t.Removed = append(t.Removed, packages(value)...)
			}
		}
	}

	for i := range out {
		if out[i].Actor == "" {
			out[i].Actor = "root"
			if strings.Contains(out[i].Command, "unattended-upgrade") {
				out[i].Actor = "unattended-upgrades"
			}
		}
	}
	return out
}

func stamp(v string) string {
	t, err := time.ParseInLocation(historyTime, v, time.Local)
	if err != nil {
		return v
	}
	return t.Format(time.RFC3339)
}

func packages(v string) []string {
	var out []string
	for _, item := range strings.Split(v, "), ") {
		name, versions, _ := strings.Cut(strings.TrimSuffix(item, ")"), " (")
		name, _, _ = strings.Cut(name, ":")
		parts := strings.Split(versions, ", ")
		version := strings.TrimSuffix(parts[len(parts)-1], ", automatic")
		if version == "automatic" && len(parts) > 1 {
			version = parts[len(parts)-2]
		}
		if name = strings.TrimSpace(name); name != "" {
			out = append(out, name+" "+strings.TrimSpace(version))
		}
	}
	return out
}
