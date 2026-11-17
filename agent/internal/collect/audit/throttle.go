package audit

import (
	"bufio"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/arseniteio/oscompliance-ens-wazuh/agent/internal/host"
)

type Throttle map[string]time.Time

func LoadThrottle(path string) (Throttle, error) {

	t := Throttle{}
	if path == "" {
		return t, nil
	}

	data, err := os.ReadFile(path)
	if errors.Is(err, fs.ErrNotExist) {
		return t, nil
	}
	if err != nil {
		return t, err
	}
	if err := json.Unmarshal(data, &t); err != nil {
		return Throttle{}, fmt.Errorf("unreadable, ignored: %w", err)
	}
	return t, nil
}

func (t Throttle) Active(now time.Time) Throttle {
	out := Throttle{}
	for p, until := range t {
		if until.After(now) {
			out[p] = until
		}
	}
	return out
}

func (t Throttle) Save(path string) error {

	data, err := json.Marshal(t)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

type GuardConfig struct {
	Auditctl string
	Log      string
	Throttle string

	Limit   int
	Window  time.Duration
	Suspend time.Duration
}

const (
	DefaultReadLimit    = 60
	DefaultGuardWindow  = 5 * time.Minute
	DefaultGuardSuspend = time.Hour

	// The tail of the audit log read on each guard run; a busy log rotates sooner.
	logTail = 32 << 20
)

type Suspension struct {
	Path  string
	Reads int
	Until time.Time
}

func Guard(cfg GuardConfig, now time.Time) ([]Suspension, error) {

	// Cron runs this every few minutes: the hourly pass is too late, a noisy read watch fills
	// a disk in minutes. The throttle file keeps Collect from loading the watch again.

	rules, err := loadedRules(cfg.Auditctl)
	if err != nil {
		return nil, err
	}
	var reads []loadedRule
	for _, r := range rules {
		if r.Key == readWatch.Key {
			reads = append(reads, r)
		}
	}

	throttle, loadErr := LoadThrottle(cfg.Throttle)
	throttle = throttle.Active(now)
	if len(reads) == 0 {
		return nil, errors.Join(loadErr, throttle.Save(cfg.Throttle))
	}

	log, err := openTail(cfg.Log, logTail)
	if err != nil {
		return nil, err
	}
	defer log.Close()

	watched := make([]string, 0, len(reads))
	for _, r := range reads {
		watched = append(watched, r.Path)
	}
	perPath, err := CountReads(log, watched, now.Add(-cfg.Window))
	if err != nil {
		return nil, err
	}

	// Per watch only: a flood on one path must not switch off the auditing of the others.
	limit := cfg.Limit * max(1, int(cfg.Window/time.Minute))

	var suspended []Suspension
	var errs []error
	for _, r := range reads {
		if perPath[r.Path] <= limit {
			continue
		}
		if _, err := host.Run(cfg.Auditctl, r.deletion()...); err != nil {
			errs = append(errs, err)
			continue
		}
		until := now.Add(cfg.Suspend)
		throttle[r.Path] = until
		suspended = append(suspended, Suspension{Path: r.Path, Reads: perPath[r.Path], Until: until})
	}

	errs = append(errs, loadErr, throttle.Save(cfg.Throttle))
	return suspended, errors.Join(errs...)
}

func openTail(path string, size int64) (io.ReadCloser, error) {

	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	info, err := f.Stat()
	if err != nil {
		f.Close()
		return nil, err
	}
	if info.Size() > size {
		if _, err := f.Seek(info.Size()-size, io.SeekStart); err != nil {
			f.Close()
			return nil, err
		}
	}
	return f, nil
}

type readEvent struct {
	at    time.Time
	names []string
}

func CountReads(r io.Reader, watched []string, since time.Time) (map[string]int, error) {

	// Only successful reads count: failed attempts by people without access cannot suspend a watch.

	events := map[string]*readEvent{}
	var order []string

	scanner := bufio.NewScanner(r)
	scanner.Buffer(make([]byte, 64<<10), 1<<20)
	for scanner.Scan() {
		line := scanner.Text()
		kind, at, serial, ok := recordHeader(line)
		if !ok {
			continue
		}
		switch kind {
		case "SYSCALL":
			if field(line, "key") == readWatch.Key && field(line, "success") == "yes" {
				events[serial] = &readEvent{at: at}
				order = append(order, serial)
			}
		case "PATH":
			// A relative name, or the parent directory of an openat, could charge one watch with
			// the reads of another: only absolute names of the file itself count.
			if e, ok := events[serial]; ok && field(line, "nametype") == "NORMAL" {
				if name := field(line, "name"); filepath.IsAbs(name) {
					e.names = append(e.names, filepath.Clean(name))
				}
			}
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}

	perPath := map[string]int{}
	for _, serial := range order {
		e := events[serial]
		if e.at.Before(since) {
			continue
		}
		if p := holder(e, watched); p != "" {
			perPath[p]++
		}
	}
	return perPath, nil
}

func holder(e *readEvent, watched []string) string {

	best := ""
	for _, name := range e.names {
		for _, w := range watched {
			if (name == w || strings.HasPrefix(name, strings.TrimSuffix(w, "/")+"/")) && len(w) > len(best) {
				best = w
			}
		}
	}
	return best
}

func recordHeader(line string) (kind string, at time.Time, serial string, ok bool) {

	rest, found := strings.CutPrefix(line, "type=")
	if !found {
		return "", time.Time{}, "", false
	}
	kind, rest, found = strings.Cut(rest, " ")
	if !found {
		return "", time.Time{}, "", false
	}
	_, stamp, found := strings.Cut(rest, "msg=audit(")
	if !found {
		return "", time.Time{}, "", false
	}
	stamp, _, found = strings.Cut(stamp, ")")
	if !found {
		return "", time.Time{}, "", false
	}
	seconds, serial, found := strings.Cut(stamp, ":")
	if !found {
		return "", time.Time{}, "", false
	}
	whole, _, _ := strings.Cut(seconds, ".")
	unix, err := strconv.ParseInt(whole, 10, 64)
	if err != nil {
		return "", time.Time{}, "", false
	}
	return kind, time.Unix(unix, 0), serial, true
}

// auditd writes a value hex encoded, without quotes, when it holds spaces or control bytes.
func field(line, name string) string {

	i := strings.Index(line, " "+name+"=")
	if i < 0 {
		return ""
	}
	value := line[i+len(name)+2:]
	if quoted, found := strings.CutPrefix(value, `"`); found {
		v, _, _ := strings.Cut(quoted, `"`)
		return v
	}
	value, _, _ = strings.Cut(value, " ")
	if value == "(null)" {
		return ""
	}
	if decoded, err := hex.DecodeString(value); err == nil {
		return string(decoded)
	}
	return value
}
