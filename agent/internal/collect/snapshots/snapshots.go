package snapshots

import (
	"strconv"
	"strings"
	"time"

	"github.com/arseniteio/oscompliance-ens/agent/internal/emit"
	"github.com/arseniteio/oscompliance-ens/agent/internal/host"
	"github.com/arseniteio/oscompliance-ens/catalog/fact"
)

type Config struct {
	LVS   string
	ZFS   string
	Btrfs string
}

var Default = Config{LVS: "/usr/sbin/lvs", ZFS: "/usr/sbin/zfs", Btrfs: "/usr/bin/btrfs"}

func Collect(e *emit.Emitter, cfg Config) error {

	s := fact.SnapshotList{Envelope: e.Envelope(fact.SnapshotListFact), Status: fact.SourceRead, Snapshots: []fact.Snapshot{}}
	var errs []string

	if host.Exists(cfg.LVS) {
		out, err := host.Run(cfg.LVS, "--noheadings", "--separator", "|", "-o", "lv_name,lv_attr,lv_time", "--config", "report/time_format=%s")
		if err != nil {
			errs = append(errs, err.Error())
		}
		s.Snapshots = append(s.Snapshots, lvm(out)...)
	}
	if host.Exists(cfg.ZFS) {
		out, err := host.Run(cfg.ZFS, "list", "-H", "-p", "-t", "snapshot", "-o", "name,creation")
		if err != nil {
			errs = append(errs, err.Error())
		}
		s.Snapshots = append(s.Snapshots, zfs(out)...)
	}
	if host.Exists(cfg.Btrfs) {
		if out, err := host.Run(cfg.Btrfs, "subvolume", "list", "-s", "/"); err == nil {
			for _, path := range btrfsPaths(out) {
				if info, err := host.Run(cfg.Btrfs, "subvolume", "show", "/"+path); err == nil {
					if created := btrfsCreated(info); created != "" {
						s.Snapshots = append(s.Snapshots, fact.Snapshot{Tool: "btrfs", Name: path, Created: created})
					}
				}
			}
		}
	}

	if len(errs) > 0 {
		s.Status, s.Error = fact.SourceError, strings.Join(errs, "; ")
	}
	return e.Emit(s)
}

func lvm(out string) []fact.Snapshot {
	var list []fact.Snapshot
	for _, line := range strings.Split(out, "\n") {
		f := strings.Split(strings.TrimSpace(line), "|")
		if len(f) < 3 || f[1] == "" || (f[1][0] != 's' && f[1][0] != 'S') {
			continue
		}
		if t, err := strconv.ParseInt(strings.TrimSpace(f[2]), 10, 64); err == nil {
			list = append(list, fact.Snapshot{Tool: "lvm", Name: strings.TrimSpace(f[0]), Created: time.Unix(t, 0).UTC().Format(time.RFC3339)})
		}
	}
	return list
}

func zfs(out string) []fact.Snapshot {
	var list []fact.Snapshot
	for _, line := range strings.Split(out, "\n") {
		f := strings.Split(line, "\t")
		if len(f) < 2 {
			continue
		}
		if t, err := strconv.ParseInt(strings.TrimSpace(f[1]), 10, 64); err == nil {
			list = append(list, fact.Snapshot{Tool: "zfs", Name: f[0], Created: time.Unix(t, 0).UTC().Format(time.RFC3339)})
		}
	}
	return list
}

func btrfsPaths(out string) []string {
	var paths []string
	for _, line := range strings.Split(out, "\n") {
		if i := strings.Index(line, " path "); i >= 0 {
			paths = append(paths, strings.TrimSpace(line[i+len(" path "):]))
		}
	}
	return paths
}

func btrfsCreated(info string) string {
	for _, line := range strings.Split(info, "\n") {
		key, value, ok := strings.Cut(strings.TrimSpace(line), ":")
		if ok && key == "Creation time" {
			if t, err := time.Parse("2006-01-02 15:04:05 -0700", strings.TrimSpace(value)); err == nil {
				return t.UTC().Format(time.RFC3339)
			}
		}
	}
	return ""
}
