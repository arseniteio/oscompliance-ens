package snapshots

import "testing"

func TestParsers(t *testing.T) {

	if got := lvm("  root|-wi-ao----|1761000000\n  pre-patch|swi-a-s---|1761700000\n"); len(got) != 1 || got[0].Name != "pre-patch" || got[0].Created != "2025-10-29T01:06:40Z" {
		t.Errorf("lvm: %v", got)
	}
	if got := zfs("tank/root@pre-patch\t1761700000\n"); len(got) != 1 || got[0].Tool != "zfs" {
		t.Errorf("zfs: %v", got)
	}
	if got := btrfsPaths("ID 257 gen 10 cgen 9 top level 5 otime 2026-10-20 06:00:00 path .snapshots/1/snapshot\n"); len(got) != 1 || got[0] != ".snapshots/1/snapshot" {
		t.Errorf("btrfs paths: %v", got)
	}
	if got := btrfsCreated("\tName: \t\t\tsnapshot\n\tCreation time: \t\t2026-10-20 06:00:00 +0200\n"); got != "2026-10-20T04:00:00Z" {
		t.Errorf("btrfs time: %q", got)
	}
}
