package transactions

import (
	"strings"
	"testing"
)

const history = `
Start-Date: 2026-10-20  06:25:31
Commandline: /usr/bin/unattended-upgrade
Upgrade: libpam-runtime:amd64 (1.5.3-5ubuntu5.5, 1.5.3-5ubuntu5.6)
End-Date: 2026-10-20  06:25:40

Start-Date: 2026-10-21  11:02:00
Commandline: apt install nmap
Requested-By: jgomez (1001)
Install: libpcap0.8t64:amd64 (1.10.4-4.1ubuntu3, automatic), nmap:amd64 (7.94+git20230807-3build2)
End-Date: 2026-10-21  11:02:09

Start-Date: 2026-10-22  09:00:00
Commandline: apt purge telnet
Purge: telnet:amd64 (0.17+2.5-3ubuntu4)
End-Date: 2026-10-22  09:00:02
`

func TestParse(t *testing.T) {

	got := Parse(history)
	if len(got) != 3 {
		t.Fatalf("transactions: %v", got)
	}
	if got[0].Actor != "unattended-upgrades" || strings.Join(got[0].Upgraded, ",") != "libpam-runtime 1.5.3-5ubuntu5.6" {
		t.Errorf("unattended: %+v", got[0])
	}
	if got[1].Actor != "jgomez" || strings.Join(got[1].Installed, ",") != "libpcap0.8t64 1.10.4-4.1ubuntu3,nmap 7.94+git20230807-3build2" {
		t.Errorf("requested: %+v", got[1])
	}
	if got[2].Actor != "root" || strings.Join(got[2].Removed, ",") != "telnet 0.17+2.5-3ubuntu4" || got[2].End == "" {
		t.Errorf("purge: %+v", got[2])
	}
}
