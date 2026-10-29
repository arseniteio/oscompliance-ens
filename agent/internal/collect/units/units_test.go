package units

import (
	"strings"
	"testing"
)

func TestParse(t *testing.T) {
	out := "cron.service loaded active running Regular background program processing daemon\n" +
		"getty@tty1.service loaded active running Getty on tty1\n" +
		"ssh.service loaded active running OpenBSD Secure Shell server\n" +
		"session-3.scope loaded active running Session 3\n"
	if got := strings.Join(parse(out), ","); got != "cron.service,getty@tty1.service,ssh.service" {
		t.Errorf("units: %s", got)
	}
}
