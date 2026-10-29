package updates

import "testing"

func TestCount(t *testing.T) {
	out := `Reading package lists...
Inst libpam-runtime [1.5.3-5ubuntu5.5] (1.5.3-5ubuntu5.6 Ubuntu:24.04/noble-updates, Ubuntu:24.04/noble-security [all])
Inst tzdata [2024a-3ubuntu1] (2025b-0ubuntu0.24.04 Ubuntu:24.04/noble-updates [all])
Conf libpam-runtime (1.5.3-5ubuntu5.6 Ubuntu:24.04/noble-updates, Ubuntu:24.04/noble-security [all])
`
	if p, s := count(out); p != 2 || s != 1 {
		t.Errorf("pending %d security %d", p, s)
	}
}
