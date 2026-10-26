package accounts

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/OpenSourceCompliance/oscompliance-ens/catalog/fact"
)

// fakeSSHD writes an executable that prints output as sshd -T would.
func fakeSSHD(t *testing.T, output string, exit int) string {
	t.Helper()

	path := filepath.Join(t.TempDir(), "sshd")
	script := "#!/bin/sh\ncat <<'END'\n" + output + "END\nexit " + string(rune('0'+exit)) + "\n"
	if err := os.WriteFile(path, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	return path
}

func writeFile(t *testing.T, path, content string, mode os.FileMode) {
	t.Helper()

	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), mode); err != nil {
		t.Fatal(err)
	}
}

func TestReadSSHD(t *testing.T) {
	read := readSSHD(fakeSSHD(t, "port 22\nauthorizedkeysfile .ssh/authorized_keys /etc/ssh/keys/%u\nauthorizedkeyscommand none\n", 0))
	if read.status != fact.SSHDRead || len(read.files) != 2 || read.files[1] != "/etc/ssh/keys/%u" {
		t.Errorf("read: %+v", read)
	}

	if got := readSSHD(fakeSSHD(t, "authorizedkeyscommand /usr/bin/sss_ssh_authorizedkeys\n", 0)); got.status != fact.SSHDCommand {
		t.Errorf("command: %+v", got)
	}

	if got := readSSHD(fakeSSHD(t, "", 1)); got.status != fact.SSHDError || got.err == "" {
		t.Errorf("error: %+v", got)
	}

	if got := readSSHD(filepath.Join(t.TempDir(), "missing")); got.status != fact.SSHDAbsent {
		t.Errorf("absent: %+v", got)
	}
}

func TestCountKeys(t *testing.T) {
	home := t.TempDir()
	entry := passwdEntry{user: "ana", uid: 1500, home: home}

	writeFile(t, filepath.Join(home, ".ssh/authorized_keys"), "# comment\n\nssh-ed25519 AAAA ana@x\nssh-rsa BBBB ana@y\n", 0o600)
	central := filepath.Join(t.TempDir(), "keys")
	writeFile(t, filepath.Join(central, "ana"), "ssh-ed25519 CCCC\n", 0o600)

	sshd := fakeSSHD(t, "authorizedkeysfile .ssh/authorized_keys .ssh/authorized_keys2 "+central+"/%u none\n", 0)
	keys := sshdKeys{status: fact.SSHDRead, path: sshd}

	if got := keys.count(entry); got == nil || *got != 3 {
		t.Errorf("2 in home + 0 missing + 1 central: got %v", got)
	}

	if got := (sshdKeys{status: fact.SSHDAbsent}).count(entry); got == nil || *got != 0 {
		t.Errorf("no sshd: want 0, got %v", got)
	}
	for _, status := range []string{fact.SSHDCommand, fact.SSHDError} {
		if got := (sshdKeys{status: status}).count(entry); got != nil {
			t.Errorf("%s: want unknown, got %d", status, *got)
		}
	}

	// sshd itself fails for this account: unknown.
	if got := (sshdKeys{status: fact.SSHDRead, path: fakeSSHD(t, "", 1)}).count(entry); got != nil {
		t.Errorf("sshd -T -C failed: want unknown, got %d", *got)
	}

	// A key file that exists but cannot be read: unknown, never 0.
	if os.Geteuid() != 0 {
		locked := filepath.Join(home, ".ssh/authorized_keys2")
		writeFile(t, locked, "ssh-ed25519 DDDD\n", 0o000)
		if got := keys.count(entry); got != nil {
			t.Errorf("unreadable key file: want unknown, got %d", *got)
		}
	}
}

func TestKeyFilePath(t *testing.T) {
	entry := passwdEntry{user: "ana", uid: 1500, home: "/home/ana"}

	cases := map[string]string{
		".ssh/authorized_keys": "/home/ana/.ssh/authorized_keys",
		"%h/.ssh/keys":         "/home/ana/.ssh/keys",
		"/etc/ssh/keys/%u":     "/etc/ssh/keys/ana",
		"/etc/ssh/keys/%U":     "/etc/ssh/keys/1500",
		"/etc/ssh/%%u/%u":      "/etc/ssh/%u/ana",
	}

	for pattern, want := range cases {
		if got := keyFilePath(pattern, entry); got != want {
			t.Errorf("%s: got %s, want %s", pattern, got, want)
		}
	}
}

// Match blocks: sshd -T -C user=... gives one account its own files or a
// command; the agent must follow it, not the global setting.
func TestCountKeysFollowsMatch(t *testing.T) {
	home := t.TempDir()

	// A configuration with Match blocks: sshd is asked per account.
	config := filepath.Join(t.TempDir(), "sshd_config")
	writeFile(t, config, "Match User git\n", 0o600)
	saved := sshdConfigs
	sshdConfigs = []string{config}
	defer func() { sshdConfigs = saved }()
	writeFile(t, filepath.Join(home, ".ssh/authorized_keys"), "ssh-ed25519 AAAA\n", 0o600)
	writeFile(t, filepath.Join(home, "git-keys"), "ssh-ed25519 B\nssh-ed25519 C\n", 0o600)

	path := filepath.Join(t.TempDir(), "sshd")
	script := `#!/bin/sh
case "$*" in
  *user=git,*) echo "authorizedkeysfile %h/git-keys" ;;
  *user=ldap,*) echo "authorizedkeyscommand /usr/bin/fetch-keys" ;;
  *) echo "authorizedkeysfile .ssh/authorized_keys" ;;
esac
`
	if err := os.WriteFile(path, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}

	keys := readSSHD(path)

	cases := map[string]*int{"ana": intp(1), "git": intp(2), "ldap": nil}
	for user, want := range cases {
		got := keys.count(passwdEntry{user: user, uid: 1500, home: home})
		if (got == nil) != (want == nil) || (got != nil && *got != *want) {
			t.Errorf("%s: got %v, want %v", user, deref(got), deref(want))
		}
	}
}

func intp(n int) *int { return &n }

func deref(p *int) any {
	if p == nil {
		return "unknown"
	}
	return *p
}

func TestHasMatch(t *testing.T) {

	dir := t.TempDir()
	plain := filepath.Join(dir, "plain")
	match := filepath.Join(dir, "match")
	if err := os.WriteFile(plain, []byte("PasswordAuthentication no\n# Match User x\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(match, []byte("Port 22\n  match Group sftp\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	if hasMatch([]string{plain}) || !hasMatch([]string{plain, match}) {
		t.Error("Match detection")
	}
}
