# Agent configuration

`/etc/oscompliance/agent.json` adapts the agent to a machine whose files are
not where a standard Linux system keeps them. The file is optional: without
it the agent uses the defaults, and with it only the keys present change.
An unknown key stops the agent with an error. The agent reads the file at
every run, so a change applies to the next pass without rebuilding or
restarting anything.

`agent.example.json` holds every key with its default value.

| Key | Default | Purpose |
|---|---|---|
| `output` | `/var/log/oscompliance/facts.ndjson` | File the facts are appended to; the Wazuh agent reads it |
| `host` | system host name | Host name written in every fact |
| `state` | `/var/lib/oscompliance/state.json` | What each collector last sent, to send only changes |
| `collectors` | every collector except `sweep` | Collectors of the hourly pass |
| `sweep_timeout` | `15m` | Time limit of the daily filesystem sweep |
| `paths.passwd` | `/etc/passwd` | Account database |
| `paths.shadow` | `/etc/shadow` | Password aging and locking |
| `paths.group` | `/etc/group` | Group database |
| `paths.sshd` | `/usr/sbin/sshd` | sshd binary, asked for its effective configuration |
| `paths.sudoers` | `/etc/sudoers` | Main sudoers file; its includes are followed |
| `paths.pam_dir` | `/etc/pam.d` | PAM configuration directory |

Collectors: `identity`, `groups`, `umask`, `sudoers`, `config`, `pam`,
`authprobe`, `listening`, `services`, `wazuh`, `acl`, `audit`, `firewall` and
`sweep`.

Flags:

| Flag | Purpose |
|---|---|
| `-config path` | Read another file; it must exist |
| `-collect a,b` | Run these collectors instead of the configured ones; the daily cron runs `-collect sweep` |
| `-full` | Send everything, even what did not change |
