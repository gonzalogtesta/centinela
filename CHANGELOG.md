# Changelog

## 1.1.0

Upgrading from 1.0: run `sudo centinela migrate` (it changes nothing without `--write`) and read "Upgrading from 1.0" in the README. The changes that can alter what you receive are marked **behaviour change**.

### Behaviour changes
- **Services are opt-in.** 1.0 assumed `fail2ban` was required and watched `nginx`, `docker` and `ssh` when the config did not say. 1.1 assumes nothing; choose with `sudo centinela setup`, or `sudo centinela migrate --write` to keep the old behaviour.
- **Disk alerts need two conditions**: a high percentage *and* little free space (20 GB / 10 GB or less), so a big, mostly empty disk stops alerting. `warn_free_gb = 0` and `crit_free_gb = 0` restore the old rule.
- **A safety guard checks every command before it runs.** A configured command that could change the machine is refused and reported as a warning instead of running.
- **Notification credentials are not passed to the commands Centinela runs.**
- **Messages may end with "N checks could not run: ..."** so a blind check cannot look healthy (`[general] coverage_line = false` turns it off).
- **The schedules watch each other**: a daily or weekly run that stopped completing is reported.
- **Two checks were split in two.** `firewall` is now `ufw` (is it active) and `fwrules` (the rules in force match what you approved); `docker` is now `docker` (containers) and `docker-images` (tags and rebuilds on Docker Hub, which needs the network and so is no longer part of the frequent timer). A config that names `firewall` or `docker` in `enable`, `disable` or `[notify.routes]` now needs the new names: `centinela migrate` shows them and `--write` adds `centinela.d/06-module-names.toml`, and until then a warning tells you. Settings keep their `[docker]` and `[firewall]` sections. The findings have new ids, so each problem that is still true is reported once more after the upgrade.

### New checks
- `memory` (percent *and* absolute free), `load` (per CPU), `oom` (a process killed by the kernel for lack of memory), `expect` (a command must print what you expect), and `fwrules`, which reports a change in the rules in force (`centinela firewall show|diff|approve`).

### Notifications
- Notifiers are modules: Telegram, ntfy and a generic webhook ship; write your own and put it in `/etc/centinela/notifiers.d/` or `[notify] modules`.
- `[notify.routes]` sends the findings of a check to its own channels, or all findings of a level (`level:crit`, `disk:warn`); `centinela --list-channels` shows each channel, its secrets and where findings go, and the wizard offers the routes when two channels can deliver. A failed route falls back to the default channels and only delivered findings are recorded as sent.
- A failed scheduled run sends one short notice (`OnFailure=`); an optional heartbeat URL and `centinela --status` show whether Centinela itself is running.

### Running it
- Optional 15 minute timer (`centinela --mode frequent`) for critical findings of the fast checks.
- Restricted install: its own account with one capability; Docker and ufw are read from their files when the socket is not available. `sudo centinela setup` now offers Full, Restricted or Advanced, shows what each costs per check, asks for the secrets with a hidden prompt, tries every check as the service would, and starts the timers. `centinela --coverage` lists which checks can run as the current user.

### Writing your own
- `centinela.testing` (`FakeCtx`, `FakeNotifier`), a module contract version (`CONTRACT = 1`), `[general] modules` to load files by path, helper imports next to a check, four tested examples (`centinela --print example-tcp-port | example-file-age | example-http-status | example-command-threshold`) and a multi-file one with its own unit test (`centinela --print example-package`, `example-package-test`).

### Testing
- `packaging/test/run.sh` runs the single file in Debian and Ubuntu containers (amd64 and arm64, with and without ufw) as root and as the restricted and advanced accounts. See "The container test matrix" in the README.
