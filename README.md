<p align="center">
  <img src="docs/logo.jpg" alt="Centinela: a neon ASCII-art sentinel holding a spear and shield" width="300">
</p>

# Centinela

**A quiet, read-only watchdog for your servers. It messages you on Telegram only when something needs action: one line per problem, each with the command to run.**

```
node-1 (10.0.0.5): 3 need action (1 critical)
[CRIT] certificate example.com EXPIRED (2025-10-14) | run: sudo certbot renew --cert-name example.com
[WARN] disk / is 86% full | run: sudo du -xh --max-depth=1 / | sort -rh | head -15
[WARN] reboot required (linux-image-6.1.0-56-amd64) | run: sudo systemctl reboot
```

When everything is fine, it sends nothing at all.

Use it on a VPS, a Raspberry Pi, a Mac mini that quietly processes jobs, or a small cluster of them. It is a single Python file with no dependencies.

- [Why Centinela](#why-centinela)
- [Where it runs](#where-it-runs)
- [Quick start](#quick-start)
- [What it checks](#what-it-checks)
- [Expectations](#expectations)
- [Add your own checks](#add-your-own-checks)
- [Several machines](#several-machines)
- [How it works](#how-it-works)
- [Scheduling](#scheduling)
- [Installation options](#installation-options)
- [Notifications](#notifications)
- [Heartbeat](#heartbeat-is-it-still-running)
- [The setup wizard](#the-setup-wizard)
- [Trust lists and freezing](#trust-lists-and-freezing)
- [Configuration reference](#configuration-reference)
- [Security model](#security-model)
- [Troubleshooting](#troubleshooting)
- [Development and contributing](#development-and-contributing)
- [Roadmap](#roadmap)

## Why Centinela

Small machines usually have no monitoring until something breaks: a certificate expires, a job silently stops, a disk fills up, a Pi throttles because of a weak power supply, a container nobody started is running. Full monitoring stacks are heavy for that, and tools that mail you everything drown you in noise.

Centinela is built around a few rules:

- **Silent when healthy.** No daily "all OK" message. A message means there is something to do.
- **Every finding is actionable.** One line: what is wrong, and the exact command to run.
- **Read-only.** The checks never install, restart or edit anything. Commands in a message are suggestions for you to run.
- **No repeats.** The same finding is sent at most once every 7 days. It is sent again at once if it gets worse, or if it resolves and later comes back.
- **No dependencies.** One Python 3.11+ standard-library program. Nothing from pip, nothing to compile.
- **Modular.** Every check is a module you can turn off per machine, or replace with your own in a few lines of Python.
- **You define what is expected.** Lists of images, services and ports you approve, and an optional freeze: anything new that appears later is reported.

## Where it runs

Centinela runs anywhere Python 3.11 or newer runs. The core (findings, deduplication, Telegram, configuration, your own checks) is platform-independent. The **built-in checks** are mostly written for Linux, so what you get out of the box depends on the machine:

| Machine | Built-in checks that apply today | Status |
|---|---|---|
| **Debian-family Linux with systemd** (Debian, Raspberry Pi OS) | All of them | Tested on Debian 12 |
| **Other Linux with systemd** (Ubuntu, Fedora, Arch, ...) | Everything except the Debian-specific `apt` and `cve`, and `firewall` unless you use ufw | Expected to work, untested |
| **macOS** | `disk`, `memory`, `load` and `docker`, plus `nginx` and `certbot` if those are installed | Core and custom checks work; the other built-ins do not apply yet |
| **Windows** | none | Not supported |

**Run `centinela --list-modules` on a new machine.** Every module marked `n/a` does not apply there, and if all of them are `n/a`, Centinela has nothing to check and will say so. Silence is not health. On such machines, [write a few custom checks](#add-your-own-checks) (is my job running, is this URL up, is the Pi overheating): that takes minutes, and recipes are below. More portable built-in checks are on the [roadmap](#roadmap).

Centinela is young (version 1.0). The parsers are covered by unit tests built on fixtures modelled on real command output; a few formats, `debsecan` in particular, were written from the tools' documentation and need confirmation on more machines. The Debian package is tested with Debian 12's own `dpkg`. Reports from other systems are very welcome.

It is a convenience watchdog, **not** an intrusion detection system or a vulnerability scanner. See [Security model](#security-model).

## Quick start

You need Python 3.11+, a notification channel such as a Telegram bot ([setup](#notifications)), and the `centinela` file from the [Releases page](https://github.com/gonzalogtesta/centinela/releases).

**As root on a Linux server** (system-wide config, timers):

```bash
sha256sum -c --ignore-missing SHA256SUMS
sudo install -m 755 -o root -g root centinela /usr/local/bin/centinela
sudo install -d -m 755 /etc/centinela/checks.d
centinela --print config | sudo tee /etc/centinela/centinela.toml >/dev/null

sudo install -d -m 700 /etc/sec
sudo install -m 600 /dev/null /etc/sec/notify.env
sudoedit /etc/sec/notify.env        # TELEGRAM_BOT_TOKEN=...  and  TELEGRAM_CHAT_ID=...

sudo centinela --list-modules        # which checks apply here
sudo centinela --dry-run             # what would be sent right now (sends nothing)
sudo centinela --test                # sends a clearly marked demo message
```

Then schedule it: [systemd timers](#scheduling) on Linux. On Debian-family systems the `.deb` does the install steps and adds the timers (see [Installation options](#installation-options)).

**As your own user** (a Mac mini, or any machine where you do not want root), everything lives in your home directory:

```bash
mkdir -p ~/.config/centinela ~/.local/state/centinela
centinela --print config > ~/.config/centinela/centinela.toml
install -m 600 /dev/null ~/.config/centinela/notify.env      # then add the two Telegram lines
```

In `~/.config/centinela/centinela.toml`, point Centinela at those files with full paths (`~` and `$HOME` are not expanded):

```toml
[general]
state_file = "/Users/you/.local/state/centinela/state.json"
[notify]
env_file = "/Users/you/.config/centinela/notify.env"
```

```bash
export CENTINELA_CONF=~/.config/centinela/centinela.toml
centinela --list-modules && centinela --dry-run && centinela --test
```

Then schedule it with [cron or launchd](#scheduling).

## What it checks

Each check is a module. By default every module that applies to the machine runs: if nginx is not installed, the nginx module quietly does nothing.

| Module | What it looks at | Needs | Critical when |
|---|---|---|---|
| `apt` | Upgradable packages (nginx, docker, openssh, kernel called out), stale package index, reboot-required | Debian-family `apt` | An update comes from a `-security` suite |
| `restart` | Services still running a binary or library that an upgrade replaced | Linux (`needrestart` optional) | Never (warning) |
| `nginx` | Installed version against the [nginx.org security advisories](https://nginx.org/en/security_advisories.html); behind the latest release of its track | `nginx` installed | An advisory rated major or critical affects your version |
| `docker` | Containers not running or unhealthy; images behind the newest tag of the same major on Docker Hub; base image of your own images; containers running images you did not approve | `docker` CLI | A container is down, unhealthy or untrusted, or the daemon is down |
| `certbot` | Let's Encrypt certificates in `/etc/letsencrypt/live` expiring in under 21 days | That directory and `openssl` | Under 7 days, or expired |
| `disk` | Space above 80% **and** little left; inodes above 80% (Linux) | Linux (GNU `df`) or macOS | 90% used and 10 GB or less left |
| `memory` | Memory used above 90% **and** little left; heavy swap use (Linux) | Linux, or macOS (`memory_pressure`) | 95% used and under 512 MB available |
| `load` | Load average per CPU (the last 15 minutes) | Linux or macOS | 2 or more per CPU |
| `oom` | A process killed by the kernel for lack of memory in the last 7 days | Linux, with access to the kernel log | Any kill |
| `units` | Failed systemd units | systemd | Never (warning) |
| `services` | Required and watched services are active; optionally anything new that starts running. Off until you list services | systemd | A required or watched service is down |
| `firewall` | `ufw status` is active; once you approve them, the rules in force are the ones you approved | `ufw`, or `nft` / `iptables-save` for the rules | ufw is inactive, or the live rules differ from the approved set |
| `ports` | Listening TCP/UDP ports against your approved list (off until you set a list) | Linux (`ss`) | A new listener open on all interfaces, an expected port gone, or an approved loopback-only port now exposed |
| `cve` | `debsecan`: high-urgency CVEs in installed Debian packages that already have a fix | `debsecan` | Remotely exploitable |
| `expect` | Your own expectations: a command whose output must look the way you say (off until you write a rule) | whatever the command needs | Rules you mark `level = "crit"` |

Notes:

- **disk** needs both a high percentage and little space actually left, because 90% of a 20 GB disk is 2 GB and 90% of a 4 TB disk is 400 GB. By default a warning needs 80% used and 20 GB or less free, and a critical needs 90% and 10 GB or less. A disk that is 94% full with 50 GB free is not reported. The message says how much is left. Set a `*_free_gb` value to `0` to judge by the percentage alone, as 1.0 did. Inodes (Linux only, macOS has no fixed inode limit) are judged by the percentage alone. On macOS it checks local volumes and, unless you set `ignore_mounts`, skips the system helper volumes (`Preboot`, `VM`, `Update`), simulator disk images and Time Machine snapshots, which are full or irrelevant by design.
- **oom** reports each process the kernel killed for lack of memory, once per process name (a count and the last time are in the line), with the `journalctl` command that shows the kernel's own account. The memory check sees pressure only at the moment it runs; this is the proof it already happened. It reads `journalctl -k` and falls back to `dmesg -T`; as the restricted user, add `SupplementaryGroups=systemd-journal adm` (or run as root). Without access the check says it could not run, in the coverage line, instead of looking healthy.
- **memory** needs both a high percentage and little memory actually available, because 90% used is about 200 MB left on a 2 GB machine and about 6 GB on a 64 GB one. By default a warning needs 90% used and 1 GB or less available, and a critical needs 95% and 512 MB or less. "Available" leaves out the file cache the system gives back when asked (Linux `MemAvailable`); on macOS it is the free percentage that `memory_pressure` reports, the system's own measure. Swap is reported on Linux only, when it is both mostly full (80%) and large (512 MB). Set a `*_free_mb` value to `0` to judge by the percentage alone.
- **load** uses the load average per CPU, not a CPU percentage. Centinela runs now and then, so a percentage at that instant would mean little, while the load average already covers the last 15 minutes. About 1.0 per CPU means every CPU is kept busy; the defaults warn at 1.0 and go critical at 2.0. On Linux the load also counts processes waiting for the disk, so heavy disk use raises it. In a container it counts the host's CPUs.
- **certbot** reads the certificate files with `openssl`, so it never takes certbot's lock. It checks the certificate stored on the machine itself. If a proxy or CDN terminates TLS in front of it, the certificate your visitors see is the proxy's, and certificates stored elsewhere (for example an origin certificate under another directory) are not checked.
- **docker** compares only Docker Hub images. The base image of your own image is found automatically when possible: from the `org.opencontainers.image.base.name` label, or by finding a Docker Hub image on the machine whose layers are the first layers of yours. That is a heuristic and needs the base image still present locally; otherwise list it with `extra_images` or `dockerfiles`. Wildcards work too: `watch_images = ["python:3.12*"]` is resolved with `docker image ls`, keeping only the newest local tag per repository and variant so rotating deploys do not pile up findings.
- **nginx** reads the advisory list from the HTML page on nginx.org. If that page changes format, the check reports nothing rather than guessing.
- **cve** covers Debian-packaged software only.
- **apt** never runs `apt-get update`. It reads the existing cache and warns if the cache is older than 7 days.

### Firewall rules: did one change?

`ufw status` and ufw's files say what ufw meant to load. The rules the kernel enforces live in memory, and anything with root can add or remove one (`iptables -A`, `nft add rule`) without touching those files. To be told when the rules in force change, approve them once:

```bash
sudo centinela firewall show       # what will be compared; read it
sudo centinela firewall approve    # save it as the approved set
```

From then on, every run reads the live rules (`nft list ruleset`, or `iptables-save` and `ip6tables-save` if nft is not there) and compares them with the approved copy. A difference is critical, with the first changed lines in the message, for example `firewall rules differ from the approved set (+1 -0 lines): + tcp dport 4444 accept`. Then:

```bash
sudo centinela firewall diff       # every changed line
sudo centinela firewall approve    # if the change is yours (a new ufw rule, say)
```

A ruleset that differs is reported once, and again only if it changes to something else. Nothing is compared until you approve, and deleting `firewall.rules` from the state directory turns it off.

What is left out, because it changes by itself: packet counters, set timeouts, comments, and the chains of Docker, fail2ban, Kubernetes, Calico, Cilium, flannel and libvirt, plus rules that name `docker0`, a `br-` bridge or a `veth`. Change that with `[firewall] ignore_chains` and `ignore_lines` (a setting replaces the default list). The consequence to know: a port a container publishes is not seen here (the [docker](#what-it-checks) check watches the containers themselves), and neither is anything inside those chains.

Reading the live rules needs root or `CAP_NET_ADMIN`. If you approved rules and Centinela later cannot read them (for example a restricted install without the capability), it reports `approved firewall rules cannot be read now` instead of staying quiet. It is a periodic snapshot: a rule added and removed between two runs is invisible. The unit allows netlink sockets for this; a single-file install must reprint the unit (`centinela --print service`).

## Expectations

The `expect` module checks that a command gives the answer you want. Write one table per rule in `centinela.toml` or a drop-in file. It does nothing until a rule exists.

```toml
[expect.ssh_root]
run = "sshd -T"
line = "permitrootlogin no"
text = "SSH root login must be off"
level = "crit"

[expect.ip_forward]
run = "sysctl -n net.ipv4.ip_forward"
equals = "0"

[expect.backup_timer]
run = "systemctl is-active backup.timer"      # no matcher: the command must exit 0
```

| Setting | Meaning |
|---|---|
| `run` | The command, as a string or a list. It is not run through a shell, so pipes and `*` do not work: use `regex` or `contains` on the whole output instead |
| `line` | Some line of the output is exactly this (after trimming) |
| `equals` | The whole output is exactly this (after trimming) |
| `contains`, `not_contains` | The output has, or does not have, this text |
| `regex` | The output matches this regular expression (multi-line, searched anywhere) |
| `exit` | Expected exit code (default `0`) |
| `level` | `warn` (default) or `crit` |
| `text` | Name shown in the message (default: the rule name) |
| `fix` | Command shown as the thing to run (default: the `run` command, so you can see the difference) |
| `timeout` | Seconds before giving up (default 30) |
| `allow_dangerous` | `true` lets this rule run a command the safety guard refuses (see below) |

### The safety guard

Centinela must not change your server, so the commands in your config are checked **before** they run. A command that is known to write, delete, restart or install is refused, and the rule is reported as a finding that says why:

```
[expect.clean] refused: rm can change or delete data. If you are sure, set allow_dangerous = true on the rule
```

What it refuses:

- commands that change data or the system: `rm`, `mv`, `cp`, `dd`, `chmod`, `chown`, `kill`, `reboot`, `mkfs*`, user and cron management, and similar
- the write verbs of tools that also read: `systemctl restart`, `docker rm` / `run` / `prune`, `apt install`, `dpkg -i`, `ip addr add`, `iptables -A`, `sysctl -w`, `nginx -s`, `journalctl --vacuum`. For `systemctl`, `docker`, `apt`, `ufw` and a few others only a short list of read-only verbs is allowed
- options that make a read command write: `find -delete` / `-exec`, `sed -i`, `curl -o`, `openssl -out`, `tar x`, `wget` (except `--spider`)
- wrappers are looked through, so `sudo rm`, `env X=1 mv` and `timeout 5 xargs rm` are refused too
- code that cannot be inspected: `bash -c "..."`, `python3 -c "..."`, `perl -e`, `awk` with an inline program
- scripts: when the command is a script (or an interpreter given one), its text is read first. It is refused if anyone but the owner can write to it (it could be swapped after you reviewed it), or if it uses a destructive command such as `rm`, `mv`, `dd`, `kill`, `rmtree` or `unlink`. Comment lines are ignored

To allow one command you have checked, set `allow_dangerous = true` on that rule. `[general] allow_dangerous_commands = true` allows everything and is not recommended. The guard also protects your own Python checks when they use `ctx.run`.

**Know its limits.** It is a safety net against mistakes such as a copied snippet, not a security boundary. It recognises known commands and reads scripts for known words, but it cannot understand an arbitrary program: a compiled binary, a script that builds a command at run time, or a command it has never heard of is allowed. A Python check that calls `subprocess` itself skips the guard. What actually enforces "read-only" on Linux is the systemd sandbox (read-only filesystem, no new privileges), and everything in the config is trusted input: keep it, and the scripts it points to, owned by root and not writable by others.

Several matchers in one rule must all hold. The message says what was expected, never what the command printed, so output that contains a secret does not reach your phone. A command that is missing, times out or exits with the wrong code is reported too, and a rule with a typo (a missing `run`, an unknown setting, an invalid regex) becomes a finding that names the rule. Commands that need root, like `sshd -T`, are skipped by Centinela's other checks without root and reported here as an unexpected exit code, so run it as root for those rules.

## Add your own checks

A custom check is a small Python file in a directory Centinela loads (`/etc/centinela/checks.d/` by default, or `extra_dir` in the config). This is how you cover anything the built-ins do not, on any machine. Below are four recipes. Each one stays silent until you configure it.

```bash
mkdir -p ~/.config/centinela/checks.d      # as your own user; /etc/centinela/checks.d as root
```

Set `extra_dir = "/full/path/to/checks.d"` under `[general]` if you are not using the default.

### A job or process must be running

`checks.d/jobs.py`, configured with `[jobs] must_run = ["process_images.py", "worker"]`. Each entry is matched against the full command line, so use a distinctive part of it:

```python
import shlex

from centinela.core import CRIT, Finding, Skip

NAME = "jobs"
DESC = "processes that must be running"


def applicable(cfg):
    return bool(cfg.list("jobs", "must_run"))


def run(ctx):
    findings = []
    for pattern in ctx.cfg.list("jobs", "must_run"):
        rc, _, _ = ctx.run(["pgrep", "-f", pattern])
        if rc == 127:
            raise Skip("pgrep is not installed")
        if rc != 0:
            findings.append(Finding(NAME, pattern, CRIT, "no process matching '%s' is running" % pattern,
                                    "ps aux | grep %s" % shlex.quote(pattern)))
    return findings
```

### A URL must answer

`checks.d/urls.py`, configured with `[urls] check = ["http://127.0.0.1:8000/health", "https://example.com"]`. Any error, including an HTTP error status, is a finding:

```python
import shlex

from centinela.core import CRIT, Finding, Skip

NAME = "urls"
DESC = "URLs that must answer"


def applicable(cfg):
    return bool(cfg.list("urls", "check"))


def run(ctx):
    findings = []
    for url in ctx.cfg.list("urls", "check"):
        try:
            ctx.http_get(url, 10)
        except Skip as exc:
            findings.append(Finding(NAME, url, CRIT, "%s is not answering (%s)" % (url, exc),
                                    "curl -sS -i %s" % shlex.quote(url)))
    return findings
```

### Raspberry Pi: temperature, throttling and weak power

`checks.d/pi.py`, optionally configured with `[pi] max_temp_c = 80`. Throttling and under-voltage are the classic silent Pi problems:

```python
from centinela.core import WARN, Finding

NAME = "pi"
DESC = "Raspberry Pi temperature, throttling and under-voltage"
THERMAL = "/sys/class/thermal/thermal_zone0/temp"


def applicable(cfg):
    import os
    return os.path.exists(cfg.get("pi", "thermal_file", THERMAL))


def run(ctx):
    findings = []
    with open(ctx.cfg.get("pi", "thermal_file", THERMAL)) as fh:
        celsius = int(fh.read().strip()) / 1000
    if celsius >= ctx.cfg.int("pi", "max_temp_c", 80):
        findings.append(Finding(NAME, "hot", WARN, "CPU temperature is %.0f C" % celsius,
                                "vcgencmd measure_temp"))
    rc, out, _ = ctx.run(["vcgencmd", "get_throttled"])
    if rc == 0 and "=" in out:
        flags = int(out.split("=", 1)[1].strip(), 16)
        if flags & 0xF:  # under-voltage, frequency capped, throttled or soft temperature limit, right now
            findings.append(Finding(NAME, "throttled", WARN,
                                    "throttling or under-voltage right now (get_throttled=0x%x): check the power supply" % flags,
                                    "vcgencmd get_throttled"))
    return findings
```

### Shipped examples

Four small, tested checks ship with Centinela. Print one, copy it into your checks directory and change it. Each stays silent until you configure it.

| Print with | Config | Reports |
|---|---|---|
| `centinela --print example-tcp-port` | `[tcp_port] targets = ["127.0.0.1:6379", "node2.local:22"]` | a host:port that does not accept TCP connections (see [Several machines](#several-machines)) |
| `centinela --print example-file-age` | `[file_age] files = ["/var/backups/db.sql.gz:26h"]` | a file (backup, log, heartbeat) not updated within its limit |
| `centinela --print example-http-status` | `[http_status] urls = [...]`, optional `must_contain` | a URL that is down, returns an error status or lacks the expected text |
| `centinela --print example-command-threshold` | `[failed_units] max = 0` | a number printed by a read-only command above a limit; copy it to watch anything a command can count |

`example-check` is the older name of `example-tcp-port`.

### The rules for a check

```python
from centinela.core import CRIT, WARN, Finding, Skip   # Skip: "cannot run right now", logged, never sent

NAME = "myapp"          # used in enable/disable lists; same NAME as a built-in replaces it
DESC = "what it checks" # shown by --list-modules

def applicable(cfg):    # optional: False = silently not for this machine
    return True

def run(ctx):           # return a list of Finding(module, id, level, text, cmd)
    ...
```

- `id` must stay the same for the same problem from run to run (it drives deduplication). `level` is `CRIT` or `WARN`. `cmd` is the command you want in the message.
- `ctx.run([...])` runs a command and returns `(returncode, stdout, stderr)` (127 if it is not installed); `ctx.http_get(url, timeout)` fetches a URL; `ctx.cfg.list/get/int/bool(section, key, default)` reads your configuration.
- Quote anything you put in `cmd` with `shlex.quote`.
- A check that raises an unexpected error becomes a finding of its own; a check that raises `Skip` is logged only.
- Test a check without a machine: `from centinela.testing import FakeCtx`, then `FakeCtx(config_text, cmds={"systemctl": (0, "output")}, urls={"/health": "ok"})` gives your `run()` a context that answers from those tables, still through the safety guard. The shipped examples are tested this way (see `tests/`).
- A module may declare `CONTRACT = 1`, the interface version it was written for. A Centinela that offers an older version ignores the module and says why on stderr, instead of running it wrongly. A module without `CONTRACT` is taken as version 1.
- `FREQUENT = True` lets the check run on the optional [frequent timer](#within-minutes-the-frequent-timer-optional); set it only when the check is quick and needs no network.
- A check can be split into helpers: the directory it is loaded from is on the import path while it loads, so `import mylib` finds `mylib.py` next to it.
- Checks outside the drop-in directory: `[general] modules = ["/opt/mychecks/redis.py"]` loads those files too, under the same ownership rules. A file without `NAME` or `run(ctx)`, or one that fails to load, is ignored with a reason on stderr; it never stops the others.
- Custom checks run with Centinela's privileges. When Centinela runs as root, it refuses to load the directory or any file in it unless they are owned by root and not group- or world-writable.

## Several machines

Install Centinela on each machine and point them all at the same Telegram chat. Every message starts with the machine's name, so you can tell them apart:

```toml
[general]
host_name = "pi-3"                 # set per machine (e.g. in centinela.d/20-local.toml)
[notify]
show = ["host", "ip"]              # header: pi-3 (192.168.1.13): 2 need action
```

That covers "something is failing on a node". A node that is **completely down sends nothing**, because it is not running to tell you. Today there are two partial answers:

- Let one or two machines probe the others with the `tcp_port` example, using each node's SSH port as the target: `targets = ["pi-1.local:22", "pi-2.local:22", "pi-3.local:22"]`. A dead or unplugged node then shows up as critical on the probing machine. Probe in both directions, or from a machine you trust to stay up, so the prober itself is not a single point of failure.
- Use the [heartbeat](#heartbeat-is-it-still-running): each machine pings a service that alerts you when the pings stop. A combined view of all nodes is still on the roadmap.

Copy the same `centinela.toml` to every node and keep per-node differences (like `host_name`) in a drop-in file, which is merged over it.

## How it works

```
  scheduler                               ┌───────────────────────────────┐
  daily  (critical only)  ──┐             │  checks (one file each)       │
  weekly (everything)     ──┴───────────► │  disk  docker  nginx  yours…  │
                                          └──────────────┬────────────────┘
                                                         ▼ findings (module, id, level, text, command)
                                          ┌───────────────────────────────┐
                                          │ cap per module, then dedupe   │◄── state.json (what was sent, when)
                                          └──────────────┬────────────────┘
                                                         ▼
                                             one Telegram message (or nothing)
```

- **Two runs.** The daily run sends only critical findings; the weekly run sends everything. They share state and a lock, so a critical finding sent in the morning is not repeated by the weekly run.
- **Findings** have a severity (`CRIT` or `WARN`), a stable id, a one-line text and the command to run. Severity is defined per check, not guessed.
- **Deduplication.** Findings are remembered in the state file (mode 600) for 7 days (`dedupe_days`), with 12 hours of slack so a weekly schedule that fires a few minutes early still re-sends a persisting finding. A finding that resolves is forgotten, so if it comes back it is sent at once. A finding that escalates from WARN to CRIT is sent at once. State is written only after Telegram accepts the message, so a failed send is retried on the next run.
- **Noise control.** More than 8 findings of one kind from one module (`max_per_module`, for example 150 stopped containers) collapse into a "+N more" line. Other kinds from the same module, such as an unexpected image, are never hidden by it.
- **Failures are visible.** A check that crashes becomes its own finding. A check that cannot run (offline, not root) is logged to stderr only. If Telegram delivery fails, the run exits non-zero, so a scheduler or systemd shows it as failed.

Exit codes: `0` nothing to report, or sent; `1` Telegram delivery failed; `2` configuration, state or usage error (including invalid TOML).

## Scheduling

Centinela runs once and exits; something has to start it. A common pattern is a daily run at 07:30 (critical only) and a weekly run on Monday at 08:00 (everything).

### systemd timers (Linux)

The unit and timers are bundled in the executable, and the `.deb` installs them. For the single-file install:

```bash
centinela --print service      | sudo tee /etc/systemd/system/centinela@.service >/dev/null
centinela --print failure-service | sudo tee /etc/systemd/system/centinela-failure@.service >/dev/null
centinela --print daily-timer  | sudo tee /etc/systemd/system/centinela-daily.timer >/dev/null
centinela --print weekly-timer | sudo tee /etc/systemd/system/centinela-weekly.timer >/dev/null
sudo systemctl daemon-reload
sudo systemctl enable --now centinela-daily.timer centinela-weekly.timer
systemctl list-timers 'centinela*'
```

The bundled unit calls `/usr/local/bin/centinela` and runs sandboxed: the filesystem is read-only to it except its own state directory. If a run itself fails (a crash, the 10 minute timeout, or no channel could be reached), `OnFailure=` starts `centinela-failure@.service`, which sends one short message through every configured channel: "the scheduled daily run of centinela failed", with the `journalctl` command to read. The same failure is not repeated for 7 days, and a later run that completes lets the next failure through at once. If every channel is down, nothing can be sent: the failed unit (`systemctl --failed`) and the journal are the only trace, which is what the [heartbeat](#heartbeat-is-it-still-running) from outside the machine is for. launchd and cron have no `OnFailure=`; there, check the exit code of the job. To run it once now: `sudo systemctl start centinela@weekly.service`, then `journalctl -u 'centinela@*' -n 30 --no-pager`.

### Within minutes: the frequent timer (optional)

A daily run tells you at 07:30. If a critical problem should reach you within minutes (a container down, a full disk, a changed firewall rule), enable a third timer. It is off by default:

```bash
centinela --print frequent-timer | sudo tee /etc/systemd/system/centinela-frequent.timer >/dev/null
sudo systemctl daemon-reload
sudo systemctl enable --now centinela-frequent.timer      # the .deb already installed the file
```

It runs `centinela --mode frequent` every 15 minutes: critical findings only, and only the checks that are cheap and local (`disk`, `memory`, `load`, `services`, `units`, `firewall`, `docker` without the Docker Hub lookup, `ports`, `expect`). Slow ones (`apt`, `cve`, `nginx`, `certbot`, anything that uses the network) keep to the daily and weekly runs; `centinela --mode frequent --list-modules` shows which is which as `run` or `slow`. It shares the dedupe state with the other runs, so a problem is sent once, not every 15 minutes. A check of your own joins by setting `FREQUENT = True` in its file; do that only if it is quick and needs no network. To follow it, `centinela --status` lists the frequent run once it has run, and the other schedules report it as late after 2 hours (`[heartbeat] stale_frequent_minutes`); remove it from `[heartbeat] watch` if you stop using the timer.

### cron (any Unix)

Cron has a minimal `PATH`, so use full paths, and make sure the `python3` it finds is 3.11 or newer (otherwise call `python3.12 /usr/local/bin/centinela ...`). In `crontab -e`:

```
30 7 * * * CENTINELA_CONF=$HOME/.config/centinela/centinela.toml /usr/local/bin/centinela --mode daily
0 8 * * 1  CENTINELA_CONF=$HOME/.config/centinela/centinela.toml /usr/local/bin/centinela --mode weekly
```

### launchd (macOS)

Save as `~/Library/LaunchAgents/dev.centinela.weekly.plist`, adjusting the paths (a second file with `--mode daily` and `Hour` 7, `Minute` 30 for the daily run). launchd does not use your shell's `PATH`, so give the Python 3.11+ interpreter explicitly:

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key><string>dev.centinela.weekly</string>
  <key>ProgramArguments</key>
  <array>
    <string>/opt/homebrew/bin/python3</string>
    <string>/usr/local/bin/centinela</string>
    <string>--mode</string><string>weekly</string>
  </array>
  <key>EnvironmentVariables</key>
  <dict><key>CENTINELA_CONF</key><string>/Users/you/.config/centinela/centinela.toml</string></dict>
  <key>StartCalendarInterval</key>
  <dict><key>Weekday</key><integer>1</integer><key>Hour</key><integer>8</integer><key>Minute</key><integer>0</integer></dict>
</dict>
</plist>
```

Load it with `launchctl load ~/Library/LaunchAgents/dev.centinela.weekly.plist`. This example has been syntax-checked with `plutil -lint` but not run through launchd yet; please report if it needs changes.

## Installation options

Requirements: **Python 3.11+**. Optional helpers on Debian-family systems: `needrestart` and `debsecan` for better restart and CVE checks.

### The single file (any system)

The `centinela` file attached to a [release](https://github.com/gonzalogtesta/centinela/releases) is the whole program. See [Quick start](#quick-start). Verify the download first:

```bash
sha256sum -c --ignore-missing SHA256SUMS     # on macOS: shasum -a 256 -c SHA256SUMS
```

### The `.deb` (Debian-family)

```bash
sha256sum -c --ignore-missing SHA256SUMS
sudo apt install ./centinela_1.0.1_all.deb
```

It installs `/usr/bin/centinela`, the systemd service and timers (not enabled automatically, because without Telegram secrets every run would fail), `/etc/centinela/centinela.toml` (a conffile: upgrades keep your edits), and the directories `/etc/centinela/centinela.d/` (drop-in config; the wizard writes `10-wizard.toml` here) and `/etc/centinela/checks.d/` (your own checks). Then follow the Quick start from the secrets step and run `sudo systemctl enable --now centinela-daily.timer centinela-weekly.timer`.

`apt remove centinela` stops the timers and removes the program but keeps your config. `apt purge centinela` also removes `centinela.toml`, the wizard file and the state. It never touches your secrets file, and files you added under `checks.d/` or `centinela.d/` stay. To upgrade, install the new `.deb`.

### Upgrading from 1.0

Run this after upgrading. It changes nothing unless you add `--write`:

```
sudo centinela migrate
```

What changed that your config may have relied on:

- **Services are opt-in.** 1.0 assumed `fail2ban` was required and `nginx`, `docker` and `ssh` were watched when your config did not say. 1.1 assumes nothing. `centinela migrate` lists the settings you were getting without knowing it. Choose your own with `sudo centinela setup` (recommended), or run `sudo centinela migrate --write` to keep exactly the old behaviour: it adds one file, `centinela.d/05-keep-1.0-services.toml`, and never edits your main config or overwrites an existing file.
- **A safety guard now checks commands before they run.** If one of your own checks runs a command that could change the machine, it is refused and the check reports a warning, so it no longer looks healthy while doing nothing. `centinela migrate` scans your `checks.d` for the commands it can read from the source and lists the ones that would be refused; commands built at run time are only reported when the check runs. See [the safety guard](#the-safety-guard).
- **Disk alerts also need little free space.** 1.0 reported any disk at 80% or 90%. 1.1 also requires 20 GB or 10 GB or less to be free, so a big disk that is 90% full with plenty of room stops alerting. To keep the old behaviour, set `warn_free_gb = 0` and `crit_free_gb = 0` under `[disk]`. `centinela migrate` mentions it.
- **Notification credentials are no longer passed to the commands Centinela runs.** A command that relied on inheriting `TELEGRAM_BOT_TOKEN` or `TELEGRAM_CHAT_ID` from the environment will not see them. Nothing else about Telegram changed: it is still the default channel.

### From source

```bash
git clone https://github.com/gonzalogtesta/centinela && cd centinela
python3 build.py                     # needs Python 3.11+; writes dist/centinela, dist/centinela_<version>_all.deb, dist/SHA256SUMS
python3 -m centinela --dry-run        # or run it without building
```

The build uses only the standard library. The single file is reproducible on any machine: the same sources give the same hash, so you can verify a published release by building it yourself. The `.deb` contains gzip-compressed archives, so its hash can differ between systems with different zlib versions; CI checks that two builds on the same runner are identical.

## Notifications

Centinela sends its messages to one or more channels, chosen in `centinela.toml`. The default is Telegram:

```toml
[notify]
channels = ["telegram"]      # also: "ntfy", "webhook"
```

All secrets and URLs go in the secrets file (`/etc/sec/notify.env` by default, or `[notify] env_file`), never in `centinela.toml`, which is meant to be readable by others. Set up each channel you list, then run `centinela --test`: it sends the demo message to every configured channel.

### Telegram

1. In Telegram, message `@BotFather`, send `/newbot`, and copy the token it gives you.
2. Find your bot's username (`https://api.telegram.org/bot<TOKEN>/getMe`, field `username`), open `https://t.me/<username>`, press **Start** and send any message.
3. Open `https://api.telegram.org/bot<TOKEN>/getUpdates`. Your chat id is `message.chat.id`.
4. Put both values in the secrets file (`/etc/sec/notify.env` by default, or `[notify] env_file`):

```
TELEGRAM_BOT_TOKEN=123456789:replace-with-your-token
TELEGRAM_CHAT_ID=987654321
```

Two classic mistakes: using the **bot's own id** (the number before the colon in the token, also shown by `getMe`) as the chat id, and messaging `@BotFather` instead of your new bot. Group chats have a negative id. The secrets file must be mode 600; Centinela warns if it is readable by others, owned by another user, or inside a git repository, and it never prints the token. Verify with `centinela --test`.

### ntfy

Use the full topic URL of your ntfy server, for example `https://ntfy.sh/your-topic`. Subscribe to the same topic in the ntfy app or web page to receive the messages. Put these in the secrets file:

```
NTFY_URL=https://ntfy.sh/your-topic
NTFY_TOKEN=replace-with-your-token
```

`NTFY_TOKEN` is optional. When set, it is sent as an `Authorization: Bearer` header.

### Webhook

`WEBHOOK_URL` receives a POST with the JSON body `{"text": "<message>"}`. Put these in the secrets file:

```
WEBHOOK_URL=https://hooks.example.com/your-endpoint
WEBHOOK_TOKEN=replace-with-your-token
```

`WEBHOOK_TOKEN` is optional. When set, it is sent as an `Authorization: Bearer` header. If the receiving service expects another JSON field name, set it in `centinela.toml`:

```toml
[notify.webhook]
field = "content"
```

The webhook channel is generic. It has not been tested with Slack or Discord, and the field name may need adjusting for the service you send to.

### Several channels

List more than one, for example `channels = ["telegram", "ntfy"]`. Every message goes to every listed channel. If one channel fails, a warning is printed and the others still get the message. Delivery counts as done when at least one channel succeeds. If all of them fail, the run exits with status 1 and nothing is recorded as sent, so the findings are retried on the next run.

### Different channels for different checks

By default every finding goes to `channels`. To send some checks elsewhere, say which channel each one uses (a database queue to ntfy, everything else to Telegram):

```toml
[notify]
channels = ["telegram"]          # the default, and the fallback
[notify.routes]
redis_queue = ["ntfy"]           # by check name; see centinela --list-modules
"*" = ["telegram", "ntfy"]       # every check that has no route of its own (optional)
```

A check can also name its own default with `CHANNELS = ["ntfy"]` in its file; `[notify.routes]` wins over it. A route only chooses among channels you set up, so a check can never send findings to an address of its own.

- Each group of findings is delivered to its own channels and recorded as sent only when delivered. A group that fails is retried through the default channels, so a finding is not dropped; if that fails too it is retried on the next run, while the other groups stay recorded.
- A route that names an unknown channel is reported as a warning finding and its findings go to the default channels.
- Notices about Centinela itself (a failed or missed run) always use the default channels, so a bad route cannot hide them.
- `centinela --dry-run` prints `-> channel` above each group. `centinela --test` sends the demo to every channel in use anywhere, so a mistake in a route shows up at once.

### Write your own channel

A channel is a Python file with the same shape as a check. Put it in `/etc/centinela/notifiers.d/` (or `[notify] extra_dir`), or list it under `[notify] modules = ["/opt/mine/pager.py"]`; the same ownership rules as for checks apply. Then use its `NAME` in `channels` or `[notify.routes]`.

```python
import json
from centinela import notify

NAME = "pager"
DESC = "my paging service"
REQUIRED = ("PAGER_URL", "PAGER_KEY")        # variables it needs in the secrets file

def deliver(text, cfg):
    url, key = notify.need("PAGER_URL", "PAGER_KEY")             # raises NotifyError if either is unset
    notify._post("pager", notify._secure_url("pager", url), json.dumps({"msg": text}).encode(),
                 {"Content-Type": "application/json", **notify.bearer("PAGER_KEY")})
```

Raise `notify.NotifyError` on failure, with a message that does not contain the secret. `notify._secure_url` insists on https, and `notify._post` refuses to follow redirects and retries briefly, so the key is never sent anywhere else. Variables that start like your `REQUIRED` names (`PAGER_`) are hidden from every command a check runs. Test it without a network with `centinela.testing.FakeNotifier`; the setup wizard and `--test` list your channel like the built-in ones.

### When a check could not run

Silence must not hide a check that was blind. When Centinela sends a message and some check could not run this time (a missing permission, a tool that failed), the last line says so: `1 check could not run: firewall (needs root)`. Checks that do not apply to the machine (no Docker installed, say) are not counted. The line appears only in a message that is sent anyway, never as a message of its own; the log (`journalctl -u centinela@weekly`) always has every skip. Switch it off with `[general] coverage_line = false`.

### Where the secret travels

Telegram takes its bot token in the URL path (`https://api.telegram.org/bot<TOKEN>/...`). The connection is HTTPS-encrypted, but the full URL, token included, is visible to a TLS-intercepting proxy and to any log that records full URLs. ntfy and webhook send their token in an `Authorization: Bearer` header instead, so it is not part of the URL.

A webhook URL can itself be the secret. Slack and Discord webhook URLs are, because anyone who has one can post to that channel. Treat them like the Telegram token.

ntfy and webhook refuse plain `http://` URLs, except for localhost, 127.0.0.1 and ::1. They never follow HTTP redirects, so a token cannot be sent on to another host. Error messages never contain the URL or the token. Commands that Centinela runs never inherit environment variables whose names start with `TELEGRAM_`, `NTFY_`, `WEBHOOK_` or `HEARTBEAT_`, or like those a channel of yours declares in `REQUIRED`.

## Heartbeat: is it still running?

Silence means "nothing to report" only if Centinela is actually running. Three small safeguards make a stopped one visible.

**It watches its own schedule.** Every completed run is recorded in the state file, and each run checks the *other* schedule: the daily run notices a weekly run that stopped completing (more than 10 days), and the weekly run notices a daily one (more than 48 hours). The finding is critical, for example `the weekly run of centinela last completed 12 days ago; its timer may be off`, with `systemctl list-timers 'centinela*' --all`. A schedule that never ran on this machine is never reported. If you use only one schedule, tell it: `[heartbeat] watch = ["daily"]`. A run in which no check could run is not recorded, because that proves nothing.

**You can ask it.** `centinela --status` prints when each schedule last completed and exits 1 if one is overdue. It changes nothing, so it fits an external probe, a cron job or a monitoring agent.

**An outside service can notice the silence.** Put a dead-man's-switch URL in the secrets file, for example a check from [healthchecks.io](https://healthchecks.io) (or Uptime Kuma's push monitor, or any service that alerts when a URL is not called on time):

```
HEARTBEAT_URL=https://hc-ping.com/your-uuid
```

Centinela calls it after every run that completed and checked something, and not after a failed run, a dry run, or a run where nothing could be checked. When the calls stop, the service tells you through its own channels. That also covers the case no software on the machine can: the machine is off, or every notification channel is down. The URL contains the secret, so it only comes from the secrets file, is https only, is never printed, and is not passed to commands. A failing ping is a warning in the journal and never fails the run.

If you also want a line in your own channel, set `[heartbeat] message = "weekly"` (a "centinela is alive" line after each quiet weekly run) or `"every"` (after every quiet run). The default is `"off"`: no message when all is well.

## The setup wizard

```bash
sudo centinela setup        # or just: centinela setup, with your own CENTINELA_CONF
```

The wizard looks at the machine (read-only), explains each step, and lets you choose. Items are numbered lists; type numbers to toggle (`2 5-7`), `a` for all, `n` for none, Enter to continue.

1. **Checks**: which modules to keep. Modules that do not apply here are skipped for you.
2. **Naming**: the machine's name, and whether message headers also show the local IP, public IP or OS.
3. **Notifications**: which channels are set up, and whether the secrets file has their keys.
4. **Docker images** running now (if Docker is present).
5. **Running services** (systemd machines).
6. **Listening ports** (Linux).
7. **How much power Centinela has** (Linux with systemd, run with `sudo`), described below.

For steps 4 to 6, each item can be **monitored** (`[x]`) or **not cared about** (`[ ]`), and you decide whether to **freeze** the list (see below). For images, pinned versions can become ranges: `redis:7.4` becomes `redis:7.*`, and rotating tags such as `app:20261118-ab` become `app:*`. Then a prompt shows the allowed versions per image and lets you change them: `redis=7.4` (fixed), `myapp=1.*`, `worker=*`, or `redis=fixed` for whatever version runs now.

At the end it prints the config it would write and asks before writing **one** file, `centinela.d/10-wizard.toml` next to your config. Apart from the optional install in step 7, that is the only thing in Centinela that ever writes anything, and only after you confirm. Your own `centinela.toml` is never edited.

Run it again any time. It starts from your previous choices, marks what is **NEW**, and shows entries that are no longer present. Options: `--dry-run` shows the result without writing, `--yes` accepts the proposals without asking, `--output FILE` writes somewhere else. On an interactive terminal it starts with a banner: the sentinel drawn in braille characters on UTF-8 terminals, a plain ASCII title otherwise (green unless `NO_COLOR` is set); `--no-banner` hides it. Piped output and `--yes` never print it.

### Step 7: Full, Restricted or Advanced

After the config is written, the wizard asks how Centinela should run:

- **Full**: as root inside the bundled read-only sandbox. Every check works. This is what you get without the wizard.
- **Restricted**: as its own account `centinela` with one capability, `CAP_DAC_READ_SEARCH` (read any file, write none). Some checks lose reach.
- **Advanced**: restricted, plus what you choose: the `systemd-journal` or `adm` group (logs), the `docker` group (the wizard makes you type `YES`: it is root-equivalent on the host), any group of your own, and `CAP_NET_ADMIN` to read the firewall rules in force (the account could then change rules too, so it asks separately). The more you add, the closer to root you get, so add only what a check you want needs.

Before it changes anything it prints what the choice means for the checks that apply on this machine, worked out from what each check says it needs: **works**, **reduced** (with what is lost), **LOST**, or **unknown** (your own commands). The same data gives this table:

<!-- limits:start -->
| Check | Full | Restricted | Advanced (journal + docker + firewall) | What Restricted loses |
|---|---|---|---|---|
| `apt` | works | works | works | nothing |
| `certbot` | works | works | works | nothing |
| `cve` | works | works | works | nothing |
| `disk` | works | works | works | nothing |
| `docker` | works | reduced | works | reads Docker's files, not the socket: image rebuilds of the same tag are not checked |
| `expect` | works | depends | depends | runs your own commands; some may need root (see `centinela --coverage`) |
| `firewall` | works | reduced | works | the ufw settings are checked, the rules in force in the kernel are not (needs CAP_NET_ADMIN) |
| `load` | works | works | works | nothing |
| `memory` | works | works | works | nothing |
| `nginx` | works | works | works | nothing |
| `oom` | works | lost | works | cannot read the kernel log (add the systemd-journal or adm group) |
| `ports` | works | reduced | reduced | process names of other accounts' listeners may be missing |
| `restart` | works | lost | lost | needs root (for example needrestart -b) |
| `services` | works | works | works | nothing |
| `units` | works | works | works | nothing |
<!-- limits:end -->

Then, one confirmation each: it creates the account and writes the systemd drop-in `restricted.conf` for `centinela@` and `centinela-failure@` (Restricted and Advanced; picking Full again removes them); asks for the notification secrets **hidden**, as you type, and stores them in `/etc/sec/notify.env` (directory 700, file 600, root), keeping any line that is already there and never printing a value; runs every check once exactly as the service would (`centinela --coverage` under the same account, capabilities and groups) and shows which could not do their work; sends a test message; offers to approve the firewall rules in force (when that check can see them); and starts the timers. `centinela --coverage` is also yours to run any time: it sends nothing and lists, per check, `ok` or `COULD NOT RUN` with the reason.

Without `sudo` or on a machine without systemd (macOS included) the wizard says so and installs nothing; `--yes` and `--output` never install either. The wizard is therefore the only part of Centinela that writes outside its state: the config drop-in, and, on your yes, the account, the drop-ins and the secrets file.

The wizard records what is on the machine when you run it. If something unwanted is already running, untick it and investigate before you freeze.

## Trust lists and freezing

For Docker images, running services and listening ports, each item is in one of three states:

| State | Meaning |
|---|---|
| **Monitored** | You trust it and want it watched: images are checked for updates, a service must stay running, a port must keep listening and must not become more exposed than approved |
| **Not cared about** | Allowed, never reported |
| **New** | Seen for the first time after the list was written |

With **freeze** on, anything *new* is reported:

- a container from an unlisted image: **critical**
- a new listener: **critical** if open on all interfaces, a warning if loopback-only
- a service that starts running that is not listed: a warning

Image rules in detail:

- The key is the image name as `docker ps` shows it. Case does not matter, `docker.io/` and `library/` are optional, and other registries are written in full, for example `"ghcr.io/me/app" = "*"`. The value is a tag pattern, or a list of them: `*` and `?` match, and an image with no tag counts as `latest`.
- An **exact tag means fixed**: any other tag is reported as unexpected, and you are not nagged about newer versions (the "same tag rebuilt upstream" warning still applies). A pattern such as `7.*` keeps the update warnings for newer tags of the same major version.
- `trusted_images = ["redis:7.*"]` (a full image glob) still works, for registries or odd names the table does not express.

With freeze off, the lists only drive the monitoring. The wizard defaults to frozen for images and ports, and not frozen for services (new services appear with ordinary package installs).

```toml
[docker.images]                        # one rule per image: which tags may run
redis  = "7.4"                         # fixed: only redis:7.4, and no "newer version" warnings
myapp  = "1.*"                         # any 1.x tag, handy for rotating deploys
worker = "*"                           # any tag
nginx  = ["1.26", "1.27"]              # several allowed
[docker]
freeze_images = true                   # report any running container that no rule allows
[ports]
expected = ["tcp/22", "tcp/443", "tcp/6379@local"]       # "@local" = loopback only
freeze   = true
```

Limits worth knowing: these are snapshots taken when Centinela runs, so a container that starts and stops between two runs is not seen. An image shown as a bare id (its tag was moved or removed) never matches a name pattern, on purpose. The check looks at *which* image runs, not what the container can do (privileged mode, a mounted Docker socket); the `docker inspect` command in the message is the first step for that.

## Configuration reference

Configuration is TOML. Every setting is optional. Files are read in this order and merged, later ones overriding earlier ones (lists replace, they do not append):

1. `/etc/centinela/centinela.toml` (or `--config FILE`, or the `CENTINELA_CONF` environment variable)
2. `centinela.d/*.toml` next to it, in file name order (the wizard writes `10-wizard.toml`; put your own overrides in `20-local.toml`)

`centinela --print config` prints a commented example with every default.

| Section | Key | Default | Meaning |
|---|---|---|---|
| `general` | `enable` | `"auto"` | `"auto"` = every module that applies, or a list of module names |
| | `disable` | `[]` | Modules to skip; wins over `enable` |
| | `extra_dir` | `/etc/centinela/checks.d` | Directory of your own checks |
| | `modules` | `[]` | Extra check files to load by path |
| | `coverage_line` | `true` | Add "N checks could not run: ..." to a message that is sent |
| | `dedupe_days` | `7` | Minimum days before the same finding is re-sent |
| | `max_per_module` | `8` | More findings than this from one module collapse into "+N more" |
| | `allow_dangerous_commands` | `false` | Turns off the safety guard for every command (not recommended; prefer `allow_dangerous` on one rule) |
| | `host_name` | system hostname | Name shown in message headers |
| | `state_file` | `/var/lib/centinela/state.json` | Dedupe state |
| `notify` | `show` | `["host"]` | Header details: `host`, `ip` (local, no packet sent), `public_ip` (asks `api.ipify.org`), `os` |
| | `channels` | `["telegram"]` | Where to send: `telegram`, `ntfy`, `webhook` |
| | `public_ip_url` | `https://api.ipify.org` | Service used for `public_ip` |
| | `env_file` | `/etc/sec/notify.env` | Secrets file for the notification channels |
| | `extra_dir` | `/etc/centinela/notifiers.d` | Directory of your own channels |
| | `modules` | `[]` | Extra channel files to load by path |
| `notify.routes` | `<check name>` or `"*"` | none | Channels for that check, e.g. `redis_queue = ["ntfy"]` |
| `notify.webhook` | `field` | `"text"` | JSON field that carries the message for the `webhook` channel |
| `apt` | `watch` | nginx, docker, openssh, kernel packages | Globs called out on their own line |
| | `max_index_age_days` | `7` | Warn when the apt cache is older |
| | `stamp_file`, `reboot_flag` | Debian defaults | Paths used to read cache age and reboot-required |
| `restart` | `proc_names` | `["nginx", "sshd"]` | Processes scanned when needrestart is absent |
| | `ignore` | `user@*.service`, `getty@*.service` | Services never reported |
| `nginx` | `binary` | `nginx` | Binary to ask for its version |
| | `advisories_url`, `downloads_url` | nginx.org pages | Where advisories and latest releases are read |
| `docker.images` | `<image> = "tag rule"` (or a list) | unset | Which tags of each image may run: exact = fixed, `*`/`?` = a range; with freeze, anything else running is critical |
| `docker` | `trusted_images` | unset | Allowed full-image globs (the table above is the friendlier form) |
| | `freeze_images` | `true` once `docker.images` or `trusted_images` is set | Report running containers allowed by no rule and not in `ignore_images` |
| | `ignore_images` | `[]` | Allowed but not monitored (also skips the update check) |
| | `ignore_containers` | `[]` | Container name globs skipped by the down/unhealthy check |
| | `allow_exit_zero` | `false` | Do not report containers that exited with code 0 |
| | `detect_base` | `true` | Find the base image of your own images |
| | `watch_images` | `[]` | Globs resolved with `docker image ls` and checked for updates |
| | `extra_images`, `dockerfiles` | `[]` | Images (or `FROM` lines of Dockerfiles) to check even if nothing runs them |
| | `hub_pages` | `3` | Pages of Docker Hub tags to read per image |
| `docker.track` | `<repo> = "major" or "minor"` | `"major"` | How far "newer tag" looks, per image, e.g. `python = "minor"` |
| `certbot` | `live_dir` | `/etc/letsencrypt/live` | Where certificates are read |
| | `warn_days`, `crit_days` | `21`, `7` | Thresholds |
| `disk` | `warn_percent`, `crit_percent` | `80`, `90` | Percent used, for space and inodes |
| | `warn_free_gb`, `crit_free_gb` | `20`, `10` | A space finding also needs this little free; `0` = percent only |
| | `ignore_mounts` | `["/snap/*"]` (Linux); the macOS system volumes (macOS) | Mount points never reported (globs); setting it replaces the default |
| `heartbeat` | `message` | `"off"` | `"weekly"` or `"every"`: a "still alive" line after a quiet run |
| | `watch` | `["daily", "weekly"]` | Which schedules the other one should expect to complete |
| | `stale_frequent_minutes`, `stale_daily_hours`, `stale_weekly_days` | `120`, `48`, `10` | How late a schedule may be before it is reported |
| `firewall` | `ignore_chains` | Docker, fail2ban, Kubernetes, ... chains | Globs of chains, tables and sets left out of the comparison |
| | `ignore_lines` | `docker0`, `br-` bridges, `veth` | Regular expressions for rules left out |
| | `show_changes` | `true` | Put the first changed lines in the message |
| `memory` | `warn_percent`, `crit_percent` | `90`, `95` | Percent of memory used |
| | `warn_free_mb`, `crit_free_mb` | `1024`, `512` | A finding also needs this little available; `0` = percent only |
| | `swap_warn_percent`, `swap_warn_mb` | `80`, `512` | Linux swap: both must be reached; `swap_warn_percent = 0` turns it off |
| `oom` | `window_days`, `ignore` | `7`, none | How far back to look; process names to leave out |
| `load` | `warn_per_cpu`, `crit_per_cpu` | `1.0`, `2.0` | Load average divided by the number of CPUs; `0` turns a level off |
| | `window` | `15` | Minutes the load is averaged over: `1`, `5` or `15` |
| | `ignore_mounts` | `["/snap/*"]` | Mount point globs to skip |
| `units` | `ignore` | `[]` | Failed units to skip (globs) |
| `services` | `required` | `[]` | Not installed or not active is critical |
| | `watch` | `[]` | Checked only if installed |
| | `known`, `freeze` | `[]`, `false` | Services you do not care about; with `freeze`, any other running service is reported |
| `cve` | `suite` | from `/etc/os-release` | Debian suite for debsecan |
| | `min_urgency` | `"high"` | Lowest urgency reported |
| | `only_fixed` | `true` | Only CVEs that already have a fix |
| `ports` | `expected`, `known`, `freeze` | unset | See [Trust lists and freezing](#trust-lists-and-freezing); the module is off until a list is set |

`services` does nothing until you list services in `required` or `watch`, or turn on `freeze`: Centinela never judges a machine on services it was not told about. The setup wizard fills `watch` for you.

Command line:

```
centinela                        run once and send findings (weekly mode: everything)
centinela --mode daily           critical findings only (also: --critical-only)
centinela --mode frequent        critical findings of the fast checks only (for the optional 15 minute timer)
centinela --coverage             run each check once, send nothing, say which could not run as this user
centinela --dry-run              print instead of sending; reads state, never writes it
centinela --no-dedupe            ignore the 7-day memory (with --dry-run)
centinela --only disk,docker     run just these modules, ignoring enable/disable
centinela --list-modules         show what runs on this machine
centinela --test                 send a clearly marked demo message (with --dry-run: print it)
centinela setup                  the wizard (see above)
centinela --print NAME           print a bundled file: config, service, daily-timer, weekly-timer, frequent-timer, example-tcp-port, example-file-age, example-http-status, example-command-threshold
centinela --version
```

Other options: `--config FILE`, `--env-file FILE`, `--state FILE`.

### Restricted install (optional)

By default the service runs as root, sandboxed. If you would rather Centinela hold no more power than it needs to look, run it as its own account that can read files but never write them. It is opt-in, and it costs you some checks.

**Linux with systemd.** The `.deb` creates the `centinela` account (no login, no home). For the single file, create it yourself:

```bash
centinela --print restricted-user | sudo tee /etc/sysusers.d/centinela.conf >/dev/null
sudo systemd-sysusers
for unit in centinela@ centinela-failure@; do   # the failure notice must run as the same account: it shares the state file
  sudo install -d -m 755 /etc/systemd/system/$unit.service.d
  centinela --print restricted | sudo tee /etc/systemd/system/$unit.service.d/restricted.conf >/dev/null
done
sudo systemctl daemon-reload
sudo centinela --dry-run
```

The service then runs as `centinela` with one capability, `CAP_DAC_READ_SEARCH` (read any file, write none), no new privileges, and a read-only filesystem except its state directory. Secrets are still read by systemd as root from `/etc/sec/notify.env` and handed to the service, so the account cannot open that file.

What you keep, and what you lose. Without the Docker socket or `ufw status`, Centinela reads the files those tools keep, which the account can see with `CAP_DAC_READ_SEARCH`:

- **Docker:** it reads `/var/lib/docker/containers/*/config.v2.json` (or the `data-root` of `daemon.json`, or `[docker] data_root`), so containers that are down, unhealthy or running an image you did not approve are still reported. A container the file calls running is trusted only if its process still exists. Not checked in this mode: rebuilds of the same tag (they need the socket). The file format is Docker's own and can change between versions; unreadable files are skipped, never fatal.
- **ufw:** it reads `ENABLED` in `/etc/ufw/ufw.conf`, so a disabled ufw is reported. The rules loaded in the kernel right now are not checked, so a flushed or edited ruleset is invisible without root.
- **Lost entirely:** `needrestart -b`, and anything else that needs more than reading. Centinela says so instead of failing silently. Adding the account to the `docker` group restores the socket, but that group is root-equivalent on the host, which defeats the point. Add `systemd-journal` or `adm` for log access.

**macOS.** Wrap the run in an Apple sandbox profile that denies every write except the state directory and refuses to run `rm`, `mv`, `cp` and similar:

```bash
centinela --print restricted-macos > ~/.config/centinela/restricted.sb
sandbox-exec -D STATE=$HOME/.local/state/centinela -f ~/.config/centinela/restricted.sb centinela --dry-run
```

In a launchd plist, put `/usr/bin/sandbox-exec -D STATE=... -f ... python3 centinela ...` in `ProgramArguments`. Apple has marked `sandbox-exec` deprecated, but it still works on Intel and Apple silicon at the time of writing; if a future macOS removes it, this profile stops working and the normal install is unaffected. Creating a separate macOS user for it is not covered here and is untested.

**Tested.** The mechanisms behind it (write denied, one capability to read root-only files, signals denied, a fixed unprivileged user with the full hardening set) were checked on a Raspberry Pi (aarch64) and an x86-64 server. The exact drop-in and the `.deb` account creation are not yet tested on real hardware. The macOS profile was run end to end on an Intel Mac only. Not yet tested as the restricted user: `ufw`, `needrestart`, Let's Encrypt files, and Linux without systemd.

## Security model

**What it does.** It runs read-only commands (a safety guard refuses configured commands that could change the machine, see [Expectations](#the-safety-guard); depending on the checks: `apt list`, `docker ps/info/image inspect`, `systemctl show/--failed`, `ufw status`, `df`, `openssl x509`, `needrestart -b`, `debsecan`, `ss`, and whatever your own checks run), reads a few files, and sends one HTTPS request per notification.

**Privileges.** Some checks need root (the Docker socket, certificate directories, `ufw status`). Without root they are skipped and Centinela says so. Run it as a normal user for a machine where that is enough, or as root for the full set. The bundled systemd unit runs as root but sandboxed: the filesystem is read-only except its own state directory, no new privileges, no home directory access, only unix, internet and netlink sockets (netlink is how `nft list ruleset` reads the firewall). The sandbox is what enforces "read-only", not just the code.

**A tighter install.** [Restricted install](#restricted-install-optional) runs it as an unprivileged account that can read but not write.

**Network.** Outbound requests go only to:

| Host | Why |
|---|---|
| `api.telegram.org`, or the ntfy / webhook URL you configure | delivering messages |
| `nginx.org` | security advisories and latest versions (only if nginx is installed) |
| `hub.docker.com` | image tags and digests (only if Docker is installed) |
| `api.ipify.org` | only if you enable `public_ip` |
| `security-tracker.debian.org` | contacted by `debsecan` itself, if installed |
| whatever your own checks contact | e.g. the URLs you list |

**Secrets.** The credentials (the bot token, and the ntfy and webhook URLs and tokens) live in a mode-600 file, are never written to the config, state or logs, and do not appear in error messages (tests check this). The wizard asks for them only with a hidden prompt, writes them only to that file, and never prints them. ntfy and webhook send their token in an `Authorization: Bearer` header and never follow HTTP redirects, so that token cannot be sent to another host.

**Supply chain.** There are no runtime or build dependencies. Builds are reproducible and releases publish SHA-256 sums. To detect tampering, not just corruption, compare the hash with the one in the release notes, not only with the file next to the download.

**What it cannot do.**

- It is a periodic snapshot, not a live monitor. Events between runs are invisible.
- Anyone with root can edit the config, stop the schedule, or read the secrets. Centinela does not defend a machine that is already fully compromised, and a missing message does not prove health. Forward your logs off the machine if you need that.
- It trusts its data sources (the nginx.org page, Docker Hub, the Debian security tracker). A scraped page can change format.
- "No findings" means "none of the checks found anything", not "the machine is secure".

**Reporting a vulnerability.** See [SECURITY.md](SECURITY.md). Please report security problems privately, through [GitHub's private vulnerability reporting](https://github.com/gonzalogtesta/centinela/security/advisories/new) (the "Report a vulnerability" button on the Security tab), and not in a public issue.

## Troubleshooting

| What you see | Meaning and fix |
|---|---|
| `centinela needs Python 3.11+` | The Python that ran it is older. Check `python3 --version`; under cron or launchd call the interpreter explicitly. |
| `no check ran on this machine` | Nothing applies here. See `--list-modules` and [Add your own checks](#add-your-own-checks). |
| `not running as root: ... checks may be skipped` | Linux only: run with `sudo` for the full set. |
| `docker skipped: docker socket not accessible` / `certbot skipped: cannot read ... (needs root)` | Same cause: not root. |
| `telegram HTTP 401` | The bot token is wrong. |
| `telegram HTTP 400: ... chat not found` | Wrong chat id, or you never pressed Start in the chat with the bot. |
| `telegram HTTP 403: Forbidden: the bot can't send messages to the bot` | You used the bot's own id as the chat id. Use `message.chat.id` from `getUpdates` after messaging the bot. |
| `getUpdates` returns `"result":[]` | You have not messaged *your bot* yet (not BotFather), or the update is older than 24 hours. Send another message and reload. |
| `cannot read ...notify.env (run as root, or with sudo)` | The secrets file is root-only: use `sudo`. |
| `... is accessible by others (mode 644)` | `chmod 600` the secrets file. |
| `... is owned by uid N, not root or you` | `sudo chown root` the secrets file. |
| `... is inside the git repository ...` | Move the secrets file out of the repository, or make sure it is ignored. |
| The systemd unit `centinela@weekly.service` shows as failed | Telegram delivery failed. Read `journalctl -u 'centinela@*' -n 30 --no-pager`; the findings are retried on the next run. |
| A module you do not need keeps reporting | Add it to `disable` in `centinela.d/20-local.toml`, or run `centinela setup`. |
| Not sure what a run would do | `centinela --dry-run --no-dedupe` prints the full message and writes nothing. |

## Development and contributing

```
centinela/            the Python package (stdlib only)
  cli.py core.py     entry point, findings, config, command and HTTP helpers
  checks/            one file per built-in module
  setup.py           the wizard
  data/              files bundled into the executable: example config, systemd units, example check
packaging/debian/    maintainer scripts and the copyright file for the .deb
build.py             builds the single-file executable, the .deb and SHA256SUMS (stdlib only)
tests/               unit tests with fixtures of command output
```

```bash
uv run --frozen python -m unittest discover -s tests     # or: python3 -m unittest discover -s tests
uv run --frozen python -m centinela --dry-run             # run from source
python3 build.py                                         # build dist/
```

The tests need no root and no network.

### Continuous integration and releases

Two GitHub Actions workflows live in `.github/workflows/`:

- `ci.yml` runs on every push to `main` and every pull request: the unit tests, a build, a check that two builds give identical hashes, and `packaging/ci/verify-debian.sh`, which installs the `.deb` on Debian 12 with the real `dpkg` and the minimum supported Python (3.11), then removes it again. You can run that script yourself wherever Docker is available.
- `release.yml` runs when a tag like `v1.0.0` is pushed. It refuses unless the tag, `pyproject.toml` and `centinela/__init__.py` agree on the version, runs the same checks, and creates a **draft** release containing the `.deb`, the single file and `SHA256SUMS`. You review the draft and publish it.

To make a release, change the version in `pyproject.toml` and `centinela/__init__.py`, commit, then:

```bash
git tag v1.0.0 && git push origin v1.0.0
```

The workflows use one third-party action, `actions/checkout`, pinned to an exact commit, and one container image, the official `debian` image, pinned by digest. Nothing else is downloaded or installed from outside the runner and the Debian mirrors.

Please keep these rules when contributing:

1. **Checks are read-only.** A check must never change the system. The only code that may write is the wizard, and only its own drop-in file after confirmation.
2. **No dependencies.** Standard library only, so the program stays one auditable file. If a dependency ever seems justified, open an issue first.
3. **Test parsers against real output.** Add a fixture of the command's actual output, including awkward cases, and do not assume anything about one particular machine.
4. **Findings must be actionable and stable.** One line, a command to run, and an id that does not change from run to run for the same problem.
5. **Say when you did not verify something.** Behaviour on systems or tool versions you could not test should be stated, not implied.

Bug reports and ideas go to the [issue tracker](https://github.com/gonzalogtesta/centinela/issues). They are most useful with the output of `centinela --dry-run --no-dedupe` and `centinela --list-modules`, plus your operating system and version. Please remove hostnames and IPs you consider private.

## Roadmap

Ideas, not promises:

- **More portable built-in checks** so that a Mac or a minimal Linux box gets useful output with no custom code: "process must be running", "URL must answer", launchd jobs and Raspberry Pi health, plus a bundled launchd schedule. Disk, memory and load already work on Linux and macOS.
- **Cluster awareness.** A combined view of several machines (a heartbeat per machine already exists).
- **Live SSH login alerts.** A small `centinela watch` service following the journal, alerting at the moment of an unknown login and on `sudo` use, with a known-keys list in the wizard.
- **Quiet mode.** `centinela here 2h` to hold back login and sudo noise while you work, with a time limit, start and end messages so it cannot be used silently, and a summary at the end.
- **More notifiers** (email, Matrix, Pushover) and more distributions.

## License

MIT. See [LICENSE](LICENSE). The `.deb` ships the text in `/usr/share/doc/centinela/copyright`.
