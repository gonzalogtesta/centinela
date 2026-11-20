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
- [Add your own checks](#add-your-own-checks)
- [Several machines](#several-machines)
- [How it works](#how-it-works)
- [Scheduling](#scheduling)
- [Installation options](#installation-options)
- [Telegram setup](#telegram-setup)
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
| **macOS** | `docker`, plus `nginx` and `certbot` if those are installed | Core and custom checks work; most built-ins do not apply yet |
| **Windows** | none | Not supported |

**Run `centinela --list-modules` on a new machine.** Every module marked `n/a` does not apply there, and if all of them are `n/a`, Centinela has nothing to check and will say so. Silence is not health. On such machines, [write a few custom checks](#add-your-own-checks) (is my job running, is this URL up, is the Pi overheating): that takes minutes, and recipes are below. More portable built-in checks are on the [roadmap](#roadmap).

Centinela is young (version 1.0). The parsers are covered by unit tests built on fixtures modelled on real command output; a few formats, `debsecan` in particular, were written from the tools' documentation and need confirmation on more machines. The Debian package is tested with Debian 12's own `dpkg`. Reports from other systems are very welcome.

It is a convenience watchdog, **not** an intrusion detection system or a vulnerability scanner. See [Security model](#security-model).

## Quick start

You need Python 3.11+, a Telegram bot ([setup](#telegram-setup)), and the `centinela` file from the [Releases page](https://github.com/gonzalogtesta/centinela/releases).

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
| `disk` | Space and inode usage above 80% | Linux (GNU `df`) | 90% or more |
| `units` | Failed systemd units | systemd | Never (warning) |
| `services` | Required and watched services are active; optionally anything new that starts running | systemd | A required or watched service is down |
| `firewall` | `ufw status` is active | `ufw` | ufw is inactive |
| `ports` | Listening TCP/UDP ports against your approved list (off until you set a list) | Linux (`ss`) | A new listener open on all interfaces, an expected port gone, or an approved loopback-only port now exposed |
| `cve` | `debsecan`: high-urgency CVEs in installed Debian packages that already have a fix | `debsecan` | Remotely exploitable |

Notes:

- **certbot** reads the certificate files with `openssl`, so it never takes certbot's lock. It checks the certificate stored on the machine itself. If a proxy or CDN terminates TLS in front of it, the certificate your visitors see is the proxy's, and certificates stored elsewhere (for example an origin certificate under another directory) are not checked.
- **docker** compares only Docker Hub images. The base image of your own image is found automatically when possible: from the `org.opencontainers.image.base.name` label, or by finding a Docker Hub image on the machine whose layers are the first layers of yours. That is a heuristic and needs the base image still present locally; otherwise list it with `extra_images` or `dockerfiles`. Wildcards work too: `watch_images = ["python:3.12*"]` is resolved with `docker image ls`, keeping only the newest local tag per repository and variant so rotating deploys do not pile up findings.
- **nginx** reads the advisory list from the HTML page on nginx.org. If that page changes format, the check reports nothing rather than guessing.
- **cve** covers Debian-packaged software only.
- **apt** never runs `apt-get update`. It reads the existing cache and warns if the cache is older than 7 days.

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

### Other machines answer on a port

Shipped as an example: `centinela --print example-check` prints `tcp_port.py`, configured with `[tcp_port] targets = ["127.0.0.1:6379", "node2.local:22"]`. It is critical when a host:port does not accept a TCP connection. See [Several machines](#several-machines).

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
- The roadmap has a heartbeat ("still alive") message and a combined view; until then, silence from a single machine does not prove it is healthy.

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
centinela --print daily-timer  | sudo tee /etc/systemd/system/centinela-daily.timer >/dev/null
centinela --print weekly-timer | sudo tee /etc/systemd/system/centinela-weekly.timer >/dev/null
sudo systemctl daemon-reload
sudo systemctl enable --now centinela-daily.timer centinela-weekly.timer
systemctl list-timers 'centinela*'
```

The bundled unit calls `/usr/local/bin/centinela` and runs sandboxed: the filesystem is read-only to it except its own state directory. To run it once now: `sudo systemctl start centinela@weekly.service`, then `journalctl -u 'centinela@*' -n 30 --no-pager`.

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
sudo apt install ./centinela_1.0.0_all.deb
```

It installs `/usr/bin/centinela`, the systemd service and timers (not enabled automatically, because without Telegram secrets every run would fail), `/etc/centinela/centinela.toml` (a conffile: upgrades keep your edits), and the directories `/etc/centinela/centinela.d/` (drop-in config; the wizard writes `10-wizard.toml` here) and `/etc/centinela/checks.d/` (your own checks). Then follow the Quick start from the secrets step and run `sudo systemctl enable --now centinela-daily.timer centinela-weekly.timer`.

`apt remove centinela` stops the timers and removes the program but keeps your config. `apt purge centinela` also removes `centinela.toml`, the wizard file and the state. It never touches your secrets file, and files you added under `checks.d/` or `centinela.d/` stay. To upgrade, install the new `.deb`.

### From source

```bash
git clone https://github.com/gonzalogtesta/centinela && cd centinela
python3 build.py                     # needs Python 3.11+; writes dist/centinela, dist/centinela_<version>_all.deb, dist/SHA256SUMS
python3 -m centinela --dry-run        # or run it without building
```

The build uses only the standard library. The single file is reproducible on any machine: the same sources give the same hash, so you can verify a published release by building it yourself. The `.deb` contains gzip-compressed archives, so its hash can differ between systems with different zlib versions; CI checks that two builds on the same runner are identical.

## Telegram setup

1. In Telegram, message `@BotFather`, send `/newbot`, and copy the token it gives you.
2. Find your bot's username (`https://api.telegram.org/bot<TOKEN>/getMe`, field `username`), open `https://t.me/<username>`, press **Start** and send any message.
3. Open `https://api.telegram.org/bot<TOKEN>/getUpdates`. Your chat id is `message.chat.id`.
4. Put both values in the secrets file (`/etc/sec/notify.env` by default, or `[notify] env_file`):

```
TELEGRAM_BOT_TOKEN=123456789:replace-with-your-token
TELEGRAM_CHAT_ID=987654321
```

Two classic mistakes: using the **bot's own id** (the number before the colon in the token, also shown by `getMe`) as the chat id, and messaging `@BotFather` instead of your new bot. Group chats have a negative id. The secrets file must be mode 600; Centinela warns if it is readable by others, and it never prints the token. Verify with `centinela --test`.

The secrets never go in `centinela.toml`, which is meant to be readable by others.

## The setup wizard

```bash
sudo centinela setup        # or just: centinela setup, with your own CENTINELA_CONF
```

The wizard looks at the machine (read-only), explains each step, and lets you choose. Items are numbered lists; type numbers to toggle (`2 5-7`), `a` for all, `n` for none, Enter to continue.

1. **Checks**: which modules to keep. Modules that do not apply here are skipped for you.
2. **Naming**: the machine's name, and whether message headers also show the local IP, public IP or OS.
3. **Telegram**: whether the secrets file exists and has both keys. It never shows or asks for the values.
4. **Docker images** running now (if Docker is present).
5. **Running services** (systemd machines).
6. **Listening ports** (Linux).

For steps 4 to 6, each item can be **monitored** (`[x]`) or **not cared about** (`[ ]`), and you decide whether to **freeze** the list (see below). For images, pinned versions can become ranges: `redis:7.4` becomes `redis:7.*`, and rotating tags such as `app:20261118-ab` become `app:*`. Then a prompt shows the allowed versions per image and lets you change them: `redis=7.4` (fixed), `myapp=1.*`, `worker=*`, or `redis=fixed` for whatever version runs now.

At the end it prints the config it would write and asks before writing **one** file, `centinela.d/10-wizard.toml` next to your config. That is the only thing in Centinela that ever writes anything, and only after you confirm. Your own `centinela.toml` is never edited.

Run it again any time. It starts from your previous choices, marks what is **NEW**, and shows entries that are no longer present. Options: `--dry-run` shows the result without writing, `--yes` accepts the proposals without asking, `--output FILE` writes somewhere else. On an interactive terminal it starts with a banner: the sentinel drawn in braille characters on UTF-8 terminals, a plain ASCII title otherwise (green unless `NO_COLOR` is set); `--no-banner` hides it. Piped output and `--yes` never print it.

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
| | `dedupe_days` | `7` | Minimum days before the same finding is re-sent |
| | `max_per_module` | `8` | More findings than this from one module collapse into "+N more" |
| | `host_name` | system hostname | Name shown in message headers |
| | `state_file` | `/var/lib/centinela/state.json` | Dedupe state |
| `notify` | `show` | `["host"]` | Header details: `host`, `ip` (local, no packet sent), `public_ip` (asks `api.ipify.org`), `os` |
| | `public_ip_url` | `https://api.ipify.org` | Service used for `public_ip` |
| | `env_file` | `/etc/sec/notify.env` | Telegram secrets file |
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
| `disk` | `warn_percent`, `crit_percent` | `80`, `90` | Thresholds, for space and inodes |
| | `ignore_mounts` | `["/snap/*"]` | Mount point globs to skip |
| `units` | `ignore` | `[]` | Failed units to skip (globs) |
| `services` | `required` | `["fail2ban"]` | Not installed or not active is critical |
| | `watch` | `["nginx", "docker", "ssh"]` | Checked only if installed |
| | `known`, `freeze` | `[]`, `false` | Services you do not care about; with `freeze`, any other running service is reported |
| `cve` | `suite` | from `/etc/os-release` | Debian suite for debsecan |
| | `min_urgency` | `"high"` | Lowest urgency reported |
| | `only_fixed` | `true` | Only CVEs that already have a fix |
| `ports` | `expected`, `known`, `freeze` | unset | See [Trust lists and freezing](#trust-lists-and-freezing); the module is off until a list is set |

The defaults for `services.required` (fail2ban) and `watch` suit a typical Linux server. On a Pi or Mac, set `required = []`, or disable the module, if they do not apply.

Command line:

```
centinela                        run once and send findings (weekly mode: everything)
centinela --mode daily           critical findings only (also: --critical-only)
centinela --dry-run              print instead of sending; reads state, never writes it
centinela --no-dedupe            ignore the 7-day memory (with --dry-run)
centinela --only disk,docker     run just these modules, ignoring enable/disable
centinela --list-modules         show what runs on this machine
centinela --test                 send a clearly marked demo message (with --dry-run: print it)
centinela setup                  the wizard (see above)
centinela --print NAME           print a bundled file: config, service, daily-timer, weekly-timer, example-check
centinela --version
```

Other options: `--config FILE`, `--env-file FILE`, `--state FILE`.

## Security model

**What it does.** It runs read-only commands (depending on the checks: `apt list`, `docker ps/info/image inspect`, `systemctl show/--failed`, `ufw status`, `df`, `openssl x509`, `needrestart -b`, `debsecan`, `ss`, and whatever your own checks run), reads a few files, and sends one HTTPS request per notification.

**Privileges.** Some checks need root (the Docker socket, certificate directories, `ufw status`). Without root they are skipped and Centinela says so. Run it as a normal user for a machine where that is enough, or as root for the full set. The bundled systemd unit runs as root but sandboxed: the filesystem is read-only except its own state directory, no new privileges, no home directory access, only unix and internet sockets. The sandbox is what enforces "read-only", not just the code.

**Network.** Outbound requests go only to:

| Host | Why |
|---|---|
| `api.telegram.org` | delivering messages |
| `nginx.org` | security advisories and latest versions (only if nginx is installed) |
| `hub.docker.com` | image tags and digests (only if Docker is installed) |
| `api.ipify.org` | only if you enable `public_ip` |
| `security-tracker.debian.org` | contacted by `debsecan` itself, if installed |
| whatever your own checks contact | e.g. the URLs you list |

**Secrets.** The bot token lives in a mode-600 file, is never written to the config, state or logs, and does not appear in error messages (a test checks this). The wizard never asks for it.

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

- **Portable built-in checks** so that a Mac or a minimal Linux box gets useful output with no custom code: disk, "process must be running", "URL must answer", launchd jobs, load and memory, and Raspberry Pi health, plus a bundled launchd schedule.
- **Cluster awareness.** A heartbeat ("still alive") message, and a combined view of several machines, so a node that goes silent is noticed.
- **Live SSH login alerts.** A small `centinela watch` service following the journal, alerting at the moment of an unknown login and on `sudo` use, with a known-keys list in the wizard.
- **Quiet mode.** `centinela here 2h` to hold back login and sudo noise while you work, with a time limit, start and end messages so it cannot be used silently, and a summary at the end.
- **More notifiers** (ntfy, Slack, email) and more distributions.

## License

MIT. See [LICENSE](LICENSE). The `.deb` ships the text in `/usr/share/doc/centinela/copyright`.
