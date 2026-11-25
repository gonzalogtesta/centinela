"""A guard against commands that could change the machine.

Centinela only looks. This refuses the commands in the config that are known to write, delete,
restart or install, so a pasted `find / -delete` or a script that calls `rm` is stopped before it runs.

It is a safety net against mistakes, NOT a sandbox: it cannot understand an arbitrary program.
What really enforces "read-only" is the systemd unit's sandbox (see the README). A command
that is not recognised is allowed, so keep config files root-owned and review what you add.
"""
from __future__ import annotations

import os
import re
import shutil

# Commands that change data or the system, whatever their arguments.
DANGEROUS = frozenset("""
rm rmdir mv cp ln dd shred truncate touch tee install mkdir mknod rsync scp sftp
mkswap mount umount swapon swapoff fdisk sfdisk parted wipefs losetup
chmod chown chgrp chattr setfacl setcap
kill pkill killall reboot shutdown halt poweroff init telinit
useradd userdel usermod groupadd groupdel groupmod passwd chpasswd adduser deluser
crontab at batch visudo update-alternatives ldconfig
""".split())
DANGEROUS_PREFIXES = ("mkfs", "mke2fs")

# Run another command: its arguments are checked too.
WRAPPERS = frozenset("sudo doas env nice ionice nohup timeout time stdbuf xargs watch setsid flock chroot unbuffer".split())

# Run code that cannot be inspected when it is given inline (-c, -e, ...).
INTERPRETERS = frozenset("""
sh bash dash zsh ksh csh tcsh fish ash busybox python python2 python3 perl ruby node nodejs php lua
awk gawk mawk osascript pwsh tclsh
""".split())
INLINE_FLAGS = ("-c", "-e", "-E", "-r", "-p", "-m", "--eval", "--command", "--exec")

# For tools with many verbs, only these read-only ones are allowed.
READ_ONLY = {
    "systemctl": {"show", "status", "is-active", "is-enabled", "is-failed", "list-units", "list-unit-files",
                  "list-timers", "list-sockets", "list-dependencies", "list-jobs", "cat", "get-default"},
    "docker": {"ps", "images", "inspect", "info", "version", "logs", "top", "stats", "port", "diff", "history",
               "events", "search"},
    "apt": {"list", "show", "search", "policy", "depends", "rdepends", "showpkg"},
    "snap": {"list", "info", "services", "connections", "version"},
    "pip": {"list", "show", "freeze", "check", "--version"},
    "pip3": {"list", "show", "freeze", "check", "--version"},
    "ufw": {"status", "show", "version"},
    "launchctl": {"list", "print", "print-cache", "print-disabled", "blame"},
    "brew": {"list", "info", "outdated", "search", "deps", "leaves", "config", "--version"},
    "kubectl": {"get", "describe", "logs", "top", "version", "cluster-info", "api-resources"},
}
# docker image ls, docker volume inspect, ...: these resource words take their own read-only sub-verb.
DOCKER_RESOURCES = {"container", "image", "network", "volume", "system", "compose", "context", "manifest"}
DOCKER_SUB_OK = {"ls", "list", "ps", "inspect", "history", "df", "logs", "top", "stats", "port", "diff", "version"}
# Tools that are only dangerous with these options or verbs.
BAD_ARGS = {
    "find": {"-delete", "-exec", "-execdir", "-ok", "-okdir", "-fprint", "-fprint0", "-fprintf", "-fls"},
    "sed": {"-i", "--in-place"},
    "openssl": {"-out", "-keyout"},
    "nginx": {"-s"},
    "curl": {"-o", "-O", "-J", "-T", "--output", "--remote-name", "--upload-file", "--create-dirs"},
    "ip": {"add", "del", "delete", "change", "replace", "flush", "set", "append", "prepend"},
    "sysctl": {"-w", "--write", "-p", "--load"},
    "ss": {"-K", "--kill"},
    "journalctl": {"--vacuum", "--rotate", "--flush", "--relinquish", "--smart-relinquish-var"},
    "iptables-save": {"-f", "--file"},
    "ip6tables-save": {"-f", "--file"},
}
# iptables flags that add, delete, flush or set something: refused even next to -L or -S
FIREWALL_WRITE_FLAGS = frozenset("""-A -I -D -R -F -X -Z -N -P -E --append --insert --delete --replace --flush
--delete-chain --zero --new-chain --policy --rename-chain""".split())
SCRIPT_WORDS = frozenset("""
rm rmdir mv dd shred truncate wipefs fdisk parted chmod chown kill pkill killall reboot shutdown halt poweroff
rmtree unlink os.remove os.rename
""".split()) | {"mkfs"}


class Unsafe(Exception):
    """A command that could change the machine; the message says why."""


def _base(arg):
    return os.path.basename(arg)


def _positional(args):
    return [a for a in args if not a.startswith("-")]


def _is_dangerous_name(name):
    return name in DANGEROUS or name.startswith(DANGEROUS_PREFIXES)


def verify(argv, _depth=0):
    """Raise Unsafe if running argv could change the machine. Returns None when it looks read-only."""
    if not argv:
        return
    if _depth > 5:
        raise Unsafe("commands nested too deeply to check")
    name, args = _base(argv[0]), [str(a) for a in argv[1:]]
    if _is_dangerous_name(name):
        raise Unsafe("%s can change or delete data" % name)
    if name in WRAPPERS:
        for i in range(len(args)):  # the real command is somewhere in the rest: check every candidate
            if not args[i].startswith("-") and "=" not in args[i]:
                verify(args[i:], _depth + 1)
        return
    if name in INTERPRETERS or re.match(r"^(python|perl|ruby|php)[\d.]*$", name):
        if name == "awk" or name == "gawk" or name == "mawk":
            if "-f" not in args:
                raise Unsafe("%s with an inline program cannot be inspected (use -f script)" % name)
        elif any(a in INLINE_FLAGS or (a.startswith("-") and not a.startswith("--") and "c" in a[1:] and len(a) <= 4)
                 for a in args):
            raise Unsafe("%s with inline code cannot be inspected; put it in a script file" % name)
        for arg in args:  # every file we are handed may be the program
            if not arg.startswith("-") and os.path.isfile(arg):
                scan_script(arg)
        return
    if name in READ_ONLY:
        safe, verbs = READ_ONLY[name], _positional(args)
        verb = verbs[0] if verbs else None
        if name == "docker" and verb in DOCKER_RESOURCES:
            if len(verbs) < 2 or verbs[1] not in DOCKER_SUB_OK:
                raise Unsafe("docker %s %s changes things; only listing and inspecting are allowed" % (verb, verbs[1] if len(verbs) > 1 else ""))
        elif verb is not None and verb not in safe:
            raise Unsafe("%s %s is not a read-only command" % (name, verb))
        return
    if name in ("apt-get", "dpkg", "yum", "dnf", "zypper", "pacman", "apk", "npm", "yarn"):
        raise Unsafe("%s can install, remove or change packages" % name)
    if name == "nft":
        verbs = _positional(args)
        if verbs[:1] != ["list"] or any(a in ("-f", "--file", "-i", "--interactive") for a in args):
            raise Unsafe("nft can change firewall rules (only `nft list ...` is allowed)")
    elif name in ("iptables", "ip6tables", "ebtables", "iptables-nft", "ip6tables-nft", "iptables-legacy", "ip6tables-legacy"):
        if (not any(a in ("-L", "-S", "-C", "--list", "--list-rules", "--check") for a in args)
                or any(a in FIREWALL_WRITE_FLAGS for a in args)):
            raise Unsafe("%s can change firewall rules (only -L, -S and -C are allowed)" % name)
    if name == "needrestart" and "-b" not in args:
        raise Unsafe("needrestart without -b can restart services")
    if name == "curl" and any(re.match(r"^-[A-Za-z]+$", a) and set(a[1:]) & set("oOJT") for a in args):
        raise Unsafe("curl can write files")
    if name == "wget" and "--spider" not in args:
        raise Unsafe("wget writes files (only wget --spider is allowed)")
    if name == "tar":
        mode = args[0].lstrip("-") if args and not args[0].startswith("--") else ""
        if "t" not in mode or set(mode) & set("xcurAd"):
            raise Unsafe("tar can write files (only listing, tar -t, is allowed)")
    if name == "sysctl" and any("=" in a for a in args):
        raise Unsafe("sysctl with name=value changes kernel settings")
    bad = BAD_ARGS.get(name)
    if bad:
        hit = [a for a in args if a in bad or any(a.startswith(b) and b.startswith("--") for b in bad)]
        if hit:
            raise Unsafe("%s %s can change data" % (name, hit[0]))
    path = argv[0] if os.sep in argv[0] else shutil.which(argv[0])
    if path and _looks_like_script(path):
        scan_script(path)


def _looks_like_script(path):
    try:
        with open(path, "rb") as fh:
            return fh.read(2) == b"#!"
    except OSError:
        return False


def scan_script(path):
    """A script runs more than its name says: refuse it if others can edit it, or it mentions a destructive command."""
    real = path if os.sep in path else (shutil.which(path) or path)
    try:
        st = os.stat(real)
        if not os.path.isfile(real):
            return
        with open(real, "rb") as fh:
            raw = fh.read(262144)
    except OSError:
        return  # not a readable file (a plain argument, or a binary we are not allowed to see)
    if st.st_mode & 0o022:
        raise Unsafe("script %s can be edited by others, so it cannot be trusted" % path)
    if b"\0" in raw[:4096]:
        return  # a binary
    text = raw.decode("utf-8", "replace")
    for number, line in enumerate(text.splitlines(), 1):
        if line.lstrip().startswith("#"):
            continue
        for word in re.findall(r"[A-Za-z0-9_.\-/]+", line):
            word = _base(word)
            for candidate in (word, word.rsplit(".", 1)[-1]):  # shutil.rmtree -> rmtree
                if candidate in SCRIPT_WORDS or candidate.startswith("mkfs"):
                    raise Unsafe("script %s uses %s on line %d" % (path, candidate, number))
