#!/bin/sh
# Scenarios run inside the test image (packaging/test/Dockerfile), as root and as the unprivileged `centinela`
# account with the capabilities each install mode gives it. Needs the container to have
# --cap-add NET_ADMIN --cap-add DAC_READ_SEARCH (run.sh does that).
#
# Every line is "ok" or "FAIL"; the script exits 1 if any failed. What the container cannot show (systemd units,
# a real journal, a real Docker daemon, Docker Hub) is stubbed or left to a real machine: see the README.
set -u

total=0
failed=0
skipped=0
ok()  { total=$((total + 1)); echo "  ok    $1"; }
bad() { total=$((total + 1)); failed=$((failed + 1)); echo "  FAIL  $1"; printf '%s\n' "$2" | sed 's/^/          | /' | head -12; }
skip() { skipped=$((skipped + 1)); echo "  skip  $1"; }
section() { echo; echo "== $1"; }

# expect "name" "extended regex" command...   (stdout and stderr together)
expect() {
    name=$1; pattern=$2; shift 2
    out=$("$@" 2>&1)
    if printf '%s' "$out" | grep -Eq -- "$pattern"; then ok "$name"; else bad "$name" "wanted /$pattern/ in: $out"; fi
}
refute() {
    name=$1; pattern=$2; shift 2
    out=$("$@" 2>&1)
    if printf '%s' "$out" | grep -Eq -- "$pattern"; then bad "$name" "did not want /$pattern/ in: $out"; else ok "$name"; fi
}

# Who runs it. restricted = the account of the Restricted install (one capability); advanced = plus CAP_NET_ADMIN;
# nobody = an account with no capability at all (a restricted install that lost its capability).
as_root()       { "$@"; }
as_restricted() { setpriv --reuid=centinela --regid=centinela --clear-groups --inh-caps=+dac_read_search --ambient-caps=+dac_read_search "$@"; }
as_advanced()   { setpriv --reuid=centinela --regid=centinela --clear-groups --inh-caps=+dac_read_search,+net_admin --ambient-caps=+dac_read_search,+net_admin "$@"; }
as_nobody()     { setpriv --reuid=centinela --regid=centinela --clear-groups "$@"; }

W=/tmp/scn
rm -rf "$W"; mkdir -p "$W"; chmod 755 "$W"
CONF="$W/centinela.toml"
STATE="$W/state/state.json"
mkdir -p "$W/state"; chmod 755 "$W/state"
printf '[general]\nextra_dir = "%s/checks.d"\nstate_file = "%s"\n' "$W" "$STATE" > "$CONF"
cen() { centinela --config "$CONF" --state "$STATE" "$@"; }
dry() { cen --dry-run --no-dedupe "$@"; }
STUBS="$W/stubs"; mkdir -p "$STUBS"
HAVE_UFW=no; command -v ufw >/dev/null 2>&1 && HAVE_UFW=yes

echo "centinela matrix: $(. /etc/os-release; echo "$PRETTY_NAME"), $(uname -m), $(python3 --version), ufw=$HAVE_UFW"

section "install"
expect "single file runs and says its version" '^centinela [0-9]+\.[0-9]+\.[0-9]+' centinela --version
expect "lists the split checks" 'ufw +.*\n?.*' cen --list-modules
for name in ufw fwrules docker docker-images oom memory load disk; do
    expect "module $name is known" "^$name " cen --list-modules
done
printf '#!/bin/sh\nexit 1\n' > "$STUBS/docker"; chmod 755 "$STUBS/docker"   # a docker CLI exists, so the docker checks apply
expect "frequent mode keeps the Docker Hub check slow" '^docker-images +slow' env PATH="$STUBS:$PATH" centinela --config "$CONF" --mode frequent --list-modules
expect "frequent mode runs the container check" '^docker +run' env PATH="$STUBS:$PATH" centinela --config "$CONF" --mode frequent --list-modules
rm -f "$STUBS/docker"
expect "frequent mode runs the firewall checks" '^ufw +(run|n/a)' cen --mode frequent --list-modules
refute "built-in checks load without a traceback" 'Traceback' cen --list-modules

section "the repository's own tests, on this system"
out=$(cd /src && python3 -W ignore -m unittest discover -s tests 2>&1); rc=$?
if [ $rc -eq 0 ]; then ok "unit tests ($(printf '%s' "$out" | grep -E '^Ran '))"; else bad "unit tests" "$out"; fi

section "resource checks on this kernel"
for who in as_root as_restricted as_nobody; do
    out=$($who centinela --config "$CONF" --state "$STATE" --only disk,memory,load --dry-run --no-dedupe 2>&1); rc=$?
    if [ $rc -eq 0 ] && ! printf '%s' "$out" | grep -q Traceback; then ok "disk, memory and load run ($who)"; else bad "disk, memory and load ($who)" "rc=$rc $out"; fi
done

section "ufw and the firewall rules"
# Under emulation (arm64 on an amd64 host) the kernel's netfilter is not reachable: ufw cannot be enabled and
# iptables-save fails with "Protocol not supported". That is the emulator, not centinela: say so and skip.
NETFILTER=no; iptables-save >/dev/null 2>&1 && NETFILTER=yes
if [ "$HAVE_UFW" = yes ] && [ "$NETFILTER" = no ]; then
    skip "ufw and the firewall rules: no usable netfilter here (emulated kernel?); run on a native host"
elif [ "$HAVE_UFW" = yes ]; then
    ufw --force disable >/dev/null 2>&1
    expect "root: inactive ufw is critical" '\[CRIT\] ufw is not active' as_root centinela --config "$CONF" --state "$STATE" --only ufw --dry-run --no-dedupe
    expect "restricted: reads ENABLED=no from the config" '\[CRIT\] ufw is disabled in /etc/ufw/ufw.conf' as_restricted centinela --config "$CONF" --state "$STATE" --only ufw --dry-run --no-dedupe
    expect "restricted: names the limit on stderr" 'not root, reading /etc/ufw/ufw.conf' as_restricted centinela --config "$CONF" --state "$STATE" --only ufw --dry-run --no-dedupe

    ufw --force enable >/dev/null 2>&1
    expect "root: active ufw says nothing" 'nothing to report' as_root centinela --config "$CONF" --state "$STATE" --only ufw --dry-run --no-dedupe
    expect "restricted: ENABLED=yes says nothing" 'nothing to report' as_restricted centinela --config "$CONF" --state "$STATE" --only ufw --dry-run --no-dedupe

    expect "fwrules is silent until you approve" 'nothing to report' as_root centinela --config "$CONF" --state "$STATE" --only fwrules --dry-run --no-dedupe
    expect "root can read the live rules" '.' as_root centinela firewall show --config "$CONF" --state "$STATE"
    expect "approve saves them" 'Approved' as_root centinela firewall approve --config "$CONF" --state "$STATE"
    expect "unchanged rules say nothing" 'nothing to report' as_root centinela --config "$CONF" --state "$STATE" --only fwrules --dry-run --no-dedupe

    ufw allow 8080/tcp >/dev/null 2>&1
    expect "root: a new rule is critical" '\[CRIT\] firewall rules differ from the approved set' as_root centinela --config "$CONF" --state "$STATE" --only fwrules --dry-run --no-dedupe
    expect "advanced (CAP_NET_ADMIN): the new rule is seen too" '\[CRIT\] firewall rules differ' as_advanced centinela --config "$CONF" --state "$STATE" --only fwrules --dry-run --no-dedupe
    expect "restricted (no CAP_NET_ADMIN): says it cannot read, not that all is well" '\[WARN\] approved firewall rules cannot be read now' as_restricted centinela --config "$CONF" --state "$STATE" --only fwrules --dry-run --no-dedupe
    expect "the diff names the line" '8080' as_root centinela firewall diff --config "$CONF" --state "$STATE"
    expect "approving again accepts the change" 'Approved' as_root centinela firewall approve --config "$CONF" --state "$STATE"
    expect "and it is quiet again" 'nothing to report' as_root centinela --config "$CONF" --state "$STATE" --only fwrules --dry-run --no-dedupe
    ufw --force disable >/dev/null 2>&1
else
    expect "ufw does not apply without ufw" '^ufw +n/a' cen --list-modules
    expect "fwrules does not apply without ufw, nft or an approved set" '^fwrules +n/a' cen --list-modules
    expect "no ufw, no complaint" 'nothing to report' dry --only ufw,fwrules
    # An approved set that outlived the tools must be reported, not silently ignored.
    printf 'table ip filter {}\n' > "$W/state/firewall.rules"
    expect "approved rules that cannot be read are reported" '\[WARN\] approved firewall rules cannot be read now' as_root centinela --config "$CONF" --state "$STATE" --only fwrules --dry-run --no-dedupe
    rm -f "$W/state/firewall.rules"
fi

section "docker from its files (no socket)"
cat > "$STUBS/docker" <<'EOF'
#!/bin/sh
echo "permission denied while trying to connect to the Docker daemon socket at unix:///var/run/docker.sock" >&2
exit 1
EOF
chmod 755 "$STUBS/docker"
ROOT="$W/dockerroot"; mkdir -p "$ROOT/containers/aaaaaaaaaaaa"
python3 - "$ROOT" <<'EOF'
import json, sys
cid = "a" * 64
conf = {"ID": cid, "Name": "/web", "State": {"Running": False, "ExitCode": 1, "StartedAt": "2026-11-01T00:00:00Z",
        "FinishedAt": "2026-11-02T00:00:00Z"}, "Config": {"Image": "redis:7.4", "Labels": {}}}
json.dump(conf, open(sys.argv[1] + "/containers/aaaaaaaaaaaa/config.v2.json", "w"))
EOF
chmod -R go-rwx "$ROOT"   # root-only, like /var/lib/docker: only a capability can read it
chmod 711 "$W"
printf '[general]\nextra_dir = "%s/checks.d"\n[docker]\ndata_root = "%s"\nignore_images = ["*"]\n' "$W" "$ROOT" > "$W/docker.toml"
dcen() { PATH="$STUBS:$PATH" centinela --config "$W/docker.toml" --state "$STATE" --dry-run --no-dedupe "$@"; }
expect "restricted: a stopped container is found from Docker's files" '\[CRIT\] container web is exited' as_restricted env PATH="$STUBS:$PATH" centinela --config "$W/docker.toml" --state "$STATE" --only docker --dry-run --no-dedupe
expect "restricted: says it read files, not the socket" 'no socket access, reading container files' as_restricted env PATH="$STUBS:$PATH" centinela --config "$W/docker.toml" --state "$STATE" --only docker --dry-run --no-dedupe
expect "root: the same stopped container, same finding" '\[CRIT\] container web is exited' as_root env PATH="$STUBS:$PATH" centinela --config "$W/docker.toml" --state "$STATE" --only docker --dry-run --no-dedupe
expect "docker-images does not repeat the container report" 'nothing to report' as_restricted env PATH="$STUBS:$PATH" centinela --config "$W/docker.toml" --state "$STATE" --only docker-images --dry-run --no-dedupe
expect "no capability: the files cannot be read, and it says so" 'cannot be read|could not run|COULD NOT RUN' as_nobody env PATH="$STUBS:$PATH" centinela --config "$W/docker.toml" --state "$STATE" --coverage
expect "no docker installed: both docker checks stay out of the way" '^docker +n/a' cen --list-modules

section "the kernel log (oom)"
cat > "$STUBS/journalctl" <<EOF
#!/bin/sh
echo "$(date -u +%Y-%m-%dT%H:%M:%S+0000) host kernel: Out of memory: Killed process 4242 (java) total-vm:1024kB, anon-rss:512kB"
EOF
chmod 755 "$STUBS/journalctl"
expect "an OOM kill in the log is reported" 'java' as_root env PATH="$STUBS:$PATH" centinela --config "$CONF" --state "$STATE" --only oom --dry-run --no-dedupe
expect "without the journal or dmesg access it says what is missing" 'COULD NOT RUN: cannot read the kernel log' as_nobody centinela --config "$CONF" --state "$STATE" --coverage

section "migrating a 1.0 config"
mkdir -p "$W/old"
cat > "$W/old/centinela.toml" <<EOF
[general]
extra_dir = "$W/checks.d"
disable = ["firewall", "docker", "disk"]
[notify.routes]
firewall = ["ntfy"]
EOF
expect "migrate names the split" 'Two checks were split in two' centinela migrate --config "$W/old/centinela.toml"
expect "migrate --write adds the drop-in" 'Wrote .*06-module-names.toml' centinela migrate --config "$W/old/centinela.toml" --write
expect "the drop-in carries the new names" 'fwrules' cat "$W/old/centinela.d/06-module-names.toml"
refute "and the old config no longer warns" 'config-names' centinela --config "$W/old/centinela.toml" --state "$STATE" --only disk --dry-run --no-dedupe

section "a check made of several files"
expect "the example package installs" 'Installed into' sh -c "centinela --print example-package | sh -s $W/checks.d"
expect "and shows up as a module" '^backup_status ' cen --list-modules
expect "its test can be printed" 'class BackupStatusTests' centinela --print example-package-test
centinela --print example-package-test > "$W/test_backup_status.py"
expect "and passes against the installed check" '^OK' sh -c "cd $W && PYTHONPATH=/usr/local/bin/centinela:$W/checks.d python3 -m unittest test_backup_status 2>&1 | tail -1"
printf '[backup_status]\nfile = "%s/none.json"\n' "$W" >> "$CONF"
expect "a missing status file is critical" '\[CRIT\] cannot read' dry --only backup_status

section "who can run what (for the record)"
for who in as_root as_restricted as_advanced as_nobody; do
    echo "-- $who"
    $who centinela --config "$CONF" --state "$STATE" --coverage 2>&1 | sed 's/^/   /'
done

echo
note=""; [ "$skipped" -eq 0 ] || note=" ($skipped skipped)"
if [ "$failed" -eq 0 ]; then echo "PASSED: $total checks$note"; else echo "FAILED: $failed of $total checks$note"; fi
[ "$failed" -eq 0 ]
