"""Example check: run a read-only command, compare the number it prints with a limit.

Here: the number of failed systemd units. Copy it and change COMMAND and the message
to watch anything a command can count (queue length, open files, rows in a file).

Install:  centinela --print example-command-threshold | sudo tee /etc/centinela/checks.d/failed_units.py
Config:   [failed_units]
          max = 0        # warn when more units than this have failed
"""
from centinela.core import WARN, Finding, Skip

NAME = "failed_units"
DESC = "number of failed systemd units stays within a limit"
COMMAND = ["systemctl", "list-units", "--failed", "--no-legend", "--plain"]


def applicable(cfg):
    return True


def run(ctx):
    rc, out, err = ctx.run(COMMAND)
    if rc == 127:
        raise Skip("systemctl not available")  # not a systemd host: say nothing
    if rc != 0:
        raise Skip("systemctl failed: %s" % err.strip()[:100])
    failed = [line.split()[0] for line in out.splitlines() if line.strip()]
    if len(failed) <= ctx.cfg.int("failed_units", "max", 0):
        return []
    return [Finding(NAME, "count", WARN, "%d failed systemd units: %s" % (len(failed), ", ".join(failed[:5])),
                    "systemctl --failed")]
