"""Example check: critical if a host:port does not accept TCP connections.

Use it for a local service (127.0.0.1:6379) or to watch other machines from this one,
e.g. a node answering on its SSH port.

Install:  centinela --print example-tcp-port | sudo tee /etc/centinela/checks.d/tcp_port.py
Config:   [tcp_port]
          targets = ["127.0.0.1:6379", "node2.local:22"]
"""
import shlex
import socket

from centinela.core import CRIT, Finding

NAME = "tcp_port"
DESC = "listed host:port pairs accept TCP connections"


def applicable(cfg):
    return bool(cfg.list("tcp_port", "targets"))  # no config, no check


def run(ctx):
    findings = []
    for target in ctx.cfg.list("tcp_port", "targets"):
        host, _, port = target.rpartition(":")
        try:
            socket.create_connection((host, int(port)), timeout=3).close()
        except (OSError, ValueError):
            findings.append(Finding(NAME, target, CRIT, "cannot connect to %s" % target,
                                    "nc -vz -w 3 %s %s" % (shlex.quote(host), shlex.quote(port))))
    return findings
