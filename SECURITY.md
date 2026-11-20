# Security policy

Centinela runs on your servers, usually as root, and it holds a Telegram token, so reports about it are taken seriously.

## Reporting a vulnerability

Please don't open a public issue for a security problem.

Use GitHub's private reporting instead: go to the Security tab of this
repository and click "Report a vulnerability". If that is not available, open a
public issue that only says you have a security report, without details, and
I will contact you.

Please include:

- what you found and where (file, command, version)
- how to reproduce it
- what you think the impact is

I will answer as soon as I can. This is a one person open source project, so
I can't promise a fixed response time, but I will keep you updated and credit
you in the fix if you want.

## What is in scope

- Centinela leaking something it should not: the Telegram token or chat id, environment variables, or file contents, in messages, logs, error output or the state file
- a way to make Centinela change the system. The checks are meant to be read-only, and the only thing that writes is the setup wizard, to its own drop-in config file after you confirm
- a way to inject or run commands through data it reads, for example container, image or package names, config values, or what a remote page returns, including the commands it suggests in a message
- a way to make a check stay silent when it should report, such as getting around a trust list or freeze, or the deduplication hiding a finding that should be sent
- weaknesses in how custom checks and config drop-ins are loaded (the ownership and permission checks on `checks.d`)
- weaknesses in the release process: builds, checksums, the `.deb` and its maintainer scripts, and the GitHub workflows

## What is not in scope

- problems in the tools Centinela calls (apt, Docker, systemd, certbot, debsecan, nginx and so on): report those to their projects
- an attacker who already has root, or runs code as your user, on the machine (see "What it cannot do" in the README's Security model)
- compromises or vulnerabilities Centinela was never meant to detect: it is a periodic watchdog, not an intrusion detection system or a vulnerability scanner
- the security of Telegram itself: messages are sent through Telegram and are not end-to-end encrypted, so avoid putting secrets in your own custom check output

## Supported versions

1.0.0 is the first release. Only the latest release and the latest commit on `main` are looked at.

## Dependencies

Centinela has no runtime or build dependencies: it is the Python standard library only. The CI uses one pinned third-party action (`actions/checkout`, by commit) and one pinned container image (the official `debian` image, by digest); see `.github/workflows/` and `packaging/ci/verify-debian.sh`.
