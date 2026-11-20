#!/usr/bin/env bash
# Verify the project on Debian 12 itself: the minimum supported Python (3.11) and the real dpkg.
# Used by CI, and runnable anywhere with Docker:  packaging/ci/verify-debian.sh
#
# The image is pinned by digest (a dated snapshot of the official debian image). Override
# with DEBIAN_IMAGE=... to try another one. Needs network access inside the container
# (apt installs python3 from the Debian mirrors).
set -euo pipefail

IMAGE="${DEBIAN_IMAGE:-debian:bookworm-20261104-slim@sha256:734a72b3d6142a71993b4bc580ca01d8ca687f77a2c422d96a961d3376b179bc}"
root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"

docker run --rm -v "$root:/src:ro" "$IMAGE" sh -eu -c '
  apt-get update -qq
  apt-get install -y -qq --no-install-recommends python3 ca-certificates >/dev/null

  mkdir /work
  tar -C /src --exclude=.git --exclude=.venv --exclude=dist --exclude=.idea -cf - . | tar -C /work -xf -
  cd /work

  echo "== python"; python3 --version
  echo "== unit tests"; python3 -m unittest discover -s tests
  echo "== build"; python3 build.py
  (cd dist && sha256sum -c SHA256SUMS)

  echo "== install the .deb with the real dpkg"
  dpkg -i dist/centinela_*_all.deb
  dpkg -V centinela
  test -x /usr/bin/centinela
  test -f /lib/systemd/system/centinela@.service
  test -f /lib/systemd/system/centinela-daily.timer
  test -f /etc/centinela/centinela.toml
  centinela --version
  centinela --list-modules --config /nonexistent/centinela.toml > /dev/null

  echo "== purge removes it"
  dpkg -P centinela
  test ! -e /usr/bin/centinela
  test ! -e /etc/centinela/centinela.toml
  echo "debian 12 verification passed"
'
