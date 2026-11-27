# Test image for the Linux matrix: the single-file build installed the way a user installs it.
#   VARIANT=plain  no firewall tools (a Raspberry Pi without ufw, a minimal VPS)
#   VARIANT=ufw    ufw, iptables and nftables installed
# Build from the repository root:
#   docker build -f packaging/test/Dockerfile --build-arg VARIANT=ufw --build-arg BASE=ubuntu:24.04 .
# packaging/test/run.sh does that for every architecture, distribution and variant.
ARG BASE=debian:bookworm-slim
ARG VARIANT=plain

FROM ${BASE} AS os-plain
ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update -qq \
 && apt-get install -y -qq --no-install-recommends python3 ca-certificates util-linux iproute2 procps >/dev/null \
 && rm -rf /var/lib/apt/lists/*

FROM os-plain AS os-ufw
RUN apt-get update -qq \
 && apt-get install -y -qq --no-install-recommends ufw iptables nftables >/dev/null \
 && rm -rf /var/lib/apt/lists/*

FROM os-${VARIANT} AS final
COPY . /src
RUN cd /src && python3 build.py --out /tmp/dist >/dev/null \
 && install -m 0755 /tmp/dist/centinela /usr/local/bin/centinela \
 && useradd --system --no-create-home --shell /usr/sbin/nologin centinela
CMD ["sh", "/src/packaging/test/scenarios.sh"]
