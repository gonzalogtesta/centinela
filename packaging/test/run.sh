#!/usr/bin/env bash
# Run the Linux test matrix: every distribution x architecture x variant, each in its own container.
#
#   packaging/test/run.sh                       everything (8 containers; the other architecture runs emulated: slow)
#   packaging/test/run.sh --platform linux/amd64 --distro debian --variant ufw
#   packaging/test/run.sh --verbose             show every line, not only the failures
#
# Needs Docker with buildx/QEMU for the architecture you do not have (Docker Desktop has them) and network access
# inside the build (apt). Nothing is installed on the host and nothing in the container can reach your machine:
# the containers only get the two capabilities the scenarios need (NET_ADMIN, DAC_READ_SEARCH).
set -uo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
platforms="linux/amd64 linux/arm64"
distros="debian ubuntu"
variants="plain ufw"
verbose=no

while [ $# -gt 0 ]; do
    case "$1" in
        --platform) platforms="$2"; shift 2 ;;
        --distro)   distros="$2"; shift 2 ;;
        --variant)  variants="$2"; shift 2 ;;
        --verbose|-v) verbose=yes; shift ;;
        -h|--help)  sed -n '2,11p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
        *) echo "unknown option: $1 (try --help)" >&2; exit 2 ;;
    esac
done

image_for() {
    case "$1" in
        debian) echo "debian:bookworm-slim" ;;   # Python 3.11, the minimum supported
        ubuntu) echo "ubuntu:24.04" ;;           # Python 3.12
        *) echo "$1" ;;                          # anything else you name: a full image reference
    esac
}

logs="$(mktemp -d)"
results=()
failed=0
for platform in $platforms; do
    for distro in $distros; do
        for variant in $variants; do
            name="$distro $platform $variant"
            tag="centinela-test:${distro//[^a-z0-9]/-}-${platform#linux/}-$variant"
            log="$logs/${distro//[^a-z0-9]/-}-${platform#linux/}-$variant.log"
            echo "== $name"
            if ! docker build -q --platform "$platform" -f "$root/packaging/test/Dockerfile" \
                    --build-arg "BASE=$(image_for "$distro")" --build-arg "VARIANT=$variant" -t "$tag" "$root" >"$log" 2>&1; then
                echo "   build failed:"; tail -5 "$log" | sed 's/^/   /'
                results+=("BUILD FAILED  $name"); failed=$((failed + 1)); continue
            fi
            docker run --rm --platform "$platform" --cap-add NET_ADMIN --cap-add DAC_READ_SEARCH "$tag" >"$log" 2>&1
            code=$?
            if [ "$verbose" = yes ]; then cat "$log"; else grep -E "^centinela matrix|FAIL|^ +\|" "$log" | sed 's/^/   /'; fi
            summary="$(grep -E '^(PASSED|FAILED)' "$log" | tail -1)"
            if [ $code -eq 0 ]; then results+=("passed        $name  ($summary)"); else
                results+=("FAILED        $name  (${summary:-no summary; see $log})"); failed=$((failed + 1)); fi
        done
    done
done

echo
echo "== matrix"
printf '%s\n' "${results[@]}"
echo "logs: $logs"
[ "$failed" -eq 0 ]
