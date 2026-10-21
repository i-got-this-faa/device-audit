#!/bin/sh
# Real peer processes; optional Linux syscall counts contain no payloads or IPs.
set -eu
cd "$(dirname "$0")"
if [ "$#" -eq 0 ]; then
    exec "${GO:-go}" test -run '^TestDirectLab$' -v -count=1 -timeout=150s .
fi
if [ "$#" -ne 1 ] || [ "$1" != "--trace" ]; then
    echo 'usage: run-proof.sh [--trace]' >&2
    exit 2
fi
command -v strace >/dev/null
trace_dir=$(mktemp -d "${TMPDIR:-/tmp}/device-audit-tailcat.XXXXXX")
trap 'rm -rf "$trace_dir"' EXIT HUP INT TERM
# No read/write tracing. -s 0 suppresses network payloads; the temporary trace
# contains socket addresses and is removed after emitting aggregate counts.
strace -f -qq -yy -s 0 -e status=successful \
    -e trace=sendto,recvfrom,sendmsg,recvmsg,sendmmsg,recvmmsg \
    -o "$trace_dir/sockets.trace" \
    "${GO:-go}" test -run '^TestDirectLab$' -v -count=1 -timeout=150s .
awk '
    /send(to|msg|mmsg)\(.*UDP.* = [1-9]/ { sent++ }
    /recv(from|msg|mmsg)\(.*UDP.* = [1-9]/ { received++ }
    END {
        printf "successful_udp_send_syscalls=%d successful_udp_receive_syscalls=%d\n", sent, received
        if (sent == 0 || received == 0) exit 1
    }
' "$trace_dir/sockets.trace"
