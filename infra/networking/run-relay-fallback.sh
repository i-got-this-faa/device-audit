#!/bin/sh
# NET05 #88: run the application mesh relay test with real blocked UDP.
# Only the fresh namespace owns these firewall rules. Never alter host networking.
set -eu
if [ "$#" -ne 0 ]; then
    echo 'usage: sh infra/networking/run-relay-fallback.sh' >&2
    exit 2
fi
for tool in unshare ip nft readlink; do
    command -v "$tool" >/dev/null
done
root=$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)
parent_net=$(readlink /proc/self/ns/net)
lab_dir=$(mktemp -d "${TMPDIR:-/tmp}/device-audit-relay.XXXXXX")
trap 'rm -rf "$lab_dir"' EXIT HUP INT TERM
# Compile while normal network access is still available.
(cd "$root" && "${GO:-go}" test -c -o "$lab_dir/mesh.test" ./networking/mesh)
unshare --user --map-root-user --net sh -eu -c '
    test "$(readlink /proc/self/ns/net)" != "$1" || {
        echo "refusing to configure the parent network namespace" >&2
        exit 1
    }
    ip link set lo up
    nft -f - <<EOF
table inet device_audit_relay {
    chain output {
        type filter hook output priority 0; policy accept;
        meta l4proto udp counter drop
    }
}
EOF
    echo "private_network_namespace=true all_output_udp=drop tcp_loopback=allowed"
    DEVICE_AUDIT_RELAY_UDP_BLOCKED=1 "$2" -test.run "^TestScopedRelay" -test.v -test.count=1 -test.timeout=150s
    nft list table inet device_audit_relay
' sh "$parent_net" "$lab_dir/mesh.test"
