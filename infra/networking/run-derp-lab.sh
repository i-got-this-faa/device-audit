#!/bin/sh
# Only the fresh namespace owns these firewall rules. Never alter host networking.
set -eu
if [ "$#" -ne 0 ]; then
    echo 'usage: sh infra/networking/run-derp-lab.sh' >&2
    exit 2
fi
for tool in unshare ip nft readlink; do
    command -v "$tool" >/dev/null
done
root=$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)
parent_net=$(readlink /proc/self/ns/net)
lab_dir=$(mktemp -d "${TMPDIR:-/tmp}/device-audit-derp.XXXXXX")
trap 'rm -rf "$lab_dir"' EXIT HUP INT TERM
# Resolve modules and compile while normal network access is still available.
# No daemon, host firewall changes, TUN device, or container engine is required.
(cd "$root/networking/tailcat-lab" && "${GO:-go}" test -c -o "$lab_dir/relay.test" .)
unshare --user --map-root-user --net sh -eu -c '
    test "$(readlink /proc/self/ns/net)" != "$1" || {
        echo "refusing to configure the parent network namespace" >&2
        exit 1
    }
    ip link set lo up
    nft -f - <<EOF
table inet device_audit_derp {
    chain output {
        type filter hook output priority 0; policy accept;
        meta l4proto udp counter drop
    }
}
EOF
    echo "private_network_namespace=true all_output_udp=drop tcp_loopback=allowed"
    DEVICE_AUDIT_DERP_LAB=1 DEVICE_AUDIT_DERP_PARENT_NETNS="$1" "$2" -test.run "^TestDERPRelayLab$" -test.v -test.timeout=150s
    nft list table inet device_audit_derp
' sh "$parent_net" "$lab_dir/relay.test"
