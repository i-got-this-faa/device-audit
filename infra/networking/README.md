# Relay and bootstrap deployment surface

Reserve this directory for a self-hosted DERP relay, DERP map publication,
TLS/bootstrap configuration, persisted server/endpoint network identity,
firewall rules and a reproducible connectivity lab. No relay executable or
deployment is included because Shepherd's original relay is a placeholder.

DERP relays encrypted WireGuard traffic; it does not authenticate application
requests or validate device reports. Verify authentication/rate-limit options
against the exact upstream revision. Direct UDP, relay-only and offline modes
need separate integration evidence. Production bootstrap requires HTTPS and
authenticated enrollment; do not expose the development controller publicly.
