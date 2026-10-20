# Live peer admission

This fork carries the core half of vpn-ui 1.9.4 live-admission changes.
It starts from bundled core commit
`bacaa47268398bbeeddc9c3c88e1ee143101da21`, the submodule revision in vpn-ui panel
commit `8044e0ad45c60149439546ea0fd99371a4d3c03d`.

The ten implementation/test files reproduce the previously reviewed core patch
byte for byte. That patch has SHA-256
`4080af4088499c7681b30ec15914cbeb2f4108b3fef9c168aec6b3b107abe181`.
This document is the only additional change in the source-import commit.
The companion panel is maintained at [hsklia/vpn-ui](https://github.com/hsklia/vpn-ui).

## Behavior

- Routing reload builds a complete candidate state before publishing it
  atomically. Concurrent requests retain a consistent routing snapshot; an
  invalid rule does not replace the working state.
- The WireGuard inbound implements live user admission through the existing
  HandlerService user API and serialized `PeerConfig` account. Valid retries
  reuse the same credentials; key, identity, or allowed-IP conflicts fail.
- Adding a peer does not replace the inbound or remove unrelated peers.
  The existing core process and active sessions can therefore remain running
  when the companion panel applies the matching live-admission path.

These changes do not deploy themselves or change an operator's running service.
A panel/node end-to-end result also depends on their admission, persistence,
account eligibility, and routing behavior.

## Verification scope

Run the focused core tests from this checkout with the Go version required by
`go.mod` and the router suite's standard `resources/geosite.dat` fixture:

```sh
go test ./app/router ./proxy/wireguard
go test -race ./app/router ./proxy/wireguard
```

The added tests cover invalid/repeated/concurrent routing reloads, retained
working routing state, canonical WireGuard accounts, idempotent admission,
credential/IP collisions, addressed removal, and encrypted existing-peer
continuity. They do not replace companion panel/node HTTP integration tests or
establish behavior for an unobserved production configuration.

The import includes source and tests only. It includes no staged database,
client private fixture, credentials, generated executable, or deployment step.
