# Xray-core (fork)

Fork of [XTLS/Xray-core](https://github.com/XTLS/Xray-core).

## Upstream version

Based on **Xray-core v26.4.17**, at upstream tag
[`v26.4.17`](https://github.com/XTLS/Xray-core/releases/tag/v26.4.17)
(commit [`b4650360`](https://github.com/XTLS/Xray-core/commit/b4650360)).

Pinned to **v26.4.17** on purpose: it is the last upstream release that still
supports the legacy `reverse` (bridge/portal) config. Upstream removed it in
**v26.4.25** (migrated to VLESS Reverse Proxy), so newer releases fail to start
with existing legacy-reverse configs.

## Changes in this fork

- **Shadowsocks: per-user `method` falls back to the server-level cipher.**
  When a Shadowsocks user entry omits `"method"`, the server-level `method`
  is inherited instead of failing with an unsupported-cipher error.
  (`infra/conf/shadowsocks.go`)

  Patch based on: [Sir-MmD/xray-core-ss-fix](https://github.com/Sir-MmD/xray-core-ss-fix)
  (`shadowsocks.patch`).

- **Per-account speed limiting, keyed by email.**
  Each account can be paced to a download and/or upload rate, optionally only
  after a byte threshold (a "limit after N GB" allowance). Limits are token
  buckets (`golang.org/x/time/rate`) wrapping the reader and writer in the
  dispatcher, so they apply to every Xray-native protocol without touching the
  proxies. (`common/speedlimit/`, gated in `app/dispatcher/default.go`)

- **Per-account IP limit (device cap), enforced at dispatch admission.**
  Each account can cap how many distinct source addresses use it at once. The
  count is a live-connection refcount per source IP, taken before any outbound
  is allocated, so it is immune to the NAT false-positives and the
  re-add-after-ban race of a log-scrape jail. Two strategies: `reject` refuses
  the newcomer, `accept` admits it and evicts the oldest connection by
  interrupting its pipes. Both dispatcher seams are gated (`Dispatch` for
  vmess/trojan/shadowsocks and mux sub-streams, `DispatchLink` for the rest).
  (`common/speedlimit/`, `app/dispatcher/default.go`)

  Both limits are driven by an external sidecar file whose path is given in the
  `XRAY_SPEEDLIMIT_FILE` environment variable. The core mtime-polls it and hot
  reloads (about every 2s), so limits can change under a live connection with no
  restart. The file lists, per account, the download/upload rates, the IP cap,
  and the strategy; the managing panel (vpn-ui) rewrites it on any change.

- **AnyTLS, inbound and outbound.**
  TLS-framed multiplexed proxy with a configurable padding scheme over the first
  records of a session, which is the part a censor can measure without decrypting
  anything. UDP is carried inside the same TLS session (UDP-over-TCP), so no
  second listener is involved. Built on
  [`anytls/sing-anytls`](https://github.com/anytls/sing-anytls).
  (`proxy/anytls/`, `infra/conf/anytls.go`)

- **TUIC v5, inbound and outbound.**
  QUIC-based, with both UDP relay carriers: `native` (one QUIC datagram per
  packet) and `quic` (a unidirectional stream per packet), plus UDP-over-stream.
  Congestion control is selectable per listener (cubic, BBR, New Reno). The
  server pins the `h3` ALPN, which is what makes it indistinguishable from HTTP/3.
  (`proxy/tuic/`, `transport/internet/tuic/`, `infra/conf/tuic.go`)

- **NaiveProxy, inbound and outbound.**
  HTTP CONNECT over HTTP/2 (TCP) and HTTP/3 (QUIC), with the reference client's
  Variant1 padding on the first frames in each direction and the
  `-connect-authority` header shape Cronet sends. Anything arriving without valid
  credentials is served a masquerade site (404, static files, reverse proxy or a
  fixed body), so the port answers a probe like an ordinary web server. Accounts
  carry their own Basic-auth `username`; when it is absent the account email is
  used, which is how accounts predating the field keep working.
  (`proxy/naive/`, `transport/internet/naive/`, `infra/conf/naive.go`)

  All three keep the account email as the identity handed to the dispatcher, so
  per-account statistics, the speed limiter, the IP limiter and online detection
  apply to them exactly as they do to the built-in protocols. A client the core
  cannot use (a duplicate credential, a colon in a Basic username, a missing
  password) is dropped with a warning rather than failing the build, because an
  error there makes Xray refuse the whole config and take every unrelated inbound
  on the host down with it.

## In short

This is a patched build of Xray-core, pinned to a version that still supports
legacy `reverse`. On top of that it adds per-account speed limiting and a
per-account IP limit (both keyed by email and driven by a hot-reloaded
`XRAY_SPEEDLIMIT_FILE` sidecar), and it no longer throws the `unsupported cipher
method` error for Shadowsocks inbounds: users defined without their own `method`
inherit the inbound's server-level cipher, so a valid Shadowsocks inbound config
works out of the box.

It also adds three protocols upstream does not carry, AnyTLS, TUIC v5 and
NaiveProxy, each as both an inbound and an outbound, and each wired through the
same dispatcher seam as the built-in protocols so they inherit per-account
statistics, speed limiting, IP limiting and online detection rather than needing
a second core alongside this one.

## One-line Compilation

### Windows (PowerShell)

```powershell
$env:CGO_ENABLED=0
go build -o xray.exe -trimpath -buildvcs=false -ldflags="-s -w -buildid=" -v ./main
```

### Linux / macOS

```bash
CGO_ENABLED=0 go build -o xray -trimpath -buildvcs=false -ldflags="-s -w -buildid=" -v ./main
```

### Reproducible Releases

Make sure that you are using the same Go version, and remember to set the git commit id (7 bytes):

```bash
CGO_ENABLED=0 go build -o xray -trimpath -buildvcs=false -gcflags="all=-l=4" -ldflags="-X github.com/xtls/xray-core/core.build=REPLACE -s -w -buildid=" -v ./main
```

For Android:

```bash
GOOS=android GOARCH=arm64 CGO_ENABLED=1 CC=/path/to/aarch64-linux-android24-clang go build -o xray -trimpath -buildvcs=false -gcflags="all=-l=4" -ldflags="-X github.com/xtls/xray-core/core.build=REPLACE -s -w -buildid= -checklinkname=0" -v ./main
GOOS=android GOARCH=amd64 CGO_ENABLED=1 CC=/path/to/x86_64-linux-android24-clang go build -o xray -trimpath -buildvcs=false -gcflags="all=-l=4" -ldflags="-X github.com/xtls/xray-core/core.build=REPLACE -s -w -buildid= -checklinkname=0" -v ./main
```

If you are compiling a 32-bit MIPS/MIPSLE target, use this command instead:

```bash
CGO_ENABLED=0 go build -o xray -trimpath -buildvcs=false -gcflags="-l=4" -ldflags="-X github.com/xtls/xray-core/core.build=REPLACE -s -w -buildid=" -v ./main
```
