# PeerAgent Companion

A minimal Android app that turns a phone into a controllable media-session
peer on a private [WireGuard](https://www.wireguard.com/) mesh: a small
HTTP server exposing `play`/`pause`/`next`/`prev`/`seek`/`volume` against
whatever's currently playing, reachable only from your own tunnel.

No Gradle, no Play Services, no third-party dependencies. Built with the
plain Android SDK command-line tools (`aapt2`, `kotlinc`, `d8`,
`apksigner`) so it can be compiled from a normal Linux shell — including
directly on-device from Termux, which is what it was originally built for.

## Why

Most "control my phone's music from my desktop" setups either go through a
cloud service or require rooting the phone. This app assumes neither: it
just needs Notification access (to read the active media session) and a
WireGuard tunnel that already reaches the phone. Everything else — auth,
CORS/browser defenses, source-IP checks — is handled in ~250 lines of
hand-rolled `HttpServer`, described in [docs/design.md](docs/design.md).

## Requirements

- A WireGuard tunnel that reaches the phone (this app does not set one up
  for you — bring your own).
- Android 10+ (`minSdkVersion 29`).
- To build: `aapt2`, `kotlinc`, `d8`, `apksigner`, and an `android.jar` for
  a recent platform (see `build.sh` for the exact paths it expects — adjust
  them for your own toolchain layout).

## Build & install

```sh
bash build.sh                          # produces build/peeragent-signed.apk
adb install -r build/peeragent-signed.apk
```

On first launch: grant Notification access when prompted (Settings →
Apps → PeerAgent Companion → Notifications → allow), then tap "Start
bridge service."

## API

All endpoints require an `X-Peer-Agent: 1` header and reject any request
carrying an `Origin` header. See [docs/design.md](docs/design.md) for the
full security model.

| Method | Path | |
| --- | --- | --- |
| GET | `/status` | Current playback state as JSON |
| POST | `/command/play` \| `pause` \| `next` \| `prev` \| `seek-fwd` \| `seek-back` \| `volume-up` \| `volume-down` | |
| POST | `/command/seek-to?ms=<n>` | Seek to an absolute position |
| GET | `/events` | Server-sent events (currently unused by any client) |

## License

MIT — see [LICENSE](LICENSE).
