# Design notes

This app grew out of a broader "peer-agent" system that let devices on a
private WireGuard mesh trigger actions on each other over a small,
deliberately unauthenticated-at-the-application-layer HTTP API — the
WireGuard source address itself is the credential. On Android that idea hit
a wall: an unrooted phone can run WireGuard fine, but a plain app UID can
neither enumerate nor bind the VPN's tun interface, and a background Python
process (peer-agent running under Termux) gets killed by Android the moment
Termux isn't in the foreground. That was the actual complaint that led here:
the phone-side listener would quietly stop working after the terminal was
swiped away, with no way to notice short of testing it.

The fix was to stop treating the phone as "just another peer" and instead
give it a real Android app: a foreground service backed by
`NotificationListenerService` access (which Android will keep alive far more
reliably than a bare process), carrying its own security perimeter directly
in `BridgeHttpServer.kt` rather than relying on a separate daemon in front
of it.

## Companion app

`dev.local.peeragent` ("PeerAgent Companion"). No Gradle — just
`aapt2` → `kotlinc` → `d8` → `apksigner`, all invoked directly (see
`build.sh`). It holds `BIND_NOTIFICATION_LISTENER_SERVICE` access (granted
once, manually, in Settings) and runs a hand-rolled HTTP server exposing
media-session control: `GET /status`, `POST /command/{play,pause,next,prev,
seek-fwd,seek-back,seek-to,volume-up,volume-down}`, `GET /events` (SSE,
currently unused).

It binds **`0.0.0.0:<port>`**, not a specific interface, and carries the
security perimeter itself in `BridgeHttpServer.kt`:

- **Bound to `0.0.0.0`, not the tunnel address.** An unprivileged app can't
  enumerate or bind WireGuard's `VpnService` tun interface (`ip addr` shows
  nothing for an app UID), and a wildcard socket survives the tunnel
  reconnecting. The source-address check below stands in for the
  interface-scoped firewall rule a Linux peer could otherwise have — the
  phone can't.
- **Source address must be within the configured tunnel subnet, or
  loopback** — otherwise 403. Handles IPv4-mapped IPv6.
- **A required non-simple header, plus method restrictions.** POST/GET only;
  anything else (including `OPTIONS`) → 405 with no CORS headers. Any
  request carrying `Origin` → 403. This defends against the
  browser-confused-deputy case: every peer on the mesh also runs a browser,
  and a web page loaded there could otherwise fire a request at the phone's
  IP. Same-origin policy blocks reading the *response*, not sending the
  *request*, so a plain `<img>` tag can trigger a GET, and a `<form>` POST
  needs no preflight but can't set custom headers and does send `Origin` -
  which this rejects outright.
- **No token.** WireGuard authenticates who can reach the tunnel in the
  first place; these checks only cover what WireGuard structurally can't -
  the browser case, and the socket being reachable off-tunnel on a
  firewall-less host.

The only caller in the setup this was built for is a small script on the
desktop peer that proxies local media-key/MPRIS commands to this app's HTTP
API over the tunnel, so external tools (widgets, status bars) can control
phone playback from another device.

To rebuild and redeploy after an edit: `bash build.sh`, then either
`adb install -r` (needs Wireless debugging paired) or copy the APK to the
device's Downloads folder and tap it. A same-signature reinstall preserves
notification access and any Restricted Settings unlock; a fresh
`adb uninstall` does not - redo both after one of those.

## Device-level things that had to be unlocked

Two things, on a hardened Android build (GrapheneOS in the setup this was
developed on) — neither is a bug in the app:

- **Restricted Settings** (stock Android 13+, not hardening-specific): a
  sideloaded app can't be granted Notification access until you go
  Settings → Apps → PeerAgent Companion → ⋮ → *Allow restricted settings*.
- **Exploit protection / hardened-runtime compatibility mode** (present on
  some hardened Android builds): without it, Binder-heavy calls from a
  plain app UID can silently hang rather than throw - this made
  `startForeground()` look broken for a long time before the real bug (see
  below) was found. Look for an equivalent toggle under the app's settings
  if notification-listener-backed foreground services misbehave similarly.

Also: `POST_NOTIFICATIONS` is a runtime permission on API 33+, not just a
manifest entry - `MainActivity` requests it on launch. Skipping that grant
alone is enough to make the foreground promotion misbehave.

## Driving Termux headlessly from another host

Useful if you're editing/building from a desktop rather than on-device,
over the same WireGuard mesh this app is designed for:

- **sshfs**, for editing files directly: Termux's `sshd` needs
  `Subsystem sftp <path>/libexec/sftp-server` uncommented in
  `$PREFIX/etc/ssh/sshd_config` (commented out by default) before sshfs will
  mount at all - it fails with a bare "read: Connection reset by peer"
  otherwise, no hint that it's the sftp subsystem specifically.
- **adb over Wireless debugging**, for anything `pm`/`dumpsys`/`logcat`-shaped
  a plain app UID (Termux included) is refused for the same reason a
  non-shell app is refused on stock Android - `adb`'s `shell` UID is
  exempted, which is the whole reason to reach for it. Pairing needs a
  fresh 6-digit code each time (`adb pair <ip:pairing-port> <code>`), then
  `adb connect <ip:connect-port>` - a **different** port than the pairing
  one, and both change on reconnect. Turn Wireless debugging back off when
  done; it's a real network-reachable service while it's on, though a
  completed pairing stays trusted across future sessions.

## The bug that cost the most time debugging this

Not a permissions issue at all, in the end: an earlier version of the build
script located the Kotlin standard library with
`find $PREFIX/opt/kotlin -iname "kotlin-stdlib*.jar" | head -1`, which
matched `kotlin-stdlib-jdk7.jar` (a ~1KB extension shim) instead of the real
`kotlin-stdlib.jar` (~750KB, holds `kotlin.jvm.internal.Intrinsics` and the
rest of the Kotlin runtime). Every Kotlin method's compiler-injected
null-check needs `Intrinsics`, so the app crash-looped on **every** launch,
every ~1s, with `NoClassDefFoundError` - fast enough that `adb logcat -d`'s
default window, the dedicated crash buffer, and `/data/anr/` (permission-
denied to a plain shell anyway) all missed it, and slow enough that each
restart briefly looked like a hang rather than a crash. `build.sh` now
hardcodes the exact base-jar path rather than globbing for it - see the
comment in `build.sh` if you hit something similar with a different Kotlin
install layout.
