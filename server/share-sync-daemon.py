#!/usr/bin/env python3
"""share-sync: two-way folder mirror between host3 and the Companion app.

Event driven in both directions, no sync state, no deletes-by-diff:

  * This process serves ROOT over HTTP (WireGuard-only) so the phone can push:
        GET    /manifest        -> {"files": {"rel/path": [size, mtime_sec]}}
        GET    /file/<rel>      -> bytes
        PUT    /file/<rel>      -> store body, X-Mtime sets mtime (seconds)
        DELETE /file/<rel>      -> remove file (and now-empty parent dirs)
  * An inotify watcher on ROOT pushes every local change to the phone's
    Companion server (PHONE_URL, same /share/... routes, X-Peer-Agent: 1).
  * Every RECONCILE_S seconds (and at start) a catch-up pass pushes files the
    phone lacks or has an older copy of. It never deletes: deletions travel
    only as live events, so an offline gap can resurrect a deleted file
    (conflict handling is deliberately out of scope for now).

Files a peer's change replaces or deletes are moved to TRASH first (30 days),
so nothing can be lost silently, even by an offline-gap resurrection.

Changes applied from the peer are remembered for a few seconds so the watcher
does not echo them straight back.
"""
import ctypes, http.client, ipaddress, json, os, queue, shutil, struct, sys, threading
import time, urllib.parse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer


def env_or_fatal(k):
    v = os.environ.get(k)
    if not v:
        sys.exit(f"share-sync: {k} must be set")
    return v


BIND_IP = env_or_fatal("SHARE_SYNC_BIND_IP")
ALLOWED = ipaddress.ip_network(env_or_fatal("SHARE_SYNC_ALLOWED_SUBNET"))
ROOT = os.path.realpath(os.path.expanduser(env_or_fatal("SHARE_SYNC_ROOT")))
PHONE = env_or_fatal("SHARE_SYNC_PHONE")  # host:port of the Companion server
PORT = int(os.environ.get("SHARE_SYNC_PORT", "8791"))
RECONCILE_S = int(os.environ.get("SHARE_SYNC_RECONCILE_S", "120"))
PARTIAL = ".part-sync"
ECHO_S = 10
# Anything a peer's change replaces or deletes is kept here first (outside
# ROOT, so it is never synced) and pruned after TRASH_DAYS.
TRASH = os.path.expanduser(os.environ.get("SHARE_SYNC_TRASH", "~/.local/share/share-sync/trash"))
TRASH_DAYS = 30

applied = {}  # rel -> (size, mtime, expiry) for files the peer just wrote; (None, None, expiry) for deletes
applied_lock = threading.Lock()
outbox = queue.Queue()


def log(msg):
    print(msg, flush=True)


def resolve(rel):
    """Map a request path to a file under ROOT, or None if it escapes it."""
    p = os.path.realpath(os.path.join(ROOT, rel))
    return p if p.startswith(ROOT + os.sep) else None


def mark_applied(rel, size, mtime):
    with applied_lock:
        applied[rel] = (size, mtime, time.time() + ECHO_S)


def is_echo(rel, size, mtime):
    with applied_lock:
        a = applied.get(rel)
        if not a or a[2] < time.time():
            return False
        return (a[0], a[1]) == (size, mtime)


def trash_copy(full, rel, remove):
    """Keep the file about to be overwritten (copy) or deleted (move) in TRASH."""
    dest = os.path.join(TRASH, time.strftime("%Y%m%d-%H%M%S"), rel)
    os.makedirs(os.path.dirname(dest), exist_ok=True)
    (shutil.move if remove else shutil.copy2)(full, dest)


def prune_trash():
    cutoff = time.time() - TRASH_DAYS * 86400
    if not os.path.isdir(TRASH):
        return
    for d in os.listdir(TRASH):
        p = os.path.join(TRASH, d)
        if os.path.getmtime(p) < cutoff:
            shutil.rmtree(p, ignore_errors=True)


def local_manifest():
    files = {}
    for dp, _, names in os.walk(ROOT):
        for n in names:
            if n.endswith(PARTIAL):
                continue
            full = os.path.join(dp, n)
            try:
                st = os.stat(full)
            except OSError:
                continue
            files[os.path.relpath(full, ROOT)] = [st.st_size, int(st.st_mtime)]
    return files


# ---------------------------------------------------------------- HTTP server

class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, fmt, *args):
        pass

    def reply(self, code, body=b"", ctype="text/plain"):
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def allowed(self):
        addr = ipaddress.ip_address(self.client_address[0])
        if getattr(addr, "ipv4_mapped", None):
            addr = addr.ipv4_mapped
        if addr not in ALLOWED and not addr.is_loopback:
            log(f"deny: source {addr}")
            self.reply(403)
            return False
        if self.headers.get("X-Share-Sync") != "1" or "Origin" in self.headers:
            self.reply(403)
            return False
        return True

    def rel(self):
        path = urllib.parse.unquote(urllib.parse.urlsplit(self.path).path)
        return path[len("/file/"):] if path.startswith("/file/") else None

    def do_GET(self):
        if not self.allowed():
            return
        if self.path == "/manifest":
            if not os.path.isdir(ROOT):
                return self.reply(503)  # never look like "everything deleted"
            return self.reply(200, json.dumps({"files": local_manifest()}).encode(), "application/json")
        rel = self.rel()
        full = resolve(rel) if rel else None
        if not full or not os.path.isfile(full):
            return self.reply(404)
        self.send_response(200)
        self.send_header("Content-Type", "application/octet-stream")
        self.send_header("Content-Length", str(os.path.getsize(full)))
        self.end_headers()
        with open(full, "rb") as f:
            while chunk := f.read(1 << 20):
                self.wfile.write(chunk)

    def do_PUT(self):
        if not self.allowed():
            return
        rel = self.rel()
        full = resolve(rel) if rel else None
        if not full or full.endswith(PARTIAL):
            return self.reply(400)
        os.makedirs(os.path.dirname(full), exist_ok=True)
        tmp = full + PARTIAL
        left = int(self.headers.get("Content-Length", "0"))
        size = left
        with open(tmp, "wb") as f:
            while left > 0:
                chunk = self.rfile.read(min(left, 1 << 20))
                if not chunk:
                    break
                f.write(chunk)
                left -= len(chunk)
        if left:
            os.unlink(tmp)
            return self.reply(400)
        mt = self.headers.get("X-Mtime")
        if mt and os.path.isfile(full):
            cur = os.stat(full)
            if cur.st_size == size and int(cur.st_mtime) == int(mt):
                os.unlink(tmp)  # already identical: an echo of our own push
                return self.reply(200, b"ok")
        if mt:
            os.utime(tmp, (int(mt), int(mt)))
        mark_applied(rel, size, int(os.stat(tmp).st_mtime))
        if os.path.isfile(full):
            trash_copy(full, rel, remove=False)
        os.replace(tmp, full)
        self.reply(200, b"ok")

    def do_DELETE(self):
        if not self.allowed():
            return
        rel = self.rel()
        full = resolve(rel) if rel else None
        if not full or not os.path.isfile(full):
            return self.reply(404)
        mark_applied(rel, None, None)
        trash_copy(full, rel, remove=True)
        d = os.path.dirname(full)
        while d != ROOT:
            try:
                os.rmdir(d)
            except OSError:
                break
            d = os.path.dirname(d)
        self.reply(200, b"ok")

    def do_POST(self):
        self.reply(405)


# ------------------------------------------------------------- push to phone

def phone_request(method, path, body=None, headers=None):
    host, port = PHONE.split(":")
    c = http.client.HTTPConnection(host, int(port), timeout=15)
    try:
        h = {"X-Peer-Agent": "1"}
        h.update(headers or {})
        c.request(method, path, body=body, headers=h)
        r = c.getresponse()
        return r.status, r.read()
    finally:
        c.close()


def push_file(rel):
    full = os.path.join(ROOT, rel)
    try:
        st = os.stat(full)
    except OSError:
        return True  # vanished again; the delete event will follow
    if is_echo(rel, st.st_size, int(st.st_mtime)):
        return True
    with open(full, "rb") as f:
        code, _ = phone_request(
            "PUT", "/share/file/" + urllib.parse.quote(rel), f,
            {"Content-Length": str(st.st_size), "X-Mtime": str(int(st.st_mtime))})
    log(f"push {rel}: {code}")
    return code == 200


def push_delete(rel):
    with applied_lock:
        a = applied.get(rel)
        if a and a[0] is None and a[2] >= time.time():  # peer-applied delete
            return True
    code, _ = phone_request("DELETE", "/share/file/" + urllib.parse.quote(rel))
    log(f"push delete {rel}: {code}")
    return code in (200, 404)


def pusher():
    """Drain outbox; failures (phone off the tunnel) wait for the next reconcile."""
    while True:
        op, rel = outbox.get()
        try:
            if op == "put":
                push_file(rel)
            else:
                push_delete(rel)
        except Exception as e:
            log(f"push {op} {rel} failed: {type(e).__name__}: {e}")


def reconcile():
    code, body = phone_request("GET", "/share/manifest")
    if code != 200:
        return
    remote = json.loads(body)["files"]
    for rel, (size, mtime) in local_manifest().items():
        r = remote.get(rel)
        if r is None or (r[1] < mtime and r != [size, mtime]):
            outbox.put(("put", rel))


def reconciler():
    while True:
        prune_trash()
        try:
            reconcile()
        except Exception as e:
            log(f"reconcile: phone unreachable ({type(e).__name__})")
        time.sleep(RECONCILE_S)


# ------------------------------------------------------------------- watcher

IN_CLOSE_WRITE, IN_MOVED_FROM, IN_MOVED_TO = 0x8, 0x40, 0x80
IN_CREATE, IN_DELETE, IN_ISDIR = 0x100, 0x200, 0x40000000
MASK = IN_CLOSE_WRITE | IN_MOVED_FROM | IN_MOVED_TO | IN_CREATE | IN_DELETE


def watcher():
    libc = ctypes.CDLL("libc.so.6", use_errno=True)
    fd = libc.inotify_init1(os.O_CLOEXEC)
    wds = {}  # wd -> dir path

    def add_tree(top):
        for dp, dns, fns in os.walk(top):
            wd = libc.inotify_add_watch(fd, dp.encode(), MASK)
            if wd >= 0:
                wds[wd] = dp
            if top != ROOT:  # dir appeared after we looked: its files predate the watch
                for n in fns:
                    if not n.endswith(PARTIAL):
                        outbox.put(("put", os.path.relpath(os.path.join(dp, n), ROOT)))

    add_tree(ROOT)
    while True:
        buf = os.read(fd, 65536)
        off = 0
        while off < len(buf):
            wd, mask, _, ln = struct.unpack_from("iIII", buf, off)
            name = buf[off + 16: off + 16 + ln].rstrip(b"\0").decode(errors="replace")
            off += 16 + ln
            d = wds.get(wd)
            if d is None or name.endswith(PARTIAL):
                continue
            full = os.path.join(d, name)
            rel = os.path.relpath(full, ROOT)
            if mask & IN_ISDIR:
                if mask & (IN_CREATE | IN_MOVED_TO):
                    add_tree(full)
                continue
            if mask & (IN_CLOSE_WRITE | IN_MOVED_TO):
                outbox.put(("put", rel))
            elif mask & (IN_DELETE | IN_MOVED_FROM):
                outbox.put(("del", rel))


if __name__ == "__main__":
    os.makedirs(ROOT, exist_ok=True)
    for fn in (watcher, pusher, reconciler):
        threading.Thread(target=fn, daemon=True).start()
    srv = ThreadingHTTPServer((BIND_IP, PORT), Handler)
    log(f"share-sync serving {ROOT} on {BIND_IP}:{PORT}, mirroring to {PHONE}")
    srv.serve_forever()
