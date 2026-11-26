#!/usr/bin/env python3
"""Health probe for a live epicmail relay. Standard library only; used by tools/ship.

  ship-probe.py BASE_URL [--landing] [--timeout S]

BASE_URL is http://127.0.0.1:3423 (on the relay host) or https://relay.example.org (from
outside). The probe checks, one line each:

  health         GET /health is 200
  ready          GET /ready is 200 (store writable, not draining)
  status         GET /status.json is JSON with store_ok true and draining false
  landing        GET / with Accept: text/html is 200 text/html (only with --landing)
  ws-challenge   a websocket connects and the first frame is a Challenge
  ws-getversion  GetVersion is answered with a x.y.z string

Prints "ok NAME DETAIL (ms)" or "FAIL NAME DETAIL" and exits 1 if anything failed.
"""
import base64
import http.client
import json
import os
import re
import socket
import ssl
import struct
import sys
import time
import urllib.parse


def conn(u, timeout):
    if u.scheme == "https":
        return http.client.HTTPSConnection(u.hostname, u.port or 443, timeout=timeout,
                                           context=ssl.create_default_context())
    return http.client.HTTPConnection(u.hostname, u.port or 80, timeout=timeout)


def get(u, path, timeout, headers=None):
    c = conn(u, timeout)
    try:
        c.request("GET", path, headers=headers or {})
        r = c.getresponse()
        return r.status, r.getheader("content-type") or "", r.read()
    finally:
        c.close()


class Ws:
    def __init__(self, u, timeout):
        port = u.port or (443 if u.scheme == "https" else 80)
        s = socket.create_connection((u.hostname, port), timeout=timeout)
        if u.scheme == "https":
            s = ssl.create_default_context().wrap_socket(s, server_hostname=u.hostname)
        s.settimeout(timeout)
        key = base64.b64encode(os.urandom(16)).decode()
        s.sendall(("GET / HTTP/1.1\r\nHost: %s\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n"
                   "Sec-WebSocket-Key: %s\r\nSec-WebSocket-Version: 13\r\n\r\n"
                   % (u.netloc, key)).encode())
        buf = b""
        while b"\r\n\r\n" not in buf:
            chunk = s.recv(4096)
            if not chunk:
                raise EOFError("closed during handshake")
            buf += chunk
        status, _, rest = buf.partition(b"\r\n")
        if b" 101 " not in status + b" ":
            raise RuntimeError("upgrade refused: " + status.decode(errors="replace"))
        self.s = s
        self.buf = buf.split(b"\r\n\r\n", 1)[1]  # frames that arrived with the handshake

    def _exact(self, n):
        while len(self.buf) < n:
            chunk = self.s.recv(4096)
            if not chunk:
                raise EOFError("socket closed")
            self.buf += chunk
        out, self.buf = self.buf[:n], self.buf[n:]
        return out

    def send_text(self, text):
        payload = text.encode()
        n = len(payload)
        head = bytes([0x81])
        if n < 126:
            head += bytes([0x80 | n])
        elif n < 65536:
            head += bytes([0x80 | 126]) + struct.pack(">H", n)
        else:
            head += bytes([0x80 | 127]) + struct.pack(">Q", n)
        mask = os.urandom(4)
        self.s.sendall(head + mask + bytes(b ^ mask[i % 4] for i, b in enumerate(payload)))

    def recv_text(self):
        while True:
            b0, b1 = self._exact(2)
            op, n = b0 & 0x0F, b1 & 0x7F
            if n == 126:
                n = struct.unpack(">H", self._exact(2))[0]
            elif n == 127:
                n = struct.unpack(">Q", self._exact(8))[0]
            data = self._exact(n) if n else b""
            if op == 1:
                return data.decode()
            if op == 8:
                raise EOFError("closed by relay: %r" % (data,))
            # ping/pong/other control frames: the probe never needs to answer within its life

    def close(self):
        self.s.close()


def main():
    args = sys.argv[1:]
    landing = "--landing" in args
    timeout = 8.0
    if "--timeout" in args:
        timeout = float(args[args.index("--timeout") + 1])
    base = [a for a in args if a.startswith("http")]
    if not base:
        sys.exit(__doc__)
    u = urllib.parse.urlparse(base[0])
    failed = []

    def check(name, fn):
        t0 = time.time()
        try:
            detail = fn() or ""
            print("ok   %-14s %s (%d ms)" % (name, detail, (time.time() - t0) * 1000))
        except Exception as e:  # noqa: BLE001 - a probe reports everything
            failed.append(name)
            print("FAIL %-14s %s: %s" % (name, type(e).__name__, e))

    def need(cond, msg):
        if not cond:
            raise AssertionError(msg)

    def health():
        st, _, _ = get(u, "/health", timeout)
        need(st == 200, "status %d" % st)

    def ready():
        st, _, body = get(u, "/ready", timeout)
        need(st == 200, "status %d %s" % (st, body[:80]))

    def status():
        st, _, body = get(u, "/status.json", timeout)
        need(st == 200, "status %d" % st)
        j = json.loads(body)
        need(j.get("store_ok") is True, "store_ok=%r" % j.get("store_ok"))
        need(j.get("draining") is False, "draining=%r" % j.get("draining"))
        return "sockets=%s uptime_s=%s" % (j.get("sockets"), j.get("uptime_s"))

    def landing_page():
        st, ctype, body = get(u, "/", timeout, {"Accept": "text/html"})
        need(st == 200 and ctype.startswith("text/html"), "status %d type %s" % (st, ctype))
        need(b"<html" in body[:2000].lower() or b"<!doctype" in body[:200].lower(), "not html")
        return "%d bytes" % len(body)

    ws = {}

    def ws_challenge():
        w = Ws(u, timeout)
        ws["w"] = w
        first = json.loads(w.recv_text())
        need(first.get("type") == "Challenge", "first frame %s" % str(first)[:80])
        need(isinstance(first.get("str"), str) and len(first["str"]) >= 16, "bad challenge")
        return "challenge %d chars" % len(first["str"])

    def ws_getversion():
        w = ws["w"]
        w.send_text('{"type":"GetVersion"}')
        for _ in range(5):  # skip interval Challenges
            f = json.loads(w.recv_text())
            if f.get("type") == "GetVersion":
                need(re.fullmatch(r"\d+\.\d+\.\d+", str(f.get("str"))), "str=%r" % f.get("str"))
                w.close()
                return "protocol " + f["str"]
        raise AssertionError("no GetVersion answer")

    check("health", health)
    check("ready", ready)
    check("status", status)
    if landing:
        check("landing", landing_page)
    check("ws-challenge", ws_challenge)
    if "w" in ws:
        check("ws-getversion", ws_getversion)
    else:
        failed.append("ws-getversion")
        print("FAIL %-14s skipped: no websocket" % "ws-getversion")
    sys.exit(1 if failed else 0)


if __name__ == "__main__":
    main()
