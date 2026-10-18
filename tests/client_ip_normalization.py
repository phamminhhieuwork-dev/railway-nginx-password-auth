#!/usr/bin/env python3
"""Regression test: nginx forwards exactly ONE client IP in X-Forwarded-For (the LEFT-most entry of the edge-built header,
accepted only in the edge's 1- or 2-entry shape), so Better Auth in meeting-ai rate-limits per client, not one shared bucket.

Synthetic addresses only (RFC 5737 / RFC 3849 documentation ranges). Python standard library only. Reuses the nginx
launcher of tests/oauth_log_redaction.py (local binary or the real image).

  python3 tests/client_ip_normalization.py --mode docker --template nginx.conf.template
  python3 tests/client_ip_normalization.py --mode local --nginx /path/to/nginx --template nginx.conf.template
  # sensitivity: the template without the fix must forward a multi-value header
  python3 tests/client_ip_normalization.py --mode docker --template base.template --expect-multi
"""
import argparse, http.client, os, subprocess, sys, time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import oauth_log_redaction as olr  # noqa: E402

CB = olr.CB
failures = []


def check(ok, label):
    print(("PASS  " if ok else "FAIL  ") + label)
    if not ok:
        failures.append(label)


def send(p, path, xff_headers, auth=False):
    """One request with 0..n X-Forwarded-For header lines (each value as given). Returns (status, upstream XFF or None)."""
    olr.SEEN_HEADERS.clear()
    c = http.client.HTTPConnection("127.0.0.1", p.port, timeout=15)
    c.putrequest("GET", path)
    c.putheader("User-Agent", "clientip-test/1")
    if auth:
        c.putheader("Authorization", olr.BASIC)
    for v in xff_headers:
        c.putheader("X-Forwarded-For", v)
    c.endheaders()
    r = c.getresponse(); r.read(); c.close()
    seen = olr.SEEN_HEADERS[-1].get("x-forwarded-for") if olr.SEEN_HEADERS else None
    return r.status, seen


# (label, incoming X-Forwarded-For header lines, expected single value at the app; PEER = nginx's $remote_addr)
PEER = "127.0.0.1"
CASES = [
    ("no X-Forwarded-For -> TCP peer", [], PEER),
    ("edge direct: single IPv4", ["198.51.100.9"], "198.51.100.9"),
    ("edge via CDN: client, shared CDN IP -> client", ["198.51.100.9, 192.0.2.200"], "198.51.100.9"),
    ("same CDN IP, different clients stay apart (A)", ["198.51.100.9, 192.0.2.200"], "198.51.100.9"),
    ("same CDN IP, different clients stay apart (B)", ["198.51.100.77, 192.0.2.200"], "198.51.100.77"),
    ("unexpected shape: 3 entries -> TCP peer", ["203.0.113.7, 198.51.100.9, 192.0.2.200"], PEER),
    ("IPv6 client direct", ["2001:db8::5"], "2001:db8::5"),
    ("IPv6 client via IPv4 CDN", ["2001:db8:0:1::abcd, 192.0.2.200"], "2001:db8:0:1::abcd"),
    ("IPv4-mapped IPv6", ["::ffff:198.51.100.9"], "::ffff:198.51.100.9"),
    ("two header lines (= 2 entries) -> first", ["198.51.100.9", "192.0.2.200"], "198.51.100.9"),
    ("malformed: not an IP -> TCP peer", ["not-an-ip"], PEER),
    ("malformed: first not an IP -> TCP peer", ["evil.example, 198.51.100.9"], PEER),
    ("malformed: port suffix -> TCP peer", ["198.51.100.9:443"], PEER),
    ("malformed: leading comma -> TCP peer", [", 198.51.100.9"], PEER),
    ("empty header -> TCP peer", [""], PEER),
]


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--mode", choices=["local", "docker"], required=True)
    ap.add_argument("--nginx", default="nginx"); ap.add_argument("--template", default="nginx.conf.template")
    ap.add_argument("--repo", default=os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    ap.add_argument("--dns-port", type=int, default=15354); ap.add_argument("--expect-multi", action="store_true")
    args = ap.parse_args()
    args.expect_leak = False
    dns = None
    if args.mode == "local":
        dns = subprocess.Popen([sys.executable, os.path.join(os.path.dirname(os.path.abspath(__file__)), "fake_nxdomain_dns.py"), str(args.dns_port)])
        time.sleep(0.5)
    up, up_port = olr.serve()
    p = olr.Proxy(args, f"http://127.0.0.1:{up_port}").start()
    multi = False
    try:
        for label, lines, want in CASES:
            for where, path, auth in (("/", "/x", True), ("callback", CB, False)):
                status, got = send(p, path, lines, auth)
                multi |= bool(got and "," in got)
                if not args.expect_multi:
                    check(status == 200 and got == want, f"{where}: {label} (app sees exactly '{want}')")
        if not args.expect_multi:
            # unchanged behaviour around the fix
            check(send(p, "/", [])[0] == 401, "Basic Auth still required for / (401 without credentials)")
            check(send(p, "/", [], auth=True)[0] == 200, "Basic Auth accepts valid credentials for /")
            check(send(p, CB, [])[0] == 200, "callback still exempt from Basic Auth")
            check(send(p, CB + "/", [])[0] == 401 and send(p, CB + "x", [])[0] == 401, "callback exemption still exact")
            access, _ = p.logs()
            check(" cip=198.51.100.9" in access and " cip=198.51.100.77" in access and " cip=2001:db8::5" in access, "access log records the normalized client IP (cip=)")
            check("not-an-ip" in access and " cip=not-an-ip" not in access, "a malformed header is logged as received but never used as cip")
    finally:
        p.stop(); up.shutdown()
        if dns:
            dns.terminate()
    if args.expect_multi:
        print(f"{'PASS' if multi else 'FAIL'}  sensitivity: template without the fix forwards a multi-value X-Forwarded-For -> {multi}")
        sys.exit(0 if multi else 1)
    print(f"\n{'ALL CHECKS PASSED' if not failures else 'FAILED: ' + '; '.join(failures)}")
    sys.exit(1 if failures else 0)


if __name__ == "__main__":
    main()
