#!/usr/bin/env python3
"""Regression test: Google OAuth callback secrets (`code`, `state`) must not reach nginx logs.

Synthetic canary values only; no real OAuth data. Python standard library only.

  # against a local nginx binary (renders nginx.conf.template itself)
  python3 tests/oauth_log_redaction.py --mode local --nginx /path/to/nginx --template nginx.conf.template
  # against the real image built from this repo (CI): logs come from `docker logs`
  python3 tests/oauth_log_redaction.py --mode docker --template nginx.conf.template
  # sensitivity check: the same scenarios MUST find leaks in a template without the fix
  python3 tests/oauth_log_redaction.py --mode local --nginx ... --template baseline.template --expect-leak

Exit 0 = every check passed (or, with --expect-leak, the leak was observed in access log, error log and Referer).
"""
import argparse, base64, http.client, os, secrets, shutil, socket, subprocess, sys, tempfile, threading, time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

CODE = "CANARYCODE" + secrets.token_hex(8)
STATE = "CANARYSTATE" + secrets.token_hex(8)
CB = "/api/auth/callback/google"
QUERY = f"?code={CODE}&state={STATE}&scope=openid+email&authuser=0&prompt=none"
USER, PASSWORD = "admin", "lab-" + secrets.token_hex(6)
BASIC = "Basic " + base64.b64encode(f"{USER}:{PASSWORD}".encode()).decode()
SEEN_HEADERS = []  # headers the upstream received, for the routing/proxy-header check

failures, leaks = [], {"access": False, "error": False, "referer": False}


def check(ok, label):
    print(("PASS  " if ok else "FAIL  ") + label)
    if not ok:
        failures.append(label)


def free_port():
    s = socket.socket(); s.bind(("127.0.0.1", 0)); p = s.getsockname()[1]; s.close(); return p


class Upstream(BaseHTTPRequestHandler):
    delay = 0.0

    def do_GET(self):
        SEEN_HEADERS.append({k.lower(): v for k, v in self.headers.items()})
        time.sleep(self.delay)
        try:
            self.send_response(200); self.send_header("Content-Length", "2"); self.end_headers(); self.wfile.write(b"ok")
        except OSError:
            pass

    def log_message(self, *a):
        pass


def serve(delay=0.0):
    handler = type("H", (Upstream,), {"delay": delay})
    srv = ThreadingHTTPServer(("127.0.0.1", 0), handler)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv, srv.server_address[1]


def garbage_server():
    s = socket.socket(); s.bind(("127.0.0.1", 0)); s.listen(8); s.settimeout(0.2)
    stop = threading.Event()

    def loop():
        while not stop.is_set():
            try:
                c, _ = s.accept()
            except OSError:
                continue
            try:
                c.recv(4096); c.sendall(b"HTTP/1.1 200 OK\r\nthis line is not a header\r\n\r\n"); c.close()
            except OSError:
                pass
    threading.Thread(target=loop, daemon=True).start()
    return s.getsockname()[1], lambda: (stop.set(), s.close())


class Proxy:
    """One nginx instance (local binary or the real image) for one ORIGIN."""

    def __init__(self, args, origin, extra_callback_directives=""):
        self.args, self.origin, self.extra = args, origin, extra_callback_directives
        self.tmp = tempfile.mkdtemp(prefix="ngx-oauthlog-"); os.chmod(self.tmp, 0o755)
        self.port = 80 if args.mode == "docker" else free_port()

    def start(self):
        a = self.args
        template = open(a.template).read()
        if self.extra:
            marker = f"location = {CB} {{"
            assert marker in template
            template = template.replace(marker, marker + "\n        " + self.extra, 1)
        if a.mode == "local":
            d = self.tmp
            htpasswd = subprocess.run(["openssl", "passwd", "-apr1", PASSWORD], capture_output=True, text=True, check=True).stdout.strip()
            open(f"{d}/htpasswd", "w").write(f"{USER}:{htpasswd}\n")
            open(f"{d}/basic_auth.conf", "w").write(f'auth_basic "Restricted";\nauth_basic_user_file {d}/htpasswd;\n')
            server = template.replace("${ORIGIN}", self.origin).replace("${DNS_RESOLVER}", f"127.0.0.1:{a.dns_port}")
            server = server.replace("/etc/nginx/snippets/basic_auth.conf", f"{d}/basic_auth.conf")
            # Only differences from the real image: no TLS module in the test build, no IPv6 in the sandbox, test port.
            server = "\n".join(l for l in server.splitlines() if "proxy_ssl_" not in l and "listen [::]:80" not in l)
            server = server.replace("listen 80;", f"listen 127.0.0.1:{self.port};")
            open(f"{d}/server.conf", "w").write(server)
            open(f"{d}/nginx.conf", "w").write(
                f"user root;\nworker_processes 1;\nerror_log stderr notice;\npid {d}/n.pid;\nevents {{ worker_connections 64; }}\n"
                f"http {{ log_format main '$remote_addr - $remote_user [$time_local] \"$request\" $status $body_bytes_sent \"$http_referer\" \"$http_user_agent\" \"$http_x_forwarded_for\"';\n"
                f"  access_log /dev/stdout main;  # same as the stock nginx image's http-level default\n"
                f"  client_body_temp_path {d}/b; proxy_temp_path {d}/p; fastcgi_temp_path {d}/f; uwsgi_temp_path {d}/u; scgi_temp_path {d}/s;\n"
                f"  include {d}/server.conf; }}\n")
            self.out, self.err = open(f"{d}/out.log", "w"), open(f"{d}/err.log", "w")
            self.proc = subprocess.Popen([a.nginx, "-p", d, "-c", f"{d}/nginx.conf", "-g", "daemon off;"], stdout=self.out, stderr=self.err)
        else:
            ctx = f"{self.tmp}/ctx"; shutil.copytree(a.repo, ctx, ignore=shutil.ignore_patterns(".git", "tests"))
            shutil.copy(a.template, f"{ctx}/nginx.conf.template")
            if self.extra:
                open(f"{ctx}/nginx.conf.template", "w").write(template)
            tag = "oauthlog-test:" + secrets.token_hex(4)
            subprocess.run(["docker", "build", "-q", "-t", tag, ctx], check=True, stdout=subprocess.DEVNULL)
            self.name = "oauthlog-" + secrets.token_hex(4); self.tag = tag
            subprocess.run(["docker", "run", "-d", "--network", "host", "--name", self.name, "-e", f"ORIGIN={self.origin}",
                            "-e", f"BASIC_AUTH={USER}:{PASSWORD}", tag], check=True, stdout=subprocess.DEVNULL)
        for _ in range(60):
            try:
                socket.create_connection(("127.0.0.1", self.port), 0.3).close(); return self
            except OSError:
                time.sleep(0.25)
        raise RuntimeError("nginx did not start:\n" + "".join(self.logs()))

    def request(self, path, headers=None, auth=False, timeout=15):
        c = http.client.HTTPConnection("127.0.0.1", self.port, timeout=timeout)
        h = {"User-Agent": "oauthlog-test/1", "X-Forwarded-For": "198.51.100.9"}
        if auth:
            h["Authorization"] = BASIC
        h.update(headers or {})
        c.request("GET", path, headers=h); r = c.getresponse(); r.read(); c.close()
        return r.status

    def abort_after(self, path, seconds):
        s = socket.create_connection(("127.0.0.1", self.port), 5)
        s.sendall(f"GET {path} HTTP/1.1\r\nHost: x\r\nUser-Agent: oauthlog-test/1\r\n\r\n".encode()); time.sleep(seconds); s.close()

    def logs(self):
        time.sleep(0.5)
        if self.args.mode == "local":
            self.out.flush(); self.err.flush()
            return open(f"{self.tmp}/out.log").read(), open(f"{self.tmp}/err.log").read()
        r = subprocess.run(["docker", "logs", self.name], capture_output=True, text=True)
        return r.stdout, r.stderr

    def stop(self):
        if self.args.mode == "local":
            self.proc.terminate(); self.proc.wait(5)
        else:
            subprocess.run(["docker", "rm", "-f", self.name], capture_output=True)
            subprocess.run(["docker", "rmi", "-f", self.tag], capture_output=True)
        shutil.rmtree(self.tmp, ignore_errors=True)


def contains_secret(text):
    return CODE in text or STATE in text


def scenario(args, label, origin, act, extra=""):
    """Run `act(proxy)`, then verify neither log stream holds the canaries (or record the leak for --expect-leak)."""
    p = Proxy(args, origin, extra).start()
    try:
        result = act(p)
        access, error = p.logs()
    finally:
        p.stop()
    a_leak, e_leak = contains_secret(access), contains_secret(error)
    leaks["access"] |= a_leak and "referer" not in label
    leaks["error"] |= e_leak
    if args.expect_leak:
        print(f"INFO  {label}: access_leak={a_leak} error_leak={e_leak}")
    else:
        check(not a_leak, f"{label}: access log has no code/state")
        check(not e_leak, f"{label}: error log has no code/state")
    return result, access, error


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--mode", choices=["local", "docker"], required=True)
    ap.add_argument("--nginx", default="nginx"); ap.add_argument("--template", default="nginx.conf.template")
    ap.add_argument("--repo", default=os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    ap.add_argument("--expect-leak", action="store_true"); ap.add_argument("--dns-port", type=int, default=15353)
    args = ap.parse_args()
    dns = None
    if args.mode == "local":  # NXDOMAIN-for-everything DNS so the "cannot resolve upstream" error path is reproducible offline
        dns = subprocess.Popen([sys.executable, os.path.join(os.path.dirname(os.path.abspath(__file__)), "fake_nxdomain_dns.py"), str(args.dns_port)])
        time.sleep(0.5)
    up, up_port = serve(); slow, slow_port = serve(delay=2.5); garbage_port, stop_garbage = garbage_server()
    ok_origin, dead_origin = f"http://127.0.0.1:{up_port}", f"http://127.0.0.1:{free_port()}"
    try:
        # 1) healthy upstream: callback is reachable WITHOUT Basic Auth; diagnostic fields present; no query in access log
        status, access, _ = scenario(args, "callback 200", ok_origin, lambda p: p.request(CB + QUERY))
        line = next((l for l in access.splitlines() if CB in l), "")
        if not args.expect_leak:
            check(status == 200, "callback is exempt from Basic Auth (200 without credentials)")
            check(f'"GET {CB} HTTP/1.1"' in line and " 200 " in line, "access log keeps method, path and status")
            check("rt=" in line and "us=200" in line, "access log keeps latency and upstream status (rt=, us=)")
            check("auth=0" in line, "access log records Authorization presence only (auth=0)")
        # 2) upstream failures: nginx writes the request line + upstream URL (with query) to request-scoped error log entries
        status, access, _ = scenario(args, "callback upstream refused", dead_origin, lambda p: p.request(CB + QUERY))
        if not args.expect_leak:
            check(status == 502 and "us=502" in next((l for l in access.splitlines() if CB in l), ""), "refused upstream -> 502 recorded in access log (status 502, us=502)")
        scenario(args, "callback upstream DNS NXDOMAIN", "http://gone.invalid:1", lambda p: p.request(CB + QUERY))
        scenario(args, "callback upstream invalid response", f"http://127.0.0.1:{garbage_port}", lambda p: p.request(CB + QUERY))
        # 3) timeout (test-only 1s read timeout) and client abort (499)
        scenario(args, "callback upstream timeout", f"http://127.0.0.1:{slow_port}", lambda p: p.request(CB + QUERY), extra="proxy_read_timeout 1s;")
        _, access, _ = scenario(args, "callback client abort", f"http://127.0.0.1:{slow_port}", lambda p: p.abort_after(CB + QUERY, 0.3))
        if not args.expect_leak:
            check(any(" 499 " in l for l in access.splitlines() if CB in l), "client abort is visible as 499 in access log")
        # 4) Referer of the follow-up request (error page link back to /login) carries the callback URL with its query
        p = Proxy(args, ok_origin).start()
        try:
            p.request("/login", {"Referer": f"https://qa.example.test{CB}{QUERY}"}, auth=True)
            p.request("/login", {"Referer": f"https://qa.example.test{CB}{QUERY}"}, auth=False)
            p.request("/?code=" + CODE + "&state=" + STATE, auth=True)
            access, error = p.logs()
        finally:
            p.stop()
        leaks["referer"] = contains_secret(access)
        if args.expect_leak:
            print(f"INFO  referer/other-path access_leak={leaks['referer']}")
        else:
            check(not contains_secret(access), "Referer and non-callback query strings never reach the access log")
            check(f'"https://qa.example.test{CB}"' in access, "Referer keeps scheme/host/path (query stripped)")
        # 5) regression: Basic Auth, exact-match exemption, proxy headers
        if not args.expect_leak:
            p = Proxy(args, ok_origin).start()
            try:
                SEEN_HEADERS.clear()
                check(p.request("/") == 401, "Basic Auth still required for / (401 without credentials)")
                check(p.request("/", auth=True) == 200, "Basic Auth accepts valid credentials for /")
                check(p.request(CB + "/") == 401 and p.request(CB + "x") == 401, "callback exemption is exact (trailing slash / suffix -> 401)")
                SEEN_HEADERS.clear(); p.request(CB + QUERY); cb_hdr = SEEN_HEADERS[-1]
                SEEN_HEADERS.clear(); p.request("/x", auth=True); root_hdr = SEEN_HEADERS[-1]
                for name, h in (("callback", cb_hdr), ("/", root_hdr)):
                    check(h.get("x-forwarded-for", "").startswith("198.51.100.9") and "x-real-ip" in h and h.get("x-forwarded-proto") == "http"
                          and "x-forwarded-host" in h and h.get("host", "").startswith("127.0.0.1"), f"{name}: proxy headers (Host, X-Forwarded-*, X-Real-IP) are sent to upstream")
                # Informational residual: request-scoped error_log entries of OTHER locations still contain their request line.
                p.request("/?note=public-value", {"Authorization": "Basic " + base64.b64encode(b"x:y").decode()})
                _, error = p.logs()
                print("INFO  residual: error_log entry for a failed Basic Auth on '/' includes the request line:", "note=public-value" in error)
            finally:
                p.stop()
    finally:
        stop_garbage(); up.shutdown(); slow.shutdown()
        if dns:
            dns.terminate()
    if args.expect_leak:
        ok = all(leaks.values())
        print(f"{'PASS' if ok else 'FAIL'}  sensitivity: leaks observed in a template without the fix -> {leaks}")
        sys.exit(0 if ok else 1)
    print(f"\n{'ALL CHECKS PASSED' if not failures else 'FAILED: ' + '; '.join(failures)}")
    sys.exit(1 if failures else 0)


if __name__ == "__main__":
    main()
