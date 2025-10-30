from pathlib import Path
from datetime import timedelta
import webbrowser
import threading
from http.server import HTTPServer, SimpleHTTPRequestHandler
from urllib.parse import urlparse, parse_qs
import ssl
import json
import base64
import os
import typing as t

import typer
from rich import print
from rich.progress import track

from texcret.utils import ensure_state, save_state


class PlatformHandler(SimpleHTTPRequestHandler):
    secret_box: dict = {}
    token_expect: str = ""

    origin = "https://example.com"

    # CORS preflight
    def do_OPTIONS(self):
        if self.headers.get("origin") == self.origin:
            self.send_response(204)
            self.send_header("Access-Control-Allow-Origin", self.origin)
            self.send_header("Access-Control-Allow-Methods", "POST, OPTIONS")
            self.send_header("Access-Control-Allow-Headers", "content-type")
            self.end_headers()
            return
        self.send_response(403)
        self.end_headers()

    def do_POST(self):
        origin = self.headers.get("origin", "")
        if origin != self.origin:
            self.send_response(403)
            self.end_headers()
            return
        parsed = urlparse(self.path)
        qs = parse_qs(parsed.query)
        token = (qs.get("token") or [""])[0]
        if token != self.token_expect:
            self.send_response(403)
            self.end_headers()
            self.wfile.write(b"bad token")
            return
        length = int(self.headers.get("content-length", "0"))
        body = self.rfile.read(length) if length > 0 else b"{}"
        try:
            data = json.loads(body.decode("utf-8"))
        except Exception:
            data = {}
        if parsed.path == "/secrets":
            self.secret_box["storage"] = data.get("storage", [])
            self.send_response(200)
            self.send_header("Access-Control-Allow-Origin", self.origin)
            self.end_headers()
            self.wfile.write(b"ok")
        else:
            self.send_response(404)
            self.end_headers()


def with_https_server(
    cert_path: Path,
    key_path: Path,
    origin: str,
    port: int,
    bridge_base_url: str,
    fn: t.Callable[[str], t.Dict[str, str]],
):
    """
    Start HTTPS server on localhost:port, run fn(base_url) in the foreground (which may
    open a browser), and stop server once fn has collected what it needs.
    """
    httpd = HTTPServer(("127.0.0.1", port), PlatformHandler)
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(certfile=str(cert_path), keyfile=str(key_path))
    httpd.socket = ctx.wrap_socket(httpd.socket, server_side=True)

    # random token to bind browser callback to this invocation
    token = base64.urlsafe_b64encode(os.urandom(24)).decode().rstrip("=")
    PlatformHandler.token_expect = token
    PlatformHandler.secret_box = {}
    PlatformHandler.origin = origin

    tserv = threading.Thread(target=httpd.serve_forever, daemon=True)
    tserv.start()

    try:
        lh = f"https://localhost:{port}"
        result = fn(bridge_base_url, token, lh, PlatformHandler.secret_box)
        return result
    finally:
        httpd.shutdown()
        httpd.server_close()


def platform_read_secret(
    cert: Path,
    key: Path,
    origin: str,
    port: int,
    timeout: timedelta,
    bridge_base_url: str,
) -> bytes:
    """
    Opens a bridge page on the {bridge_base_url}/bridge.html where user can load all required secrets and send them back to cli.
    """

    def run(base, token, lh, box):
        # Serve the HTML at /platform.html, then navigate with proper query
        url = f"{base}/bridge.html?token={token}&lh={lh}"
        webbrowser.open(url)
        # Wait until secret arrives (simple polling)
        for _ in track(
            range(int(timeout.total_seconds() * 10)),
            description="Waiting for passkey bridge to reply",
        ):
            if box.get("storage"):
                return {"storage": box["storage"]}
            threading.Event().wait(0.1)
        raise RuntimeError("Timed out waiting for platform registration.")

    res = with_https_server(cert, key, origin, port, bridge_base_url, run)
    return res["storage"]


def load_secrets(
    cert: Path = typer.Option(exists=True, help="(Platform only) TLS cert"),
    key: Path = typer.Option(exists=True, help="(Platform only) TLS key"),
    port: int = typer.Option(8443, help="(Platform only) HTTPS port"),
    origin: str = typer.Option(
        "https://localhost", help="Origin for roaming (must be https://<rp_id>)"
    ),
    bridge_base_path: str = typer.Option("", help="Bridge base path"),
    timeout: float = typer.Option(
        3.0, help="Timeout (in minutes) for passkey bridge to respond back"
    ),
):
    """Load secrets through the bridge interface."""
    bridge_base_url = origin + bridge_base_path
    timeout = timedelta(minutes=timeout)
    sec = platform_read_secret(
        cert, key, origin, port, timeout=timeout, bridge_base_url=bridge_base_url
    )
    print(f"[green]✅ secrets loaded ({len(sec)} bytes).[/green]")
    print(sec)
    st = ensure_state(origin)
    st["secrets"] = sec
    save_state(origin, st)
