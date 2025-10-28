import base64
import getpass
import json
import os
import re
import ssl
import struct
import threading
import typing as t
import webbrowser
from datetime import timedelta
from dataclasses import dataclass
from http.server import HTTPServer, SimpleHTTPRequestHandler
from pathlib import Path
from urllib.parse import urlparse, parse_qs

import typer
from rich import print
from rich.progress import track

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

app = typer.Typer(add_completion=False, no_args_is_help=True)

STATE_DIR = Path(os.path.expanduser("~/.config/texcrets"))
STATE_DIR.mkdir(parents=True, exist_ok=True)
STATE_FILE = STATE_DIR / "secrets.json"

# ===== Formats & constants =====
MAGIC2 = b"YKLB2\x00"  # 6 bytes
DATA_IV_LEN = 12  # AES-GCM IV for data
WRAP_IV_LEN = 12  # AES-GCM IV for wrapping
SALT_LEN = 16  # salt for HKDF/PBKDF2
PASSKEY_INFO = b"YK-largeBlob-text"
SECRET_LEN = 32


# ---------- Utilities ----------


def load_full_state() -> dict:
    if STATE_FILE.exists():
        return json.loads(STATE_FILE.read_text())
    return {}


def load_state(origin: str | None) -> dict:
    return load_full_state().get(origin, {}).copy()


def save_state(origin, d: dict):
    all = load_full_state()
    all[origin] = d
    STATE_FILE.write_text(json.dumps(all, indent=2))


def ensure_state(origin):
    st = load_state(origin)
    if "secrets" not in st:
        st["secrets"] = []
    return st


# ---------- Derivation (wrap keys) ----------
def derive_wrapkey_from_passkey(secret32: bytes, salt16: bytes) -> AESGCM:
    hkdf = HKDF(algorithm=hashes.SHA256(), length=32, salt=salt16, info=PASSKEY_INFO)
    return AESGCM(hkdf.derive(secret32))


def derive_wrapkey_from_password(password: str, salt16: bytes) -> AESGCM:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(), length=32, salt=salt16, iterations=200_000
    )
    return AESGCM(kdf.derive(password.encode("utf-8")))


# ---------- Header v2 ----------
@dataclass
class Recipient:
    salt: bytes
    wrap_iv: bytes
    wrapped_key: bytes


def make_header_v2(data_iv: bytes, name: str, recips: t.List[Recipient]) -> bytes:
    name_utf8 = name.encode("utf-8")
    parts = [
        MAGIC2,
        data_iv,
        struct.pack(">H", len(name_utf8)),
        name_utf8,
        struct.pack(">H", len(recips)),
    ]
    for r in recips:
        parts.extend(
            [r.salt, r.wrap_iv, struct.pack(">H", len(r.wrapped_key)), r.wrapped_key]
        )
    return b"".join(parts)


@dataclass
class ParsedHeaderV2:
    data_iv: bytes
    name: str
    recipients: t.List[Recipient]
    body_off: int


def parse_header_v2(blob: bytes) -> ParsedHeaderV2:
    if len(blob) < 6 or blob[:6] != MAGIC2:
        raise ValueError("Not a YKLB2 file (bad magic).")
    off = 6
    data_iv = blob[off : off + DATA_IV_LEN]
    off += DATA_IV_LEN
    name_len = struct.unpack(">H", blob[off : off + 2])[0]
    off += 2
    name = blob[off : off + name_len].decode("utf-8")
    off += name_len
    recip_count = struct.unpack(">H", blob[off : off + 2])[0]
    off += 2
    recips: t.List[Recipient] = []
    for _ in range(recip_count):
        salt = blob[off : off + SALT_LEN]
        off += SALT_LEN
        wrap_iv = blob[off : off + WRAP_IV_LEN]
        off += WRAP_IV_LEN
        wrap_len = struct.unpack(">H", blob[off : off + 2])[0]
        off += 2
        wrapped_key = blob[off : off + wrap_len]
        off += wrap_len
        recips.append(Recipient(salt, wrap_iv, wrapped_key))
    return ParsedHeaderV2(data_iv, name, recips, off)


# ---------- State helpers ----------
def list_state_secrets(origin) -> str:
    return ensure_state(origin)["secrets"]


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


def decrypt_with_passwords(blob: bytes, pwds: list[str]) -> bytes:
    """Decrypt with passwords"""

    hdr = parse_header_v2(blob)
    ct = blob[hdr.body_off :]

    data_key_raw: t.Optional[bytes] = None

    for pwd in pwds:
        for r in hdr.recipients:
            try:
                data_key_raw = derive_wrapkey_from_password(pwd, r.salt).decrypt(
                    r.wrap_iv, r.wrapped_key, None
                )
                raise StopIteration
            except Exception:
                pass

    if data_key_raw is None:
        typer.secho(
            f"Failed to unwrap key for {hdr.name} (no matching secret).", fg="red"
        )
        return

    try:
        pt = AESGCM(data_key_raw).decrypt(hdr.data_iv, ct, None)
    except Exception as e:
        typer.secho(f"Data decrypt failed for {hdr.name}: {e}", fg="red")
        return

    print(f"[green]✓[/green] Decrypted with password: {hdr.name!r}")
    return pt


def open_storage(origin, pwds):
    secrets = list_state_secrets(origin)
    if not secrets:
        print(
            f"[yellow]No secrets stored for origin {origin}. Load secrets first.[/yellow]"
        )
        return {}
    blob = base64.decodebytes(secrets.encode(encoding="utf-8"))
    data = decrypt_with_passwords(blob, pwds)
    if data is None:
        typer.secho("No secrets opened", fg="red")
        return {}
    storage = json.loads(data)
    storage_secretsB64 = storage["secretsB64"]
    storage_passwords = storage["passwords"]
    print(f"{len(storage_secretsB64)} secrets decrypted")
    print(f"{len(storage_passwords)} passwords decrypted")
    return storage


@app.command("load-secrets")
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


@app.command("list-secrets")
def list_secrets(
    origin: str = typer.Option("https://localhost", help="Secrerts origin"),
    password: t.List[str] = typer.Option(None, help="Password(s); '-' to prompt"),
    show_secrets: bool = typer.Option(False, help="Show secrets"),
):
    """List stored secrets."""
    pwds: t.List[str] = []
    for p in password or []:
        pwds.append(getpass.getpass("Enter password: ") if p == "-" else p)

    storage = open_storage(origin, pwds)
    if storage == {}:
        return
    storage_secretsB64 = storage["secretsB64"]
    storage_passwords = storage["passwords"]
    for i, secret in enumerate(storage_secretsB64, start=1):
        if show_secrets:
            sec = base64.decodebytes(secret.encode(encoding="utf-8"))
            print(str(i), "-", secret, sec.hex())
        else:
            s = secret[:5] + "..." + secret[-5:]
            print(str(i), "-", s)
    for i, storage_password in enumerate(storage_passwords, start=1):
        if show_secrets:
            s = storage_password
        else:
            s = storage_password[:3] + "..." + storage_password[-2:]
        print(str(i), "-", s)


def prep_secrets(
    origin: str,
    password: list[str] | None,
    use_arg_passwords: bool,
    force_secrets: bool,
):
    pwds: t.List[str] = []
    for p in password or []:
        pwds.append(getpass.getpass("Enter password: ") if p == "-" else p)

    storage = open_storage(origin, pwds)
    if storage == {} and force_secrets:
        typer.secho("Can't proceed without secrets.", fg="red")
        raise typer.Abort(11)
    storage_secrets = [
        base64.decodebytes(s.encode(encoding="utf-8"))
        for s in storage.get("secrets", [])
    ]
    storage_secrets = list(set(storage_secrets))
    used_passwords = storage.get("passwords", [])

    if use_arg_passwords:
        used_passwords = list(set(used_passwords + pwds))
    else:
        used_passwords = list(set([p for p in used_passwords if p not in pwds]))

    return (storage_secrets, used_passwords)


@app.command("encrypt")
def encrypt(
    paths: t.List[Path] = typer.Argument(..., exists=True, readable=True),
    origin: str = typer.Option("https://localhost", help="Secrerts origin"),
    out_dir: Path = typer.Option(None, help="Output dir (default: alongside input)"),
    password: t.List[str] = typer.Option(None, help="Password(s); '-' to prompt"),
    arg_passwords: bool = typer.Option(False, help="Use argument passwords"),
    force_secrets: bool = typer.Option(True, help="Continue only if secrets opened"),
):
    """Encrypt files."""
    (storage_secrets, used_passwords) = prep_secrets(
        origin, password, use_arg_passwords=arg_passwords, force_secrets=force_secrets
    )

    for p in track(paths, description="Encrypting"):
        pt = p.read_bytes()
        data_key_raw = os.urandom(32)
        data_iv = os.urandom(DATA_IV_LEN)
        ct = AESGCM(data_key_raw).encrypt(data_iv, pt, None)

        recipients: t.List[Recipient] = []

        # secrets wraps
        for sec in storage_secrets:
            salt = os.urandom(SALT_LEN)
            wrap_iv = os.urandom(WRAP_IV_LEN)
            wrapped = derive_wrapkey_from_passkey(sec, salt).encrypt(
                wrap_iv, data_key_raw, None
            )
            recipients.append(Recipient(salt, wrap_iv, wrapped))
        # password wraps
        for pwd in used_passwords:
            salt = os.urandom(SALT_LEN)
            wrap_iv = os.urandom(WRAP_IV_LEN)
            wrapped = derive_wrapkey_from_password(pwd, salt).encrypt(
                wrap_iv, data_key_raw, None
            )
            recipients.append(Recipient(salt, wrap_iv, wrapped))

        header = make_header_v2(data_iv, p.name, recipients)
        (out_dir or p.parent).mkdir(parents=True, exist_ok=True)
        dst = (out_dir or p.parent) / (p.name + ".enc")
        dst.write_bytes(header + ct)
        print(f"[green]✓[/green] {p} -> {dst}  (recipients={len(recipients)})")


@app.command()
def decrypt(
    paths: t.List[Path] = typer.Argument(..., exists=True, readable=True),
    origin: str = typer.Option("https://localhost", help="Secrerts origin"),
    out_dir: Path = typer.Option(None, help="Output dir (default: alongside input)"),
    password: t.List[str] = typer.Option(None, help="Try password(s); '-' to prompt"),
    arg_passwords: bool = typer.Option(False, help="Use argument passwords"),
    force_secrets: bool = typer.Option(True, help="Continue only if secrets opened"),
):
    """Decrypt files."""
    (storage_secrets, used_passwords) = prep_secrets(
        origin, password, use_arg_passwords=arg_passwords, force_secrets=force_secrets
    )

    for encp in track(paths, description="Decrypting"):
        blob = encp.read_bytes()
        hdr = parse_header_v2(blob)
        ct = blob[hdr.body_off :]

        data_key_raw: t.Optional[bytes] = None

        # Try secrets
        for sec in storage_secrets:
            for r in hdr.recipients:
                try:
                    data_key_raw = derive_wrapkey_from_passkey(sec, r.salt).decrypt(
                        r.wrap_iv, r.wrapped_key, None
                    )
                    raise StopIteration
                except Exception:
                    pass

        # Try passwords
        if data_key_raw is None:
            for pwd in used_passwords:
                for r in hdr.recipients:
                    try:
                        data_key_raw = derive_wrapkey_from_password(
                            pwd, r.salt
                        ).decrypt(r.wrap_iv, r.wrapped_key, None)
                        raise StopIteration
                    except Exception:
                        pass

        if data_key_raw is None:
            typer.secho(
                f"Failed to unwrap key for {encp.name} (no matching secret).", fg="red"
            )
            continue

        try:
            pt = AESGCM(data_key_raw).decrypt(hdr.data_iv, ct, None)
        except Exception as e:
            typer.secho(f"Data decrypt failed for {encp.name}: {e}", fg="red")
            continue

        dst = (out_dir or encp.parent) / hdr.name
        dst.write_bytes(pt)
        print(f"[green]✓[/green] {encp} -> {dst}")


def process_texcret_blocks(
    in_path: Path, out_path: Path, storage_secrets, used_passwords
):
    """Encrypt the content inside

    {% texcret %}
    ...
    {% endtexcret %}

    blocks.
    """

    # Read the file
    text = in_path.read_text(encoding="utf-8")

    # Regex: matches {% texcret %}...{% endtexcret %}, including multiline content
    pattern = re.compile(
        r"{%\s*texcret\s*%}(.*?){%\s*endtexcret\s*%}",
        re.DOTALL | re.IGNORECASE,
    )

    # Replacement: uppercase the inner block
    def repl(match: re.Match):
        inner = match.group(1)

        pt = inner.encode(encoding="utf-8")
        data_key_raw = os.urandom(32)
        data_iv = os.urandom(DATA_IV_LEN)
        ct = AESGCM(data_key_raw).encrypt(data_iv, pt, None)

        recipients: t.List[Recipient] = []

        # secrets wraps
        for sec in storage_secrets:
            salt = os.urandom(SALT_LEN)
            wrap_iv = os.urandom(WRAP_IV_LEN)
            wrapped = derive_wrapkey_from_passkey(sec, salt).encrypt(
                wrap_iv, data_key_raw, None
            )
            recipients.append(Recipient(salt, wrap_iv, wrapped))
        # password wraps
        for pwd in used_passwords:
            salt = os.urandom(SALT_LEN)
            wrap_iv = os.urandom(WRAP_IV_LEN)
            wrapped = derive_wrapkey_from_password(pwd, salt).encrypt(
                wrap_iv, data_key_raw, None
            )
            recipients.append(Recipient(salt, wrap_iv, wrapped))

        header = make_header_v2(data_iv, "---", recipients)
        res = base64.encodebytes(header + ct).decode(encoding="utf-8")
        print(
            f"[green]✓[/green] Texcreted {inner[:20]!r} -> {res[:20]!r}  (recipients={len(recipients)})"
        )

        return "\n[Texcret start]: #\n\n" + res + "\n[Texcret end]: #\n"

    new_text = pattern.sub(repl, text)

    # Write the result
    out_path.write_text(new_text, encoding="utf-8")


def process_texcreted_blocks(
    in_path: Path, out_path: Path, storage_secrets, used_passwords
):
    """Decrypt the content inside

    [Texcret start]: #
    ...
    [Texcret end]: #

    blocks.
    """

    # Read the file
    text = in_path.read_text(encoding="utf-8")

    # Regex: matches [Texcret start]: #...[Texcret end]: #, including multiline content
    pattern = re.compile(
        r"\n?\[\s*Texcret\s*start\s*\]:\s*#(.*?)\[\s*Texcret\s*end\s*\]:\s*#\n?",
        re.DOTALL | re.IGNORECASE,
    )

    # Replacement: uppercase the inner block
    def repl(match: re.Match):
        inner = match.group(1)
        stripped = inner.strip()
        blob = base64.decodebytes(stripped.encode(encoding="utf-8"))
        hdr = parse_header_v2(blob)
        ct = blob[hdr.body_off :]

        data_key_raw: t.Optional[bytes] = None

        # Try secrets
        for sec in storage_secrets:
            for r in hdr.recipients:
                try:
                    data_key_raw = derive_wrapkey_from_passkey(sec, r.salt).decrypt(
                        r.wrap_iv, r.wrapped_key, None
                    )
                    raise StopIteration
                except Exception:
                    pass

        # Try passwords
        if data_key_raw is None:
            for pwd in used_passwords:
                for r in hdr.recipients:
                    try:
                        data_key_raw = derive_wrapkey_from_password(
                            pwd, r.salt
                        ).decrypt(r.wrap_iv, r.wrapped_key, None)
                        raise StopIteration
                    except Exception:
                        pass

        if data_key_raw is None:
            typer.secho(
                f"Failed to unwrap key for {hdr.name} (no matching secret).", fg="red"
            )
            return inner

        try:
            pt = AESGCM(data_key_raw).decrypt(hdr.data_iv, ct, None)
        except Exception as e:
            typer.secho(f"Data decrypt failed for {hdr.name}: {e}", fg="red")
            return inner

        res = pt.decode(encoding="utf-8")
        print(f"[green]✓[/green] Detexcreted {stripped[:20]!r} -> {res[:20]!r}")

        return "{% texcret %}" + res + "{% endtexcret %}"

    new_text = pattern.sub(repl, text)

    # Write the result
    out_path.write_text(new_text, encoding="utf-8")


@app.command("texcret")
def texcret(
    paths: t.List[Path] = typer.Argument(..., exists=True, readable=True),
    origin: str = typer.Option("https://localhost", help="Secrerts origin"),
    out_dir: Path = typer.Option(None, help="Output dir (default: alongside input)"),
    password: t.List[str] = typer.Option(None, help="Password(s); '-' to prompt"),
    arg_passwords: bool = typer.Option(False, help="Use argument passwords"),
    force_secrets: bool = typer.Option(True, help="Continue only if secrets opened"),
    in_file: bool = typer.Option(False, help="Replace the file content"),
):
    """Texcretize files."""
    (storage_secrets, used_passwords) = prep_secrets(
        origin, password, use_arg_passwords=arg_passwords, force_secrets=force_secrets
    )

    for p in track(paths, description="Texcreting"):
        if in_file:
            dst = p
        else:
            (out_dir or p.parent).mkdir(parents=True, exist_ok=True)
            dst = (out_dir or p.parent) / (p.name + ".texcreted")
        process_texcret_blocks(p, dst, storage_secrets, used_passwords)
        if p == dst:
            print(f"Processed {p}")
        else:
            print(f"Processed {p} -> {dst}")


@app.command("detexcret")
def detexcret(
    paths: t.List[Path] = typer.Argument(..., exists=True, readable=True),
    origin: str = typer.Option("https://localhost", help="Secrerts origin"),
    out_dir: Path = typer.Option(None, help="Output dir (default: alongside input)"),
    password: t.List[str] = typer.Option(None, help="Password(s); '-' to prompt"),
    arg_passwords: bool = typer.Option(False, help="Use argument passwords"),
    force_secrets: bool = typer.Option(True, help="Continue only if secrets opened"),
    in_file: bool = typer.Option(False, help="Replace the file content"),
):
    """Detexcret files."""
    (storage_secrets, used_passwords) = prep_secrets(
        origin, password, use_arg_passwords=arg_passwords, force_secrets=force_secrets
    )

    for p in track(paths, description="Detexcreting"):
        if in_file:
            dst = p
        else:
            (out_dir or p.parent).mkdir(parents=True, exist_ok=True)
            dst = (out_dir or p.parent) / (p.name + ".texcreted")
        process_texcreted_blocks(p, dst, storage_secrets, used_passwords)
        if p == dst:
            print(f"Processed {p}")
        else:
            print(f"Processed {p} -> {dst}")


if __name__ == "__main__":
    app()
