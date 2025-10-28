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
def save_state(d: dict):
    STATE_FILE.write_text(json.dumps(d, indent=2))


def load_state() -> dict:
    if STATE_FILE.exists():
        return json.loads(STATE_FILE.read_text())
    return {}


def ensure_state():
    st = load_state()
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
def list_state_secrets() -> str:
    return ensure_state()["secrets"]


def add_state_platform(rp_id: str, origin: str, cred_id_b64: str):
    st = ensure_state()
    st["creds"].append(
        {
            "kind": "platform",
            "rp_id": rp_id,
            "origin": origin,
            "cred_id_b64": cred_id_b64,
        }
    )
    save_state(st)


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
        base = origin
        result = fn(base, token, lh, PlatformHandler.secret_box)
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
) -> bytes:
    """
    Opens a bridge page on the https://{origin}/bridge.html where user can load all required secrets and send them back to cli.
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

    res = with_https_server(cert, key, origin, port, run)
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

    print(f"[green]✓[/green] {hdr.name}")
    return pt


def open_storage(pwds):
    secrets = list_state_secrets()
    if not secrets:
        print(
            "[yellow]No secrets stored. Use `add-cred` or `add-platform-cred`.[/yellow]"
        )
        return
    blob = base64.decodebytes(secrets.encode(encoding="utf-8"))
    data = decrypt_with_passwords(blob, pwds)
    if data is None:
        typer.secho("No secrets opened", fg="red")
        return
    open_storage = json.loads(data)
    storage_secretsB64 = open_storage["secretsB64"]
    storage_passwords = open_storage["passwords"]
    print(f"{len(storage_secretsB64)} secrets decrypted")
    print(f"{len(storage_passwords)} passwords decrypted")
    return open_storage


@app.command("list-secrets")
def list_secrets(
    password: t.List[str] = typer.Option(None, help="Password(s); '-' to prompt"),
    show_secrets: bool = typer.Option(False, help="Show secrets"),
):
    """List stored secrets."""
    pwds: t.List[str] = []
    for p in password or []:
        pwds.append(getpass.getpass("Enter password: ") if p == "-" else p)

    storage = open_storage(pwds)
    storage_secretsB64 = storage["secretsB64"]
    storage_passwords = storage["passwords"]
    for i, secret in enumerate(storage_secretsB64, start=1):
        if show_secrets:
            xx = base64.decodebytes(secret.encode(encoding="utf-8"))
            hex = xx.hex()
            print(str(i), "-", secret, hex)
        else:
            s = secret[:5] + "..." + secret[-5:]
            print(str(i), "-", s)
    for i, storage_password in enumerate(storage_passwords, start=1):
        if show_secrets:
            s = storage_password
        else:
            s = storage_password[:3] + "..." + storage_password[-2:]
        print(str(i), "-", s)


@app.command("load-secrets")
def load_secrets(
    cert: t.Optional[Path] = typer.Option(
        None, exists=True, help="(Platform only) TLS cert"
    ),
    key: t.Optional[Path] = typer.Option(
        None, exists=True, help="(Platform only) TLS key"
    ),
    port: int = typer.Option(8443, help="(Platform only) HTTPS port"),
    origin: str = typer.Option(
        "https://localhost", help="Origin for roaming (must be https://<rp_id>)"
    ),
    timeout: float = typer.Option(
        3.0, help="Timeout (in minutes) for passkey bridge to respond back"
    ),
):
    """"""
    timeout = timedelta(minutes=timeout)
    sec = platform_read_secret(cert, key, origin, port, timeout=timeout)
    print(f"[green]✅ secrets loaded ({len(sec)} bytes).[/green]")
    print(sec)
    st = ensure_state()
    st["secrets"] = sec
    save_state(st)


@app.command("encrypt")
def encrypt(
    paths: t.List[Path] = typer.Argument(..., exists=True, readable=True),
    out_dir: Path = typer.Option(None, help="Output dir (default: alongside input)"),
    password: t.List[str] = typer.Option(None, help="Password(s); '-' to prompt"),
    arg_passwords: bool = typer.Option(True, help="Use argument passwords"),
):
    """Encrypt files."""
    pwds: t.List[str] = []
    for p in password or []:
        pwds.append(getpass.getpass("Enter password: ") if p == "-" else p)

    storage = open_storage(pwds)
    storage_secrets = [
        base64.decodebytes(s.encode(encoding="utf-8")) for s in storage["secretsB64"]
    ]
    used_passwords = storage["passwords"]

    if arg_passwords:
        used_passwords += pwds

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
        dst = (out_dir or p.parent) / (p.name + ".texcret")
        dst.write_bytes(header + ct)
        print(f"[green]✓[/green] {p} -> {dst}  (recipients={len(recipients)})")


@app.command()
def decrypt(
    paths: t.List[Path] = typer.Argument(..., exists=True, readable=True),
    out_dir: Path = typer.Option(None, help="Output dir (default: alongside input)"),
    password: t.List[str] = typer.Option(None, help="Try password(s); '-' to prompt"),
    arg_passwords: bool = typer.Option(True, help="Use argument passwords"),
):
    """Decrypt files."""

    pwds: t.List[str] = []
    for p in password or []:
        pwds.append(getpass.getpass("Enter password: ") if p == "-" else p)

    storage = open_storage(pwds)
    storage_secrets = [
        base64.decodebytes(s.encode(encoding="utf-8")) for s in storage["secretsB64"]
    ]
    used_passwords = storage["passwords"]

    if arg_passwords:
        used_passwords += pwds

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
    """Encrypt the content inside {% texcret %}...{% endtexcret %} blocks."""

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
            f"[green]✓[/green] {inner[:20]!r} -> {res[:20]!r}  (recipients={len(recipients)})"
        )

        return "\n\n[Texcret start]: #\n\n" + res + "\n[Texcret end]: #\n\n"

    new_text = pattern.sub(repl, text)

    # Write the result
    out_path.write_text(new_text, encoding="utf-8")
    print(f"Processed {in_path} → {out_path}")


@app.command("texcretize")
def texcretize(
    paths: t.List[Path] = typer.Argument(..., exists=True, readable=True),
    out_dir: Path = typer.Option(None, help="Output dir (default: alongside input)"),
    password: t.List[str] = typer.Option(None, help="Password(s); '-' to prompt"),
    arg_passwords: bool = typer.Option(True, help="Use argument passwords"),
):
    """Texcretize files."""
    pwds: t.List[str] = []
    for p in password or []:
        pwds.append(getpass.getpass("Enter password: ") if p == "-" else p)

    storage = open_storage(pwds)
    storage_secrets = [
        base64.decodebytes(s.encode(encoding="utf-8")) for s in storage["secretsB64"]
    ]
    used_passwords = storage["passwords"]

    if arg_passwords:
        used_passwords += pwds

    for p in track(paths, description="Texcretizing"):
        (out_dir or p.parent).mkdir(parents=True, exist_ok=True)
        dst = (out_dir or p.parent) / (p.name + ".texcreted")
        process_texcret_blocks(p, dst, storage_secrets, used_passwords)


@app.command()
def rotate(
    paths: t.List[Path] = typer.Argument(..., exists=True, readable=True),
    out_dir: Path = typer.Option(None, help="Output dir (default: in-place)"),
    # unwrap sources:
    try_all_creds: bool = typer.Option(True, help="Try all stored creds to unwrap"),
    cred: t.List[int] = typer.Option(None, help="Try only these roaming indexes"),
    pcred: t.List[int] = typer.Option(None, help="Try only these platform indexes"),
    password: t.List[str] = typer.Option(
        None, help="Plus these passwords to unwrap (repeatable; '-' to prompt)"
    ),
    # wrap targets:
    all_creds: bool = typer.Option(False, help="Wrap to ALL stored creds"),
    wrap_cred: t.List[int] = typer.Option(None, help="Wrap to these roaming indexes"),
    wrap_pcred: t.List[int] = typer.Option(None, help="Wrap to these platform indexes"),
    wrap_password: t.List[str] = typer.Option(
        None, help="Wrap to these passwords (repeatable; '-' to prompt)"
    ),
    keep_backups: bool = typer.Option(True, help="Keep .bak of original"),
    cert: t.Optional[Path] = typer.Option(
        None, exists=True, help="TLS cert for platform (unwrap/wrap)"
    ),
    key: t.Optional[Path] = typer.Option(
        None, exists=True, help="TLS key for platform (unwrap/wrap)"
    ),
    port: int = typer.Option(8443, help="HTTPS port for platform"),
):
    """Rewrap .enc files: unwrap with provided sources; rewrap to chosen roaming/platform recipients and/or passwords."""
    creds = list_state_creds()

    # Source sets
    src_ridx: t.List[int] = []
    src_pidx: t.List[int] = []
    if cred or pcred:
        src_ridx = list(cred or [])
        src_pidx = list(pcred or [])
    elif try_all_creds:
        for i, c in enumerate(creds):
            (src_pidx if c["kind"] == "platform" else src_ridx).append(i)

    src_pwds: t.List[str] = []
    for p in password or []:
        src_pwds.append(getpass.getpass("Enter password (unwrap): ") if p == "-" else p)

    # Target sets
    dst_ridx: t.List[int] = []
    dst_pidx: t.List[int] = []
    if all_creds:
        for i, c in enumerate(creds):
            (dst_pidx if c["kind"] == "platform" else dst_ridx).append(i)
    else:
        dst_ridx = list(wrap_cred or [])
        dst_pidx = list(wrap_pcred or [])

    dst_pwds: t.List[str] = []
    for p in wrap_password or []:
        dst_pwds.append(getpass.getpass("Enter password (wrap): ") if p == "-" else p)

    if not dst_ridx and not dst_pidx and not dst_pwds:
        typer.secho(
            "No wrap recipients selected. Use --all-creds / --wrap-cred / --wrap-pcred / --wrap-password.",
            fg="red",
        )
        raise typer.Exit(1)

    # Preload roaming secrets for source & targets
    src_roam_secs: t.List[bytes] = []
    for i in src_ridx:
        c = get_cred_by_index(i)
        if c["kind"] == "roaming":
            src_roam_secs.append(
                read_roaming_largeblob_secret(
                    c["rp_id"], c["origin"], bytes.fromhex(c["cred_id_hex"])
                )
            )

    dst_roam_secs: t.List[bytes] = []
    for i in dst_ridx:
        c = get_cred_by_index(i)
        if c["kind"] == "roaming":
            dst_roam_secs.append(
                read_roaming_largeblob_secret(
                    c["rp_id"], c["origin"], bytes.fromhex(c["cred_id_hex"])
                )
            )

    for encp in track(paths, description="Rotating"):
        blob = encp.read_bytes()
        hdr = parse_header_v2(blob)
        ct = blob[hdr.body_off :]

        data_key_raw: t.Optional[bytes] = None

        # Try unwrap with roaming
        for sec in src_roam_secs:
            for r in hdr.recipients:
                try:
                    data_key_raw = derive_wrapkey_from_passkey(sec, r.salt).decrypt(
                        r.wrap_iv, r.wrapped_key, None
                    )
                    raise StopIteration
                except Exception:
                    pass

        # Try unwrap with platform
        if data_key_raw is None and src_pidx:
            for i in src_pidx:
                c = get_cred_by_index(i)
                if c["kind"] != "platform":
                    continue
                if not cert or not key:
                    raise typer.BadParameter(
                        "Platform unwrap requires --cert and --key."
                    )
                secp = platform_read_secret(
                    cert, key, c["rp_id"], c["origin"], port, c.get("cred_id_b64")
                )
                for r in hdr.recipients:
                    try:
                        data_key_raw = derive_wrapkey_from_passkey(
                            secp, r.salt
                        ).decrypt(r.wrap_iv, r.wrapped_key, None)
                        raise StopIteration
                    except Exception:
                        pass

        # Try unwrap with passwords
        if data_key_raw is None and src_pwds:
            for pwd in src_pwds:
                for r in hdr.recipients:
                    try:
                        data_key_raw = derive_wrapkey_from_password(
                            pwd, r.salt
                        ).decrypt(r.wrap_iv, r.wrapped_key, None)
                        raise StopIteration
                    except Exception:
                        pass

        if data_key_raw is None:
            typer.secho(f"Failed to unwrap key for {encp.name}", fg="red")
            continue

        # Rewrap recipients
        recipients: t.List[Recipient] = []

        # Reuse same data_iv/name and ciphertext; we only rewrap the data key.
        # Roaming targets
        for sec in dst_roam_secs:
            salt = os.urandom(SALT_LEN)
            wrap_iv = os.urandom(WRAP_IV_LEN)
            wrapped = derive_wrapkey_from_passkey(sec, salt).encrypt(
                wrap_iv, data_key_raw, None
            )
            recipients.append(Recipient(salt, wrap_iv, wrapped))

        # Platform targets (fetch per target)
        for i in dst_pidx:
            c = get_cred_by_index(i)
            if c["kind"] != "platform":
                continue
            if not cert or not key:
                raise typer.BadParameter("Platform wrap requires --cert and --key.")
            secp = platform_read_secret(
                cert, key, c["rp_id"], c["origin"], port, c.get("cred_id_b64")
            )
            salt = os.urandom(SALT_LEN)
            wrap_iv = os.urandom(WRAP_IV_LEN)
            wrapped = derive_wrapkey_from_passkey(secp, salt).encrypt(
                wrap_iv, data_key_raw, None
            )
            recipients.append(Recipient(salt, wrap_iv, wrapped))

        # Password targets
        for pwd in dst_pwds:
            salt = os.urandom(SALT_LEN)
            wrap_iv = os.urandom(WRAP_IV_LEN)
            wrapped = derive_wrapkey_from_password(pwd, salt).encrypt(
                wrap_iv, data_key_raw, None
            )
            recipients.append(Recipient(salt, wrap_iv, wrapped))

        new_header = make_header_v2(hdr.data_iv, hdr.name, recipients)
        out = new_header + ct

        dst = (out_dir or encp.parent) / encp.name
        tmp = dst.with_suffix(dst.suffix + ".tmp")
        tmp.write_bytes(out)
        if (out_dir is None) and (dst.exists()):
            bak = dst.with_suffix(dst.suffix + ".bak")
            try:
                if bak.exists():
                    bak.unlink()
                dst.replace(bak)
            except Exception:
                pass
        tmp.replace(dst)
        print(f"[green]✓[/green] rewrapped {encp.name} (recipients={len(recipients)})")


if __name__ == "__main__":
    app()
