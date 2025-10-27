import base64
import getpass
import json
import os
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
from rich.table import Table
from rich.progress import track

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

# FIDO2 (roaming) -------------------------------------------------------------
from fido2.hid import CtapHidDevice
from fido2.client import Fido2Client, UserInteraction
from fido2.webauthn import (
    PublicKeyCredentialRpEntity,
    PublicKeyCredentialUserEntity,
    AttestationConveyancePreference,
    PublicKeyCredentialParameters,
    PublicKeyCredentialType,
    PublicKeyCredentialDescriptor,
    AuthenticatorSelectionCriteria,
)

app = typer.Typer(add_completion=False, no_args_is_help=True)

STATE_DIR = Path(os.path.expanduser("~/.yk_largeblob"))
STATE_DIR.mkdir(parents=True, exist_ok=True)
STATE_FILE = STATE_DIR / "cred.json"

# ===== Formats & constants =====
MAGIC2 = b"YKLB2\x00"  # 6 bytes
DATA_IV_LEN = 12  # AES-GCM IV for data
WRAP_IV_LEN = 12  # AES-GCM IV for wrapping
SALT_LEN = 16  # salt for HKDF/PBKDF2
PASSKEY_INFO = b"YK-largeBlob-text"
SECRET_LEN = 32

# ===== State schema =====
# {
#   "creds": [
#       {"kind":"roaming","rp_id":"...","origin":"...","cred_id_hex":"..."},
#       {"kind":"platform","rp_id":"...","origin":"https://localhost:8443","cred_id_b64":"..."}
#   ]
# }
# (No secrets and no passwords are stored.)


# ---------- Utilities ----------
def save_state(d: dict):
    STATE_FILE.write_text(json.dumps(d, indent=2))


def load_state() -> dict:
    if STATE_FILE.exists():
        return json.loads(STATE_FILE.read_text())
    return {}


def ensure_state():
    st = load_state()
    if "creds" not in st:
        st["creds"] = []
    return st


# ---------- Roaming (HID) helpers ----------
def pick_device() -> "CtapHidDevice":
    devs = list(CtapHidDevice.list_devices())
    if not devs:
        typer.secho("No FIDO2 (roaming) device found. Insert your YubiKey.", fg="red")
        raise typer.Exit(1)
    if len(devs) > 1:
        typer.secho(
            f"Multiple roaming authenticators found; using the first: {devs[0]}",
            fg="yellow",
        )
    return devs[0]


class QuietUI(UserInteraction):
    def prompt_up(self) -> bool:
        return True


def build_client(rp_id: str, origin: str) -> Fido2Client:
    dev = pick_device()
    return Fido2Client(dev, origin=origin, user_interaction=QuietUI())


def make_roaming_credential_and_write_blob(
    rp_id: str, origin: str
) -> t.Tuple[bytes, bytes]:
    client = build_client(rp_id, origin)
    rp = PublicKeyCredentialRpEntity(id=rp_id, name="YK multi-secret CLI")
    user = PublicKeyCredentialUserEntity(
        id=os.urandom(16), name="multi@example.com", display_name="Multi User"
    )
    params = [
        PublicKeyCredentialParameters(PublicKeyCredentialType.PUBLIC_KEY, -7)
    ]  # ES256
    secret = os.urandom(SECRET_LEN)

    options, state = client.make_credential_options(
        rp=rp,
        user=user,
        challenge=os.urandom(32),
        authenticator_selection=AuthenticatorSelectionCriteria(
            resident_key="preferred",
            user_verification="preferred",
            require_resident_key=None,
        ),
        attestation=AttestationConveyancePreference.NONE,
        extensions={"largeBlob": {"support": "required"}},
        timeout=60000,
    )
    att_obj, _client_data = client.make_credential(options, state)
    cred_data = att_obj.auth_data.credential_data
    if not cred_data:
        raise RuntimeError("No credential data returned.")
    cred_id = cred_data.credential_id

    # Write the secret immediately
    allow = [PublicKeyCredentialDescriptor(type="public-key", id=cred_id)]
    options, state = client.get_assertion_options(
        rp_id=rp_id,
        challenge=os.urandom(32),
        allow_credentials=allow,
        user_verification="preferred",
        extensions={"largeBlob": {"write": secret}},
        timeout=60000,
    )
    _assertions, _cd = client.get_assertion(options, state)
    return cred_id, secret


def read_roaming_largeblob_secret(rp_id: str, origin: str, cred_id: bytes) -> bytes:
    client = build_client(rp_id, origin)
    allow = [PublicKeyCredentialDescriptor(type="public-key", id=cred_id)]
    options, state = client.get_assertion_options(
        rp_id=rp_id,
        challenge=os.urandom(32),
        allow_credentials=allow,
        user_verification="preferred",
        extensions={"largeBlob": {"read": True}},
        timeout=60000,
    )
    assertions, _cd = client.get_assertion(options, state)
    ext = assertions[0].client_extension_results
    blob = ext.get("largeBlob", {}).get("blob")
    if not blob or len(blob) < SECRET_LEN:
        raise RuntimeError("largeBlob read missing/short.")
    return bytes(blob[:SECRET_LEN])


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
def list_state_creds() -> t.List[dict]:
    return ensure_state()["creds"]


def add_state_roaming(rp_id: str, origin: str, cred_id_hex: str):
    st = ensure_state()
    st["creds"].append(
        {
            "kind": "roaming",
            "rp_id": rp_id,
            "origin": origin,
            "cred_id_hex": cred_id_hex,
        }
    )
    save_state(st)


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


def get_cred_by_index(idx: int) -> dict:
    creds = list_state_creds()
    if idx < 0 or idx >= len(creds):
        raise typer.BadParameter(f"Index out of range (0..{len(creds) - 1}).")
    return creds[idx]


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
        if parsed.path == "/platform/secret":
            self.secret_box["secretB64"] = data.get("secretB64", "")
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
    Opens a page that authenticates the platform passkey and reads the first 32B of largeBlob.
    If cred_id_b64 is None, the browser lets the user choose.
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
            if box.get("secretB64"):
                return {"secretB64": box["secretB64"]}
            threading.Event().wait(0.1)
        raise RuntimeError("Timed out waiting for platform registration.")

    res = with_https_server(cert, key, origin, port, run)
    return res["secretB64"]


# ---------- Commands ----------
@app.command("add-cred")
def add_cred(
    rp_id: str = typer.Option("localhost", help="RP ID (domain)"),
    origin: str = typer.Option(
        "https://localhost", help="Origin for roaming (must be https://<rp_id>)"
    ),
):
    """Register a *roaming* credential (YubiKey) and write a 32B secret; store metadata."""
    print("[bold]Registering new roaming credential…[/bold]")
    cred_id, _secret = make_roaming_credential_and_write_blob(rp_id, origin)
    add_state_roaming(rp_id, origin, cred_id.hex())
    print(
        f"[green]✅ Added roaming credential[/green] id={cred_id.hex()} for rp_id={rp_id}"
    )


@app.command("list-creds")
def list_creds():
    """List stored credentials (roaming + platform)."""
    creds = list_state_creds()
    if not creds:
        print(
            "[yellow]No credentials stored. Use `add-cred` or `add-platform-cred`.[/yellow]"
        )
        return
    tbl = Table(title="Stored credentials")
    tbl.add_column("#", justify="right")
    tbl.add_column("kind")
    tbl.add_column("rp_id")
    tbl.add_column("origin")
    tbl.add_column("id (short)")
    for i, c in enumerate(creds):
        short = (c.get("cred_id_hex", "") or c.get("cred_id_b64", ""))[:16] + "…"
        tbl.add_row(str(i), c["kind"], c["rp_id"], c["origin"], short)
    print(tbl)


@app.command("platform-secret")
def get_platform_secret(
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
    print(f"[green]✅ largeBlob read {len(sec)} bytes.[/green]")
    # print(sec.hex())
    print(sec)


@app.command("auth-test")
def auth_test(
    cred: int = typer.Option(..., help="Index from list-creds"),
    cert: t.Optional[Path] = typer.Option(
        None, exists=True, help="(Platform only) TLS cert"
    ),
    key: t.Optional[Path] = typer.Option(
        None, exists=True, help="(Platform only) TLS key"
    ),
    port: int = typer.Option(8443, help="(Platform only) HTTPS port"),
    show_hex: bool = typer.Option(False, help="Print 32B secret as hex"),
):
    """Authenticate and read 32B largeBlob secret to verify the credential."""
    c = get_cred_by_index(cred)
    if c["kind"] == "roaming":
        sec = read_roaming_largeblob_secret(
            c["rp_id"], c["origin"], bytes.fromhex(c["cred_id_hex"])
        )
    else:
        if not cert or not key:
            raise typer.BadParameter("Platform auth needs --cert and --key.")
        sec = platform_read_secret(
            cert, key, c["rp_id"], c["origin"], port, c.get("cred_id_b64")
        )
    print(f"[green]✅ largeBlob read {len(sec)} bytes.[/green]")
    if show_hex:
        print(sec.hex())


# Helper to fetch secrets for selected creds (roaming + platform)
def gather_selected_secrets(
    roaming_idx: t.List[int],
    platform_idx: t.List[int],
    cert: t.Optional[Path],
    key: t.Optional[Path],
    port: int,
) -> t.List[bytes]:
    secrets: t.List[bytes] = []
    # Roaming
    for idx in roaming_idx:
        c = get_cred_by_index(idx)
        if c["kind"] != "roaming":
            continue
        secrets.append(
            read_roaming_largeblob_secret(
                c["rp_id"], c["origin"], bytes.fromhex(c["cred_id_hex"])
            )
        )
    # Platform (batch through a single server instance per run is already OK because we open once per secret)
    for idx in platform_idx:
        c = get_cred_by_index(idx)
        if c["kind"] != "platform":
            continue
        if not cert or not key:
            raise typer.BadParameter("Platform secret requires --cert and --key.")
        secrets.append(
            platform_read_secret(
                cert, key, c["rp_id"], c["origin"], port, c.get("cred_id_b64")
            )
        )
    return secrets


@app.command()
def encrypt(
    paths: t.List[Path] = typer.Argument(..., exists=True, readable=True),
    out_dir: Path = typer.Option(None, help="Output dir (default: alongside input)"),
    all_creds: bool = typer.Option(
        False, help="Wrap for ALL stored credentials (both kinds)"
    ),
    cred: t.List[int] = typer.Option(
        None, help="Wrap for these indexes (repeatable) — roaming"
    ),
    pcred: t.List[int] = typer.Option(
        None, help="Wrap for these indexes (repeatable) — platform"
    ),
    password: t.List[str] = typer.Option(
        None, help="Add password recipient(s). Use '-' to prompt."
    ),
    cert: t.Optional[Path] = typer.Option(
        None, exists=True, help="TLS cert for platform secrets"
    ),
    key: t.Optional[Path] = typer.Option(
        None, exists=True, help="TLS key for platform secrets"
    ),
    port: int = typer.Option(8443, help="HTTPS port for platform secrets"),
):
    """Encrypt files (YKLB2): fresh dataKey; wrap for selected roaming/platform creds and/or passwords."""
    creds = list_state_creds()
    ridx: t.List[int] = []
    pidx: t.List[int] = []
    if all_creds:
        for i, c in enumerate(creds):
            (pidx if c["kind"] == "platform" else ridx).append(i)
    else:
        ridx = list(cred or [])
        pidx = list(pcred or [])

    pwds: t.List[str] = []
    for p in password or []:
        pwds.append(getpass.getpass("Enter password: ") if p == "-" else p)

    if not ridx and not pidx and not pwds:
        typer.secho(
            "No recipients selected. Use --all-creds / --cred / --pcred / --password.",
            fg="red",
        )
        raise typer.Exit(1)

    # Fetch required secrets (will open browser for platform creds)
    secrets_roaming: t.List[bytes] = []
    secrets_platform: t.List[bytes] = []
    if ridx:
        for i in ridx:
            c = get_cred_by_index(i)
            if c["kind"] == "roaming":
                secrets_roaming.append(
                    read_roaming_largeblob_secret(
                        c["rp_id"], c["origin"], bytes.fromhex(c["cred_id_hex"])
                    )
                )
    if pidx:
        for i in pidx:
            c = get_cred_by_index(i)
            if c["kind"] == "platform":
                if not cert or not key:
                    raise typer.BadParameter("Platform wrap requires --cert and --key.")
                secrets_platform.append(
                    platform_read_secret(
                        cert, key, c["rp_id"], c["origin"], port, c.get("cred_id_b64")
                    )
                )

    for p in track(paths, description="Encrypting"):
        pt = p.read_bytes()
        data_key_raw = os.urandom(32)
        data_iv = os.urandom(DATA_IV_LEN)
        ct = AESGCM(data_key_raw).encrypt(data_iv, pt, None)

        recipients: t.List[Recipient] = []

        # roaming wraps
        for sec in secrets_roaming:
            salt = os.urandom(SALT_LEN)
            wrap_iv = os.urandom(WRAP_IV_LEN)
            wrapped = derive_wrapkey_from_passkey(sec, salt).encrypt(
                wrap_iv, data_key_raw, None
            )
            recipients.append(Recipient(salt, wrap_iv, wrapped))
        # platform wraps
        for sec in secrets_platform:
            salt = os.urandom(SALT_LEN)
            wrap_iv = os.urandom(WRAP_IV_LEN)
            wrapped = derive_wrapkey_from_passkey(sec, salt).encrypt(
                wrap_iv, data_key_raw, None
            )
            recipients.append(Recipient(salt, wrap_iv, wrapped))
        # password wraps
        for pwd in pwds:
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
    out_dir: Path = typer.Option(None, help="Output dir (default: alongside input)"),
    try_all_creds: bool = typer.Option(True, help="Try all stored creds (both kinds)"),
    cred: t.List[int] = typer.Option(None, help="Try only these roaming indexes"),
    pcred: t.List[int] = typer.Option(None, help="Try only these platform indexes"),
    password: t.List[str] = typer.Option(None, help="Try password(s); '-' to prompt"),
    cert: t.Optional[Path] = typer.Option(
        None, exists=True, help="TLS cert for platform"
    ),
    key: t.Optional[Path] = typer.Option(
        None, exists=True, help="TLS key for platform"
    ),
    port: int = typer.Option(8443, help="HTTPS port for platform"),
):
    """Decrypt v2 files: try roaming/platform secrets and/or passwords to unwrap the data key."""
    creds = list_state_creds()
    ridx: t.List[int] = []
    pidx: t.List[int] = []
    if cred or pcred:
        ridx = list(cred or [])
        pidx = list(pcred or [])
    elif try_all_creds:
        for i, c in enumerate(creds):
            (pidx if c["kind"] == "platform" else ridx).append(i)

    pwds: t.List[str] = []
    for p in password or []:
        pwds.append(getpass.getpass("Enter password: ") if p == "-" else p)

    # Preload roaming secrets
    secrets_roaming: t.List[bytes] = []
    for i in ridx:
        c = get_cred_by_index(i)
        if c["kind"] == "roaming":
            secrets_roaming.append(
                read_roaming_largeblob_secret(
                    c["rp_id"], c["origin"], bytes.fromhex(c["cred_id_hex"])
                )
            )
    # Platform secrets will be pulled on-demand per file (one read can be reused across files, but we keep it simple)

    for encp in track(paths, description="Decrypting"):
        blob = encp.read_bytes()
        hdr = parse_header_v2(blob)
        ct = blob[hdr.body_off :]

        data_key_raw: t.Optional[bytes] = None

        # Try roaming
        for sec in secrets_roaming:
            for r in hdr.recipients:
                try:
                    data_key_raw = derive_wrapkey_from_passkey(sec, r.salt).decrypt(
                        r.wrap_iv, r.wrapped_key, None
                    )
                    raise StopIteration
                except Exception:
                    pass
        # Try platform (pull once if needed)
        if data_key_raw is None and pidx:
            for i in pidx:
                c = get_cred_by_index(i)
                if c["kind"] != "platform":
                    continue
                if not cert or not key:
                    raise typer.BadParameter(
                        "Platform decrypt requires --cert and --key."
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

        # Try passwords
        if data_key_raw is None:
            for pwd in pwds:
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
