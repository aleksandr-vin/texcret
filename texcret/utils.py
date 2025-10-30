import base64
from getpass import getpass
import json
import struct
import typing as t
from dataclasses import dataclass

import typer
from rich import print

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

from .constants import (
    STATE_FILE,
    MAGIC2,
    PASSKEY_INFO,
    DATA_IV_LEN,
    SALT_LEN,
    WRAP_IV_LEN,
)
from .pinentry import call_pinentry_getpin, clear_pinentry_external_cache, PinentryError


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


def prep_secrets(
    origin: str,
    password: list[str] | None,
    use_arg_passwords: bool,
    force_secrets: bool,
    allow_external_password_cache: bool,
    reset_external_cache: bool,
):
    pwds: t.List[str] = []
    for i, p in enumerate(password or [], start=1):
        if p == "-":
            try:
                cache_key_info = f"texcrets-{origin}-{i}"
                if reset_external_cache:
                    clear_pinentry_external_cache(cache_key_info)
                pwd = call_pinentry_getpin(
                    "Enter password:",
                    desc=f"Password #{i}",
                    title="Texcret",
                    allow_external_password_cache=allow_external_password_cache,
                    cache_key_info=cache_key_info,
                )
            except FileNotFoundError:
                pwd = getpass(f"Enter password #{i}: ")
            except PinentryError as err:
                typer.secho(str(err), fg="red")
                raise typer.Abort(11) from err
            pwds.append(pwd)

    storage = open_storage(origin, pwds)
    if storage == {} and allow_external_password_cache:
        print(
            "[blue](It could be that a password obtained from cache was wrong or outdated, "
            "try resetting the cache with [cyan bold]--reset-external-cache[/cyan bold])[/blue]"
        )
    if storage == {} and force_secrets:
        typer.secho("Can't proceed without secrets.", fg="red")
        raise typer.Abort(11)
    storage_secrets = [
        base64.decodebytes(s.encode(encoding="utf-8"))
        for s in storage.get("secretsB64", [])
    ]
    storage_secrets = list(set(storage_secrets))
    used_passwords = storage.get("passwords", [])

    if use_arg_passwords:
        used_passwords = list(set(used_passwords + pwds))
    else:
        used_passwords = list(set([p for p in used_passwords if p not in pwds]))

    return (storage_secrets, used_passwords)


def has_blocks(regex, in_path):
    """Check if file has texcret or texcreted blocks."""
    # Read the file
    text = in_path.read_text(encoding="utf-8")
    return regex.search(text) is not None
