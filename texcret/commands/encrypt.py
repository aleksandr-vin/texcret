import typing as t
from pathlib import Path
import os

import typer
from rich import print
from rich.progress import track

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from texcret.utils import (
    prep_secrets,
    derive_wrapkey_from_passkey,
    derive_wrapkey_from_password,
    make_header_v2,
    Recipient,
)
from texcret.constants import DATA_IV_LEN, SALT_LEN, WRAP_IV_LEN


def encrypt(
    paths: t.List[Path] = typer.Argument(..., exists=True, readable=True),
    origin: str = typer.Option("https://localhost", help="Secrerts origin"),
    out_dir: Path = typer.Option(None, help="Output dir (default: alongside input)"),
    password: t.List[str] = typer.Option(None, help="Password(s); '-' to prompt"),
    arg_passwords: bool = typer.Option(False, help="Use argument passwords"),
    force_secrets: bool = typer.Option(True, help="Continue only if secrets opened"),
    allow_external_password_cache: bool = typer.Option(
        True, help="Allow external password cache (if pinentry is available)"
    ),
    reset_external_cache: bool = typer.Option(
        False, help="Reset external password cache (if pinentry is available)"
    ),
):
    """Encrypt files."""
    (storage_secrets, used_passwords) = prep_secrets(
        origin,
        password,
        use_arg_passwords=arg_passwords,
        force_secrets=force_secrets,
        allow_external_password_cache=allow_external_password_cache,
        reset_external_cache=reset_external_cache,
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
