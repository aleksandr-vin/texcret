import typing as t
from pathlib import Path
import os
import re
import base64

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
    has_blocks,
)
from texcret.constants import DATA_IV_LEN, SALT_LEN, WRAP_IV_LEN, TEXCRET_BLOCK_RE


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
        res = base64.b64encode(header + ct).decode(encoding="utf-8")
        print(
            f"[green]✓[/green] Texcreted {inner[:20]!r} -> {res[:20]!r}  (recipients={len(recipients)})"
        )

        return "\n[Texcret start]: #\n\n" + res + "\n\n[Texcret end]: #\n"

    new_text = TEXCRET_BLOCK_RE.sub(repl, text)

    # Write the result
    out_path.write_text(new_text, encoding="utf-8")


def texcret(
    paths: t.List[Path] = typer.Argument(..., exists=True, readable=True),
    origin: str = typer.Option("https://localhost", help="Secrerts origin"),
    out_dir: Path = typer.Option(None, help="Output dir (default: alongside input)"),
    password: t.List[str] = typer.Option(None, help="Password(s); '-' to prompt"),
    arg_passwords: bool = typer.Option(False, help="Use argument passwords"),
    force_secrets: bool = typer.Option(True, help="Continue only if secrets opened"),
    in_file: bool = typer.Option(False, help="Replace the file content"),
    allow_external_password_cache: bool = typer.Option(
        True, help="Allow external password cache (if pinentry is available)"
    ),
    reset_external_cache: bool = typer.Option(
        False, help="Reset external password cache (if pinentry is available)"
    ),
):
    """Texcretize files."""

    # Check if files need texcreting
    action_paths = []
    for p in track(paths, description="Searching for blocks to texcret"):
        if has_blocks(TEXCRET_BLOCK_RE, p):
            print(f"    Found in {p}")
            action_paths.append(p)
        else:
            print(f"Not found in {p}")

    if len(action_paths) == 0:
        print("Nothing to do.")
        return

    (storage_secrets, used_passwords) = prep_secrets(
        origin,
        password,
        use_arg_passwords=arg_passwords,
        force_secrets=force_secrets,
        allow_external_password_cache=allow_external_password_cache,
        reset_external_cache=reset_external_cache,
    )

    for p in track(action_paths, description="Texcreting"):
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
