import typing as t
from pathlib import Path

import typer
from rich import print
from rich.progress import track

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from texcret.utils import (
    prep_secrets,
    derive_wrapkey_from_passkey,
    derive_wrapkey_from_password,
    parse_header_v2,
)


def decrypt(
    paths: t.List[Path] = typer.Argument(..., exists=True, readable=True),
    origin: str = typer.Option("https://localhost", help="Secrerts origin"),
    out_dir: Path = typer.Option(None, help="Output dir (default: alongside input)"),
    password: t.List[str] = typer.Option(None, help="Try password(s); '-' to prompt"),
    arg_passwords: bool = typer.Option(False, help="Use argument passwords"),
    force_secrets: bool = typer.Option(True, help="Continue only if secrets opened"),
    allow_external_password_cache: bool = typer.Option(
        True, help="Allow external password cache (if pinentry is available)"
    ),
    reset_external_cache: bool = typer.Option(
        False, help="Reset external password cache (if pinentry is available)"
    ),
):
    """Decrypt files."""
    (storage_secrets, used_passwords) = prep_secrets(
        origin,
        password,
        use_arg_passwords=arg_passwords,
        force_secrets=force_secrets,
        allow_external_password_cache=allow_external_password_cache,
        reset_external_cache=reset_external_cache,
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
