import typing as t
from pathlib import Path
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
    parse_header_v2,
    has_blocks,
)
from texcret.constants import TEXCRETED_BLOCK_RE


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

    new_text = TEXCRETED_BLOCK_RE.sub(repl, text)

    # Write the result
    out_path.write_text(new_text, encoding="utf-8")


def detexcret(
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
    """Detexcret files."""

    # Check if files need texcreting
    action_paths = []
    for p in track(paths, description="Searching for blocks to detexcret"):
        if has_blocks(TEXCRETED_BLOCK_RE, p):
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

    for p in track(action_paths, description="Detexcreting"):
        if in_file:
            dst = p
        else:
            (out_dir or p.parent).mkdir(parents=True, exist_ok=True)
            dst = (out_dir or p.parent) / (p.name + ".detexcreted")
        process_texcreted_blocks(p, dst, storage_secrets, used_passwords)
        if p == dst:
            print(f"Processed {p}")
        else:
            print(f"Processed {p} -> {dst}")
