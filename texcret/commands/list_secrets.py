import base64
import typing as t

import typer
from rich import print

from texcret.utils import prep_secrets


def list_secrets(
    origin: str = typer.Option("https://localhost", help="Secrerts origin"),
    password: t.List[str] = typer.Option(None, help="Password(s); '-' to prompt"),
    show_secrets: bool = typer.Option(False, help="Show secrets"),
    arg_passwords: bool = typer.Option(False, help="Use argument passwords"),
    allow_external_password_cache: bool = typer.Option(
        True, help="Allow external password cache (if pinentry is available)"
    ),
    reset_external_cache: bool = typer.Option(
        False, help="Reset external password cache (if pinentry is available)"
    ),
):
    """List stored secrets."""

    (storage_secrets, used_passwords) = prep_secrets(
        origin,
        password,
        use_arg_passwords=arg_passwords,
        force_secrets=False,
        allow_external_password_cache=allow_external_password_cache,
        reset_external_cache=reset_external_cache,
    )

    for i, secret in enumerate(storage_secrets, start=1):
        secretB64 = base64.b64encode(secret).decode(encoding="utf-8")
        if show_secrets:
            print(str(i), "[S]", f"{secretB64!r}", secret.hex())
        else:
            s = secretB64[:5] + "..." + secretB64[-5:]
            print(str(i), "[S]", f"{s!r}")
    for i, storage_password in enumerate(used_passwords, start=1):
        if show_secrets:
            s = storage_password
        else:
            s = storage_password[:3] + "..." + storage_password[-2:]
        print(str(i), "[P]", f"{s!r}")
