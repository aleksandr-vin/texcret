from importlib.metadata import version, PackageNotFoundError

import typer
from rich import print

import texcret.commands as commands

try:
    __version__ = version("texcret")
except PackageNotFoundError:
    __version__ = "unknown"

app = typer.Typer(add_completion=False, no_args_is_help=True)

for cmd in commands.__all__:
    app.command()(cmd)


@app.command("version")
def version():
    """Print version."""
    print(f"Texcret version: {__version__}")


if __name__ == "__main__":
    app()
