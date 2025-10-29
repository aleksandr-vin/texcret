import os
import shutil
import subprocess
import platform


# For more info, see https://velvetcache.org/2023/03/26/a-peek-inside-pinentry/


class PinentryError(RuntimeError):
    pass


def call_pinentry_getpin(
    prompt: str,
    desc: str | None = None,
    title: str | None = None,
    allow_external_password_cache: bool = False,
    cache_key_info: str | None = None,
    program: str = os.environ.get("PINENTRY", "pinentry"),
) -> str:
    # quick availability check
    if shutil.which(program) is None:
        raise FileNotFoundError(f"{program} not found in PATH")

    p = subprocess.Popen(
        [program],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        bufsize=1,  # line-buffered
    )

    def send(cmd: str):
        # commands to pinentry must end with "\n"
        p.stdin.write(cmd + "\n")
        p.stdin.flush()

    def read_resp():
        """read responses until OK or ERR/BYE"""
        pin = None
        while True:
            line = p.stdout.readline()
            # print(f">>> {line=}")
            if not line:
                break
            line = line.rstrip("\n")
            # data line with secret: starts with 'D '
            if line.startswith("D "):
                pin = line[2:]
            elif line.startswith("OK"):
                return "ok", pin
            elif line.startswith("ERR"):
                # ERR <code> <message>
                return "error", line
            elif line.startswith("CANCEL"):
                return "cancel", line
            # otherwise ignore informational lines

    def command(cmd):
        send(cmd)
        code, data = read_resp()
        if code != "ok":
            raise PinentryError(f"{code}: {data}")
        return data

    def reply():
        code, data = read_resp()
        if code != "ok":
            raise PinentryError(f"{code}: {data}")
        return data

    command(f"OPTION ttyname={os.ttyname(1)}")
    command(f"OPTION ttytype={os.environ.get('TERM', 'vt100')}")
    command(f"OPTION lc-ctype={os.environ.get('LANG', 'en_US.UTF-8')}")

    # set optional fields
    title and command(f"SETTITLE {title}")
    # description may contain spaces; pinentry takes the whole remaining fields
    desc and command(f"SETDESC {desc}")
    # set the prompt shown on UI
    command(f"SETPROMPT {prompt}")

    if allow_external_password_cache:
        command("OPTION allow-external-password-cache")
        command(
            f"SETKEYINFO --{cache_key_info}"
        )  # No idea why first 2 chars are lost and not saved in keychain in mac, placeholding with ``--''

    # ask for the pin (this will pop up the configured UI)
    command("GETPIN")
    pin = reply()

    # tell pinentry to exit politely
    try:
        command("BYE")
    except Exception:
        pass
    p.stdin.close()
    p.stdout.close()
    p.stderr.close()
    p.wait()

    if pin is None:
        raise PinentryError("no pin returned")

    return pin


def clear_pinentry_external_cache(cache_key_info):
    system = platform.system()
    if system == "Darwin":
        # macOS Keychain
        for service in ["GnuPG"]:
            subprocess.run(
                [
                    "security",
                    "delete-generic-password",
                    "-s",
                    service,
                    "-a",
                    cache_key_info,
                ],
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                check=False,
            )
    elif system == "Linux":
        # GNOME keyring (via secret-tool)
        subprocess.run(["secret-tool", "clear", "label", "GnuPG"], check=False)
    else:
        print("No known external cache mechanism for this platform.")


# usage
if __name__ == "__main__":
    try:
        secret = call_pinentry_getpin(
            "Enter passphrase:", desc="Secret for my app", title="MyApp Login"
        )
        print("Got secret of length", len(secret))
    except Exception as e:
        print("Failed:", e)
