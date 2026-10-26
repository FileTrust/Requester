#!/usr/bin/env python3
import os
import sys

if __name__ == "__main__":
    from pathlib import Path
    from ft_update_bootstrap import enter
    enter(Path(__file__).resolve().parent)

# Ensure App/REQ/ is on sys.path so 'core' is importable as a package.
_this_dir = os.path.dirname(os.path.abspath(__file__))
if _this_dir not in sys.path:
    sys.path.insert(0, _this_dir)


def _restart_in_app_environment() -> None:
    """Start over using the interpreter install.sh prepared, if we are not it.

    `python3 REQ.py` is the obvious thing to type, and it is wrong: the system
    interpreter has none of the packages install.sh installed. So if the
    environment install.sh builds is sitting right next to this file, hand over
    to it rather than failing on an import the user cannot place.
    """
    if os.environ.get("FILETRUST_REQ_RESTARTED") == "1":
        return  # already tried once; never loop
    venv = os.path.join(_this_dir, ".venv")
    if os.path.realpath(sys.prefix) == os.path.realpath(venv):
        return  # this *is* the app environment
    for rel in (("bin", "python"), ("Scripts", "python.exe")):
        candidate = os.path.join(venv, *rel)
        if os.access(candidate, os.X_OK):
            break
    else:
        return  # not installed yet; run with whatever we have
    os.environ["FILETRUST_REQ_RESTARTED"] = "1"
    print("Starting with the app's own Python environment.", file=sys.stderr)
    try:
        os.execv(candidate, [candidate, os.path.abspath(__file__), *sys.argv[1:]])
    except OSError as exc:
        # A damaged venv should not stop the app from opening at all.
        print(f"  could not use it ({exc}); continuing with {sys.executable}",
              file=sys.stderr)


def _require_account() -> None:
    """Refuse to open the window when there is no usable account, and say why.

    install.sh offers to create an account and a user may decline, so "no key
    yet" is an expected state rather than a broken install. REQ would otherwise
    open normally and fail on the first download, because its address is what a
    Data Owner shares files with.
    """
    from core import req_config as C

    if getattr(C, "ACCOUNT_READY", False):
        return

    where = getattr(C.config, "CONFIG_PATH", "config.json")
    message = (
        f"{C.ACCOUNT_PROBLEM}.\n\n"
        "The Requester app needs an account: its address is what a Data Owner "
        "shares files with, and it signs each download request.\n\n"
        "Either let the installer create one for you:\n"
        "    ./install.sh --new-account\n\n"
        "or put your own private key into this file, as req_private_key:\n"
        f"    {where}\n\n"
        "Then give your address to whoever is sharing files with you."
    )
    print(f"\n{message}\n", file=sys.stderr)
    try:
        import tkinter as tk
        from tkinter import messagebox

        root = tk.Tk()
        root.withdraw()
        messagebox.showerror("FileTrust Requester — no account yet", message)
        root.destroy()
    except Exception:
        pass  # no display: the message is on the terminal either way
    raise SystemExit(2)


def _unlock_account() -> None:
    """Ask for the password, and the code, before anything needs the key.

    This runs before `core.req_config` is imported anywhere, because that
    module derives the signing account the moment it loads. An install with no
    keyvault.json -- everyone who has not chosen a password -- passes straight
    through.
    """
    from core import ft_unlock

    ready, problem = ft_unlock.unlock_app_key(_this_dir, "FileTrust Requester")
    if ready:
        return
    if problem == "cancelled":
        raise SystemExit(1)
    message = (
        f"The app could not be unlocked: {problem}.\n\n"
        "The account key is in keyvault.json, encrypted with your password. "
        "Nobody can recover that password -- not us, and not a reinstall.\n\n"
        "If you have lost it, this requester address is gone with it, and the "
        "only way forward is a new account, which each Data Owner then has to "
        "share with again:\n"
        "    ./install.sh --new-account"
    )
    print(f"\n{message}\n", file=sys.stderr)
    try:
        import tkinter as tk
        from tkinter import messagebox

        root = tk.Tk()
        root.withdraw()
        messagebox.showerror("FileTrust Requester — locked", message)
        root.destroy()
    except Exception:
        pass
    raise SystemExit(2)


_restart_in_app_environment()

if __name__ == "__main__":
    _unlock_account()
    _require_account()
    from core.req_ui import build_ui

    build_ui()
else:
    from core.req_ui import build_ui
