from __future__ import annotations

from importlib.resources import files
from pathlib import Path

_LOGO_BANNER = r"""
 __     __         _ _   _   _  __
 \ \   / /_ _ _  _| | |_| | / |/ /___   _____  __
  \ \ / / _` | || | | __| | | ' // _ \ / _ \ \/ /
   \ V / (_| | |_| | | |_| | | . \ (_) | (_) >  <
    \_/ \__,_|\__,_|_|\__|_| |_|\_\___/ \___/_/\_\

 Secure Secret Add-On
""".strip("\n")


def get_logo_banner() -> str:
    return _LOGO_BANNER


def get_logo_asset_path() -> Path:
    """Return the packaged logo path (SVG preferred, PNG fallback)."""
    return Path(str(files("vaultknox").joinpath("assets/vaultknox-logo.svg")))


def get_logo_png_path() -> Path:
    """Return the packaged PNG logo path (for web/GitHub usage)."""
    return Path(str(files("vaultknox").joinpath("assets/vaultknox-logo.png")))
