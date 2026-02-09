from __future__ import annotations

from importlib import metadata


def get_version() -> str:
    try:
        return metadata.version("jwt-workbench")
    except metadata.PackageNotFoundError:
        # Allows running from source without an installed dist (best-effort).
        return "0.0.0"


__version__ = get_version()
