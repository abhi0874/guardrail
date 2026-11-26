"""Locate read-only assets in a source checkout or an installed wheel."""

from pathlib import Path

PACKAGE = Path(__file__).resolve().parent
ROOT = PACKAGE / "_bundle" if (PACKAGE / "_bundle").is_dir() else PACKAGE.parents[1]
