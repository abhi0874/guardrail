"""Check the exported source inventory without accessing local credentials."""

import hashlib
import json
import subprocess
from pathlib import Path

FORBIDDEN = {
    ".venv",
    ".cache",
    ".runtime",
    "__pycache__",
    "node_modules",
    ".next",
    ".vercel",
    "out",
    "test-results",
    "playwright-report",
}
ROOTS = {
    "src",
    "security-tests",
    "web",
    "tests",
    "policies",
    "docs",
    "examples",
    "scripts",
    ".github",
}
FILES = {
    ".env.example",
    ".gitignore",
    ".dockerignore",
    ".pre-commit-config.yaml",
    ".python-version",
    "README.md",
    "CONTRIBUTING.md",
    "ACKNOWLEDGMENTS.md",
    "CODE_OF_CONDUCT.md",
    "SECURITY.md",
    "LICENSING.md",
    "LICENSE",
    "Makefile",
    "Dockerfile",
    "Dockerfile.ci",
    "Dockerfile.cloud",
    "compose.yaml",
    "pyproject.toml",
    "uv.lock",
}


def main() -> None:
    paths = subprocess.check_output(
        ["git", "ls-files", "--cached", "--others", "--exclude-standard", "-z"]
    ).split(b"\0")
    inventory = {}
    for raw in paths:
        if not raw:
            continue
        p = Path(raw.decode())
        assert p.parts[0] in ROOTS or str(p) in FILES, str(p)
        assert not set(p.parts) & FORBIDDEN, str(p)
        assert not p.is_symlink() and p.is_file(), str(p)
        assert p.name == ".env.example" or not p.name.startswith(".env"), str(p)
        assert p.suffix not in {".db", ".sqlite3", ".pem", ".key", ".log", ".pyc"}, str(p)
        data = p.read_bytes()
        assert (b"-----BEGIN " + b"PRIVATE KEY-----" + bytes([10])) not in data, str(p)
        if p.parts[0] in {"src", "scripts", ".github"}:
            assert (b"/" + b"Users/") not in data, str(p)
        inventory[str(p)] = hashlib.sha256(data).hexdigest()
    print(
        json.dumps({"files": len(inventory), "runtime_artifacts": 0, "source_inventory": inventory})
    )


if __name__ == "__main__":
    main()
