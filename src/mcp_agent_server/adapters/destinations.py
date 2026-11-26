"""Only canonical ASCII DNS names may appear in the operator's exact allowlist."""

import re


def canonical_host(value: str) -> str:
    host = value.lower()
    labels = host.split(".")
    if (
        not value.isascii()
        or len(host) > 253
        or len(labels) < 2
        or not re.fullmatch("[a-z]{2,63}", labels[-1])
        or any(
            not re.fullmatch(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", s) or s.startswith("xn--")
            for s in labels
        )
        or any(
            s
            in {
                "localhost",
                "local",
                "localdomain",
                "internal",
                "intranet",
                "lan",
                "home",
                "corp",
                "arpa",
                "onion",
            }
            for s in labels
        )
    ):
        raise ValueError("Use an exact public ASCII DNS name")
    return host
