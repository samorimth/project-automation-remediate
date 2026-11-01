"""Identidade do script usado na aprovação. O hash é SHA-256 do texto UTF-8."""

import hashlib


def compute_sha256(content: str) -> str:
    return hashlib.sha256(content.encode("utf-8")).hexdigest()
