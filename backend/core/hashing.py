"""Hashing y métricas básicas."""

from __future__ import annotations

import hashlib
import math
from collections import Counter


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def md5_bytes(data: bytes) -> str:
    return hashlib.md5(data).hexdigest()


def entropy(data: bytes) -> float:
    """Entropía de Shannon (0..8) sobre bytes."""
    if not data:
        return 0.0
    counts = Counter(data)
    total = len(data)
    return -sum((c / total) * math.log2(c / total) for c in counts.values())


def printable_ratio(data: bytes) -> float:
    if not data:
        return 0.0
    printable = sum(1 for b in data if 32 <= b < 127 or b in (9, 10, 13))
    return printable / len(data)


def shannon_normalized(data: bytes) -> float:
    return round(entropy(data) / 8.0, 4)
