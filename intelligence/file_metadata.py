import hashlib
import math
from pathlib import Path


def shannon_entropy(data: bytes):
    if not data:
        return 0.0

    freq = {}
    for b in data:
        freq[b] = freq.get(b, 0) + 1

    entropy = 0.0
    length = len(data)

    for count in freq.values():
        p = count / length
        entropy -= p * math.log2(p)

    return round(entropy, 3)


def extract_file_metadata(path):
    data = Path(path).read_bytes()

    return {
        "md5": hashlib.md5(data).hexdigest(),
        "sha1": hashlib.sha1(data).hexdigest(),
        "sha256": hashlib.sha256(data).hexdigest(),
        "size_bytes": len(data),
        "entropy": shannon_entropy(data)
    }
