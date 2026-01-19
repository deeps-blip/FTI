import math

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

    return entropy


def detect_obfuscation(r2, binary_path):
    sections = r2.cmdj("iSj") or []
    binary = open(binary_path, "rb").read()

    high_entropy_sections = []

    for sec in sections:
        name = sec.get("name", "")
        size = sec.get("size", 0)
        vaddr = sec.get("vaddr")

        if not vaddr or size <= 0:
            continue

        chunk = binary[:size]
        ent = shannon_entropy(chunk)

        if ent > 7.2:
            high_entropy_sections.append(name)

    return {
        "packed_or_obfuscated": bool(high_entropy_sections),
        "high_entropy_sections": high_entropy_sections
    }
