def extract_strings(r2):
    strings = r2.cmdj("izj") or []
    return [s["string"] for s in strings if "string" in s]
