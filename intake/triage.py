def triage(known: bool) -> str:
    if known:
        return "KNOWN_MALICIOUS"
    return "UNKNOWN_SAMPLE"
