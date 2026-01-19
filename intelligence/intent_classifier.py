PURPOSE_RULES = {
    "network_communication": ["send", "recv", "connect", "http", "internet"],
    "file_access": ["createfile", "readfile", "writefile"],
    "persistence": ["regset", "autorun", "startup", "schtasks"],
    "credential_access": ["password", "cred", "token"],
    "process_injection": ["writeprocessmemory", "createremotethread"],
    "anti_analysis": ["debug", "sandbox", "sleep", "vm"],
    "crypto": ["crypt", "aes", "rsa", "xor"],
}


def classify_functions(functions):
    classified = []

    for f in functions:
        signal = " ".join(
            f["called_symbols"] + f["string_refs"] + f["syscalls"]
        ).lower()

        purposes = []

        for purpose, indicators in PURPOSE_RULES.items():
            if any(i in signal for i in indicators):
                purposes.append(purpose)

        if not purposes:
            purposes = ["control_or_dispatch"]

        classified.append({
            "function": f["name"],
            "purposes": purposes
        })

    return classified
