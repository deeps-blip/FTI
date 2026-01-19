CRITICAL_APIS = {
    "process_injection": [
        "WriteProcessMemory",
        "CreateRemoteThread",
        "NtWriteVirtualMemory"
    ],
    "credential_theft": [
        "CredRead",
        "LSA",
        "LogonUser"
    ],
    "persistence": [
        "RegSetValue",
        "RegCreateKey",
        "schtasks",
        "Startup"
    ],
    "network_exfiltration": [
        "send",
        "recv",
        "WinHttp",
        "InternetOpen"
    ],
    "evasion": [
        "IsDebuggerPresent",
        "CheckRemoteDebuggerPresent",
        "Sleep"
    ],
    "crypto_ransom": [
        "CryptEncrypt",
        "AES",
        "RSA"
    ]
}


def map_functions(functions):
    mapped = []

    for f in functions:
        signal = " ".join(
            f.get("called_symbols", []) +
            f.get("string_refs", []) +
            f.get("syscalls", [])
        ).lower()

        behaviors = []
        critical = False

        for category, indicators in CRITICAL_APIS.items():
            if any(i.lower() in signal for i in indicators):
                behaviors.append(category)
                critical = True

        if not behaviors:
            behaviors.append("control_or_dispatch")

        mapped.append({
            "function": f["name"],
            "behaviors": behaviors,
            "critical_system_threat": critical
        })

    return mapped
