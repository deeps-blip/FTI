NETWORK_APIS = {"connect", "recv", "send", "WinHttpOpen"}
FILE_APIS = {"CreateFile", "ReadFile", "WriteFile"}
PERSISTENCE_APIS = {"RegSetValue", "RegCreateKey", "schtasks"}


def map_capabilities(imports, data_targets):
    imports_set = set(imports)

    return {
        "networking": bool(imports_set & NETWORK_APIS or data_targets["urls"]),
        "filesystem": bool(imports_set & FILE_APIS or data_targets["files"]),
        "persistence": bool(imports_set & PERSISTENCE_APIS or data_targets["registry_keys"]),
        "credential_access": any("password" in s.lower() for s in data_targets["files"])
    }
