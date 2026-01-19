import re

URL_REGEX = re.compile(r"https?://[^\s]+")
FILE_REGEX = re.compile(r"[A-Za-z]:\\\\[^\s]+")


def extract_data_targets(strings):
    urls = []
    files = []
    registry = []

    for s in strings:
        if URL_REGEX.search(s):
            urls.append(s)
        if FILE_REGEX.search(s):
            files.append(s)
        if "HKCU\\" in s or "HKLM\\" in s:
            registry.append(s)

    return {
        "urls": list(set(urls)),
        "files": list(set(files)),
        "registry_keys": list(set(registry))
    }
