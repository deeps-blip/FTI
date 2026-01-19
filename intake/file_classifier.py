import subprocess

def classify_file(path: str) -> str:
    output = subprocess.check_output(["file", path]).decode().lower()

    if "elf" in output:
        return "ELF"
    if "pe32" in output or "dll" in output:
        return "DLL"
    if path.endswith(".py"):
        return "PYTHON"

    return "UNKNOWN"
