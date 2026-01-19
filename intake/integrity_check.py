import os

def validate_file(path: str, max_size_mb=20) -> bool:
    if not os.path.exists(path):
        return False
    size_ok = os.path.getsize(path) <= max_size_mb * 1024 * 1024
    return size_ok
