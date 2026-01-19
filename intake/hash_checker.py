import hashlib


def compute_hashes(path: str) -> dict:
    """
    Compute MD5, SHA1, and SHA256 hashes for a file.
    """
    md5 = hashlib.md5()
    sha1 = hashlib.sha1()
    sha256 = hashlib.sha256()

    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(8192), b""):
            md5.update(chunk)
            sha1.update(chunk)
            sha256.update(chunk)

    return {
        "md5": md5.hexdigest(),
        "sha1": sha1.hexdigest(),
        "sha256": sha256.hexdigest()
    }


def is_known(hashes: dict, db_path="config/hashes.db") -> dict:
    """
    Check MD5, SHA1, and SHA256 hashes against known hash database.
    Returns match status and matched hash type.
    """
    try:
        with open(db_path) as f:
            known_hashes = set(line.strip().lower() for line in f if line.strip())
    except FileNotFoundError:
        return {
            "known": False,
            "matched_on": None
        }

    for algo, value in hashes.items():
        if value.lower() in known_hashes:
            return {
                "known": True,
                "matched_on": algo
            }

    return {
        "known": False,
        "matched_on": None
    }
