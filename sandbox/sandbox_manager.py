def initialize_sandbox(sample_path: str) -> dict:
    return {
        "sandbox": "docker-container",
        "mode": "static-only",
        "network": "disabled",
        "mounted_path": sample_path
    }
