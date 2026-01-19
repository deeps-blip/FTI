import os
import sys
import json

# -----------------------------
# Intake imports
# -----------------------------
from intake.integrity_check import validate_file
from intake.hash_checker import compute_hashes, is_known
from intake.file_classifier import classify_file
from intake.triage import triage

# -----------------------------
# Sandbox imports
# -----------------------------
from sandbox.mount_manager import mount_readonly
from sandbox.sandbox_manager import initialize_sandbox

# -----------------------------
# Static analysis (radare2)
# -----------------------------
from analyzer import analyze_binary


SAMPLES_DIR = "data/samples"


# -----------------------------
# Sample discovery
# -----------------------------
def get_sample_files():
    if not os.path.isdir(SAMPLES_DIR):
        return []

    return [
        os.path.join(SAMPLES_DIR, f)
        for f in os.listdir(SAMPLES_DIR)
        if os.path.isfile(os.path.join(SAMPLES_DIR, f))
    ]


# -----------------------------
# File processing pipeline
# -----------------------------
def process_file(path: str, index: int, total: int):
    print(f"\nProcessing file {index}/{total}")
    print(f"Path: {path}")

    # -----------------------------
    # Phase 1 – Integrity & Validation
    # -----------------------------
    if not validate_file(path):
        print("Validation failed")
        return

    hashes = compute_hashes(path)
    known_result = is_known(hashes)

    known = known_result.get("known", False)
    matched_on = known_result.get("matched_on")

    file_type = classify_file(path)
    triage_status = triage(known)

    # -----------------------------
    # Phase 1 – Sandbox Setup
    # -----------------------------
    mounted = mount_readonly(path)
    sandbox = initialize_sandbox(mounted)

    print("\n--- Intake Summary ---")
    print("MD5:", hashes["md5"])
    print("SHA1:", hashes["sha1"])
    print("SHA256:", hashes["sha256"])
    print("Known:", known)
    print("Matched on:", matched_on)
    print("File type:", file_type)
    print("Triage:", triage_status)
    print("Sandbox:", sandbox)

    # -----------------------------
    # Phase 2 – Static Malware Dissection
    # -----------------------------
    print("\n--- Phase 2: Static Malware Analysis (radare2) ---")

    try:
        report = analyze_binary(path)

        print("Static analysis completed successfully")
        print("Analysis artifacts stored at:")
        print(report["report_path"])

    except Exception as e:
        print("Static analysis failed:", str(e))
        return

    # -----------------------------
    # Phase transition
    # -----------------------------
    print("\nState: READY_FOR_FEDERATED_LEARNING")


# -----------------------------
# Entry point
# -----------------------------
def main():
    if len(sys.argv) >= 2:
        files = [sys.argv[1]]
    else:
        files = get_sample_files()

    if not files:
        print("No samples found")
        return

    total_files = len(files)

    print("Phase 1 – Malware Intake")
    print("Samples directory:", SAMPLES_DIR)
    print("Total files:", total_files)

    for idx, path in enumerate(files, start=1):
        process_file(path, idx, total_files)

    print("\nPipeline completed successfully")


if __name__ == "__main__":
    main()
