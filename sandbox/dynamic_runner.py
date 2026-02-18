import subprocess
import os
import tempfile
import shutil

BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))


def run_with_strace(relative_sample_path, timeout=10):
    """
    Runs a binary under strace from a writable /tmp location.
    relative_sample_path example: data/samples/malware1
    """

    # --------------------------------------------------
    # Resolve original sample path
    # --------------------------------------------------
    sample_path = os.path.join(BASE_DIR, relative_sample_path)

    if not os.path.exists(sample_path):
        raise FileNotFoundError(f"Sample not found: {sample_path}")

    # --------------------------------------------------
    # Create isolated temp directory
    # --------------------------------------------------
    temp_dir = tempfile.mkdtemp(prefix="fti_sandbox_")

    # Copy binary into /tmp
    temp_binary_path = os.path.join(
        temp_dir,
        os.path.basename(sample_path)
    )

    shutil.copy2(sample_path, temp_binary_path)

    # Make temp copy executable
    os.chmod(temp_binary_path, 0o755)

    # Create trace output file inside temp dir
    trace_file = os.path.join(temp_dir, "trace.log")

    cmd = [
        "strace",
        "-f",
        "-tt",
        "-s", "256",
        "-o", trace_file,
        temp_binary_path
    ]

    # --------------------------------------------------
    # Execute under strace
    # --------------------------------------------------
    try:
        subprocess.run(
            cmd,
            timeout=timeout,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL
        )
    except subprocess.TimeoutExpired:
        pass

    # --------------------------------------------------
    # Read trace output
    # --------------------------------------------------
    if os.path.exists(trace_file):
        with open(trace_file, "r", errors="ignore") as f:
            data = f.read()
    else:
        data = ""

    # --------------------------------------------------
    # Cleanup sandbox directory
    # --------------------------------------------------
    try:
        shutil.rmtree(temp_dir)
    except Exception:
        pass

    return data
