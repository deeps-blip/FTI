#!/bin/bash
set -e

SAMPLE_DIR="/app/data/samples"
SANDBOX_DIR="/sandbox/malware"

echo "[+] Preparing for analysis..."
mkdir -p "$SANDBOX_DIR"

# Check if there are any files to move before iterating
# Using nullglob to avoid error if no files match
shopt -s nullglob
files=("$SAMPLE_DIR"/*)
if [ ${#files[@]} -gt 0 ]; then
    echo "[+] Moving malware samples into sandbox..."
    for file in "${files[@]}"; do
        if [ -f "$file" ]; then
            fname=$(basename "$file")
            echo "[+] Ingesting: $fname"
            cp "$file" "$SANDBOX_DIR/$fname"
            if rm -f "$file"; then
                echo "[+] Host copy removed"
            else
                echo "[!] Failed to remove host file"
            fi
        fi
    done
else
    echo "[*] No new samples found in $SAMPLE_DIR."
fi

echo "[+] Starting Malware Analysis Pipeline..."
# Run the analysis script. This will block until all files in SANDBOX_DIR are processed.
# We run it here so it happens inside the Docker environment as requested.
python3 ingest_file.py || echo "[!] Analysis pipeline encountered errors but continuing..."

echo "[+] Analysis complete. Starting Backend Service..."
exec "$@"
