#!/bin/bash

SAMPLE_DIR="/app/data/samples"
SANDBOX_DIR="/sandbox/malware"

echo "[+] Moving malware samples into sandbox..."

mkdir -p $SANDBOX_DIR

for file in $SAMPLE_DIR/*; do
    if [ -f "$file" ]; then
        fname=$(basename "$file")

        echo "[+] Ingesting $fname"

        cp "$file" "$SANDBOX_DIR/$fname"

        if rm -f "$file"; then
            echo "[+] Host copy removed"
        else
            echo "[!] Failed to remove host file"
        fi
    fi
done

echo "[+] Starting analysis..."

exec "$@"