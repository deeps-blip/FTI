# Federated Threat Intelligence (FTI)

Federated Threat Intelligence (FTI) is a **modular static malware analysis framework** built using **Python** and **radare2**.  
It focuses on **reliable function discovery, metadata extraction, and structured report generation** in a reproducible local or containerized environment.

FTI is designed as a **foundation for collaborative and federated threat intelligence research**, prioritizing stability, determinism, and clean architecture over aggressive or speculative analysis.

---

## Key Objectives

- Provide a **stable static analysis pipeline** for malware samples
- Extract **verifiable features** suitable for downstream intelligence tasks
- Ensure **deterministic behavior** across local and Docker executions
- Act as a **baseline platform** for future federated learning integration

---

## Features

- Static malware analysis using **radare2**
- Reliable function enumeration (`aflj`)
- Cryptographic file metadata extraction:
  - MD5
  - SHA1
  - SHA256
- File size and entropy calculation
- Structured JSON reporting
- Timestamped feature directories per sample
- Dockerized execution for reproducibility
- Clear separation of concerns across modules

---

## Analysis Pipeline

1. **Sample ingestion**
   - Reads binaries from `data/samples/`
2. **Static analysis**
   - Loads binary using radare2
   - Performs basic analysis (`aa`)
3. **Function extraction**
   - Enumerates discovered functions
4. **Metadata extraction**
   - Hashes, size, entropy
5. **Report generation**
   - Writes structured JSON output to `data/features/`

Each sample generates a **dedicated, timestamped report directory**.

---

## Output Format

 <sample.exe>_{timestamp}/ under the features folder in the data folder


### Example `analysis.json`

```json
{
  "file_metadata": {
    "binary_name": "sample.exe",
    "md5": "…",
    "sha1": "…",
    "sha256": "…",
    "size_bytes": 55296,
    "entropy": 6.03
  },
  "functions": [
    {
      "name": "entry0",
      "offset": 4198400
    }
  ],
  "risk": {
    "verdict": "baseline_analysis",
    "score": 0
  }
}

```
### Getting Started (Local)
Requirements

Python 3.11 or 3.12 (recommended)

radare2

r2pipe
---
# Installation
```bash
pip install -r requirements.txt
```
---
# Run Analysis
```bash
python ingest_file.py
```

# Reports will be written to:
```bash
data/features/
```
---
# Docker Usage
-Build and Run
```bash
docker compose up --build
```
---
## Notes

- `data/samples` and `data/features` are mounted as Docker volumes
- Generated reports persist on the host filesystem
- Docker ensures reproducible and isolated execution environments

---

## Known Limitations

- Static analysis only (no dynamic execution)
- Packed or heavily obfuscated binaries may yield limited results
- Function semantics are not yet inferred
- Federated learning is planned but not yet implemented

---

## Roadmap

- Function behavior classification
- Call graph generation
- Feature normalization for federated learning
- Command-line interface (CLI)
- Regression and stability testing
- Report schema versioning

---

## Design Principles

- Stability over aggressiveness
- Deterministic analysis
- Minimal assumptions
- Clear module boundaries
- Reports are always generated or fail loudly

This project intentionally avoids experimental analysis until a strong and reliable baseline is established.

---

## License

This project is provided for **research and educational purposes only**.  
Users are responsible for ensuring compliance with applicable laws when handling malware samples.

---

## Contributions

Contributions are welcome, especially in the areas of:

- Static analysis improvements
- Report schema enhancements
- Testing and validation
- Documentation

Please open an issue or submit a pull request.
