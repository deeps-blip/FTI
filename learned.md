# FTI Project Analysis - Learned Documentation

## System Overview
Federated Threat Intelligence (FTI) is a hybrid malware analysis platform. It combines static analysis (via radare2), dynamic analysis (via strace), and AI-driven insights (Gemini) to generate comprehensive threat reports.

## Core Components
- **Intake Service (`intake/`)**: Handles file classification, hashing, and initial triage.
- **Extractors (`extractors/`)**: Performs static analysis tasks:
    - `strings.py`: Extracts strings from binaries.
    - `imports.py`: Lists imported libraries and functions.
    - `functions.py`: Discovers and analyzes binary functions.
    - `data_targets.py`: Identifies sensitive data targets.
- **Sandbox (`sandbox/`)**: Handles dynamic analysis:
    - `dynamic_runner.py`: Executes the binary using `strace` for syscall monitoring.
    - `syscall_parser.py`: Aggregates raw syscall logs into behavioral categories.
- **Intelligence (`intelligence/`)**: The "brain" of the system:
    - `intent_classifier.py`: Maps function features to purposes (e.g., networking, crypto) using rule-based keyword matching.
    - `risk_scorer.py`: Calculates a risk score and severity based on static intents and dynamic behaviors using hardcoded weights (`CATEGORY_WEIGHTS`).
    - `report_builder.py`: Orchestrates the output of JSON metadata, threat summaries, and call graphs into `data/features/`.
- **Backend (`api.py`)**: FastAPI server providing endpoints for sample listing, analysis, and report generation.
- **Frontend (`frontend/`)**: Vite-powered interactive dashboard with a retro-terminal UI.

## Analysis Workflow
1.  **Input**: Sample binary placed in `data/samples/`.
2.  **Static Phase**: `RadareRunner` initializes radare2, performs deep analysis (`aaaa`), and extractors pull technical indicators.
3.  **Dynamic Phase**: Binary is executed under `strace`, and syscalls are categorized.
4.  **Scoring Phase**: `risk_scorer.py` fuses static and dynamic findings into a final risk score and verdict.
5.  **Output**: A timestamped directory is created in `data/features/` containing structured JSON reports and a callgraph.

## Current Implementation: Federated Learning (FL)
The system has been evolved from a purely rule-based engine to a federated network:
- **Feature Vectorization**: `intelligence/feature_vector.py` converts analysis results into 10D tensors for model training.
- **Federated Models**: 
    - `FederatedRiskScorer`: Replaces/Augments hardcoded weights with a trainable linear model.
- **Infrastructure**:
    - `federated/server.py`: FastAPI aggregator performing FedAvg.
    - `federated/client.py`: Local trainer using scikit-learn SGDClassifier.
    - `Dockerfile.aggregator`: Containerized aggregator service.
- **Integration**:
    - `intelligence/risk_scorer.py` now prioritizes ML model predictions with a fallback to legacy rules.
    - Frontend includes a "Federated Learning" module to trigger global sync.
