# Federated Learning Implementation Strategy (FTI) - Docker Optimized

## 1. Vision
Transform the FTI from a standalone, rule-based analysis tool into a **collaborative intelligence network**. Federated Learning (FL) will allow multiple FTI instances (at different organizations) to collectively train a high-accuracy malware detection model without ever sharing raw binary samples or sensitive local feature logs.

## 2. Target Models for Federation
We will replace the current hardcoded logic with two federated models:
1.  **Federated Intent Classifier (FIC)**: Replaces `PURPOSE_RULES` in `intent_classifier.py` with a model that learns to map function metadata (symbols, syscalls, strings) to behavioral purposes.
2.  **Federated Risk Scorer (FRS)**: Replaces `CATEGORY_WEIGHTS` in `risk_scorer.py` with a model that learns the optimal weights for fusing static and dynamic indicators into a final risk score.

## 3. Architecture Overview (Docker Native)
The system will operate as a multi-container ecosystem:

- **Local Client (FTI Node Container)**: 
    - The existing `intake` service will act as the FL Client.
    - Performs standard analysis and collects ground truth from Gemini AI.
    - Trains local updates on the `data/features` volume.
    - Communicates with the aggregator via the internal `fti-network`.
- **Central Aggregator (FTI Aggregator Container)**:
    - A new microservice (`fti-aggregator`) dedicated to model management.
    - Distributes the latest "Global Model" weights via a REST API.
    - Performs **FedAvg** (Federated Averaging) on received updates.

## 4. Docker Implementation Details

### Service Orchestration
The `docker-compose.yml` will be expanded to include the aggregator:
```yaml
  aggregator:
    build: 
      context: .
      dockerfile: Dockerfile.aggregator
    container_name: fti-aggregator
    networks:
      - fti-network
    volumes:
      - ./data/global_models:/app/models
```

### Persistent Volumes
- **/app/data/features**: Stores local analysis results (training data).
- **/app/models**: A new persistent volume to store global and local model weights (`.pt` or `.h5` files), ensuring persistence across container restarts.

### Networking & Security
- **Internal Communication**: Clients will reach the aggregator at `http://aggregator:8001`.
- **Isolation**: The aggregator can be hosted on a separate machine or a central cloud server in a real-world multi-org scenario.

## 5. Feature Vectorization Strategy
To train models, we must convert raw JSON analysis into numeric tensors:
- **Static Features**: Bag-of-words or TF-IDF on `called_symbols`, `string_refs`, and `imports`.
- **Dynamic Features**: Normalized counts of syscall categories (network, file, process, etc.).
- **Metadata Features**: Entropy, file size, and header flags.

## 6. Proposed Implementation Roadmap

### Phase 1: Feature Engineering & Local Learning
- **Task**: Create `intelligence/feature_vector.py` to transform `analysis.json` reports into training-ready tensors.
- **Task**: Implement a local training script that uses existing analysis results as training data.

### Phase 2: Federated Infrastructure (Dockerized)
- **Task**: Create `Dockerfile.aggregator` and update `docker-compose.yml`.
- **Task**: Develop `federated/client.py`: Handles weight synchronization with the aggregator service.
- **Task**: Develop `federated/server.py`: The FastAPI-based aggregation logic for the `aggregator` service.

### Phase 3: Integration
- **Task**: Modify `intelligence/risk_scorer.py` to use model predictions.
- **Task**: Add a "Contribute to Global Intelligence" toggle in the Frontend.

## 7. Security & Privacy
- **Differential Privacy**: Add noise to local weight updates to prevent "model inversion" attacks.
- **Secure Aggregation**: Use cryptographic techniques to ensure the server only sees the *sum* of updates.

## 8. Immediate Next Steps
1.  **Define the Schema**: Finalize the feature vector format.
2.  **Seed the Global Model**: Train an initial "Base Model" using the current `sample_outputs` and hardcoded rules.
