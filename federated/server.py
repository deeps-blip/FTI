import os
import json
import logging
import numpy as np
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
from typing import List

# Setup logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = FastAPI(title="FTI Federated Aggregator")

MODELS_DIR = os.environ.get("MODELS_DIR", "data/global_models")
GLOBAL_WEIGHTS_PATH = os.path.join(MODELS_DIR, "global_frs_weights.npy")
GLOBAL_BIAS_PATH = os.path.join(MODELS_DIR, "global_frs_bias.npy")

class ModelUpdate(BaseModel):
    client_id: str
    weights: List[float]
    bias: float
    num_samples: int

# In-memory storage for client updates
client_updates = {}

def load_global_model():
    if os.path.exists(GLOBAL_WEIGHTS_PATH) and os.path.exists(GLOBAL_BIAS_PATH):
        weights = np.load(GLOBAL_WEIGHTS_PATH)
        bias = np.load(GLOBAL_BIAS_PATH)
        return weights.tolist(), float(bias)
    return None, None

def save_global_model(weights, bias):
    os.makedirs(MODELS_DIR, exist_ok=True)
    np.save(GLOBAL_WEIGHTS_PATH, np.array(weights))
    np.save(GLOBAL_BIAS_PATH, np.array(bias))

@app.post("/update")
async def receive_update(update: ModelUpdate):
    """Receive a local model update from a client."""
    client_updates[update.client_id] = {
        "weights": np.array(update.weights),
        "bias": update.bias,
        "num_samples": update.num_samples
    }
    logger.info(f"Received update from {update.client_id} with {update.num_samples} samples.")
    
    # Perform aggregation if we have enough clients (e.g., at least 1, but we can aggregate every time for simplicity in this prototype)
    aggregate_models()
    return {"status": "Update received and aggregated"}

def aggregate_models():
    """Perform Federated Averaging (FedAvg)."""
    if not client_updates:
        return

    total_samples = sum(info["num_samples"] for info in client_updates.values())
    if total_samples == 0:
        return

    # Initialize empty arrays
    first_client = list(client_updates.values())[0]
    agg_weights = np.zeros_like(first_client["weights"])
    agg_bias = 0.0

    # Weighted sum
    for info in client_updates.values():
        weight = info["num_samples"] / total_samples
        agg_weights += info["weights"] * weight
        agg_bias += info["bias"] * weight

    # Save the new global model
    save_global_model(agg_weights, agg_bias)
    logger.info("Global model aggregated and saved.")

@app.get("/model")
async def get_global_model():
    """Distribute the latest global model."""
    weights, bias = load_global_model()
    if weights is None:
        # Provide a default initialized model if none exists
        weights = np.zeros(10).tolist()
        bias = 0.0
    return {"weights": weights, "bias": bias}

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8001)
