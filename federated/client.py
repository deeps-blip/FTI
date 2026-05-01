import os
import json
import logging
import requests
import numpy as np
from sklearn.linear_model import SGDClassifier
from intelligence.feature_vector import extract_features, extract_label_from_verdict
from federated.local_model import FederatedRiskScorer

# Setup logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Config
FEATURES_DIR = os.environ.get("FEATURES_DIR", "data/features")
AGGREGATOR_URL = os.environ.get("AGGREGATOR_URL", "http://aggregator:8001")
CLIENT_ID = os.environ.get("CLIENT_ID", "fti-node-1")

def load_local_data():
    X = []
    y = []
    if not os.path.exists(FEATURES_DIR):
        logger.warning(f"Features directory {FEATURES_DIR} not found.")
        return X, y

    for entry in os.listdir(FEATURES_DIR):
        sample_dir = os.path.join(FEATURES_DIR, entry)
        if not os.path.isdir(sample_dir) or "__" not in entry:
            continue
            
        try:
            with open(os.path.join(sample_dir, "analysis.json"), "r") as f:
                analysis = json.load(f)
            with open(os.path.join(sample_dir, "threat_summary.json"), "r") as f:
                threat_summary = json.load(f)
                
            verdict = threat_summary.get("verdict")
            if not verdict:
                continue
                
            label = extract_label_from_verdict(verdict)
            
            # Extract features
            intents = analysis.get("intents", [])
            obfuscation = analysis.get("obfuscation", {})
            behavior_flow = analysis.get("behavior_flow", {})
            
            dynamic_analysis = analysis.get("dynamic_analysis", {})
            dynamic_findings = None
            if dynamic_analysis:
                dynamic_findings = dynamic_analysis.get("syscall_findings", {})

            features = extract_features(intents, obfuscation, behavior_flow, dynamic_findings)
            
            X.append(features)
            y.append(label)
        except Exception as e:
            logger.error(f"Error processing {entry}: {e}")

    return np.array(X), np.array(y)

def fetch_global_model():
    """Fetch the latest global model from the aggregator."""
    try:
        response = requests.get(f"{AGGREGATOR_URL}/model", timeout=5)
        response.raise_for_status()
        data = response.json()
        return np.array(data["weights"]), data["bias"]
    except Exception as e:
        logger.error(f"Failed to fetch global model: {e}")
        return None, None

def send_update(weights, bias, num_samples):
    """Send local model update to the aggregator."""
    try:
        payload = {
            "client_id": CLIENT_ID,
            "weights": weights.tolist(),
            "bias": float(bias),
            "num_samples": int(num_samples)
        }
        response = requests.post(f"{AGGREGATOR_URL}/update", json=payload, timeout=5)
        response.raise_for_status()
        logger.info("Successfully sent update to aggregator.")
    except Exception as e:
        logger.error(f"Failed to send update to aggregator: {e}")

def run_federated_round():
    """Run a single round of federated learning locally."""
    logger.info("Starting federated learning round...")
    
    # 1. Fetch Global Model
    global_weights, global_bias = fetch_global_model()
    if global_weights is None:
        logger.warning("Could not fetch global model. Proceeding with initialized zeros if no local model exists.")
        global_weights = np.zeros(10)
        global_bias = 0.0

    # 2. Load Local Data
    X, y = load_local_data()
    num_samples = len(X)
    
    if num_samples == 0:
        logger.info("No local data found. Skipping training.")
        # We can still save the global model locally to use it for scoring
        fl_scorer = FederatedRiskScorer()
        fl_scorer.save_model(global_weights, global_bias)
        return

    # 3. Train Local Model
    # SGDClassifier with log_loss acts like Logistic Regression
    clf = SGDClassifier(loss='log_loss', max_iter=1000, tol=1e-3, learning_rate='constant', eta0=0.01)
    
    # Initialize classifier with global weights (a hack for SGDClassifier to start from global weights)
    # The clean way is to initialize coef_ and intercept_ after a dummy fit, or use partial_fit.
    # We will use partial_fit to continue training from global weights if we can, but scikit-learn
    # requires classes to be known.
    classes = np.array([0, 1])
    clf.partial_fit(X, y, classes=classes)
    
    # Override with global weights and do partial fit again to simulate training from global
    clf.coef_ = np.array([global_weights])
    clf.intercept_ = np.array([global_bias])
    
    # Train locally for a few epochs
    for _ in range(5):
        clf.partial_fit(X, y)
        
    local_weights = clf.coef_[0]
    local_bias = clf.intercept_[0]
    
    logger.info(f"Local training complete on {num_samples} samples.")
    
    # 4. Send Update to Aggregator
    send_update(local_weights, local_bias, num_samples)
    
    # 5. Save locally so `risk_scorer.py` can use it
    fl_scorer = FederatedRiskScorer()
    fl_scorer.save_model(local_weights, local_bias)
    logger.info("Local model saved for scoring engine.")

if __name__ == "__main__":
    run_federated_round()
