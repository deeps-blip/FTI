import os
import numpy as np

MODELS_DIR = os.environ.get("MODELS_DIR", "data/global_models")
FRS_WEIGHTS_PATH = os.path.join(MODELS_DIR, "frs_weights.npy")
FRS_BIAS_PATH = os.path.join(MODELS_DIR, "frs_bias.npy")

class FederatedRiskScorer:
    def __init__(self):
        self.weights = None
        self.bias = None
        self.load_model()

    def load_model(self):
        try:
            if os.path.exists(FRS_WEIGHTS_PATH) and os.path.exists(FRS_BIAS_PATH):
                self.weights = np.load(FRS_WEIGHTS_PATH)
                self.bias = np.load(FRS_BIAS_PATH)
        except Exception as e:
            print(f"[!] Failed to load FRS model: {e}")
            self.weights = None
            self.bias = None

    def is_available(self):
        return self.weights is not None and self.bias is not None

    def predict_risk(self, feature_vector):
        """
        Returns a risk score between 0 and 100 based on the linear model prediction.
        """
        if not self.is_available():
            return None
        
        try:
            # Linear combination
            raw_score = np.dot(self.weights, feature_vector) + self.bias
            # Sigmoid to get a probability [0, 1]
            prob = 1.0 / (1.0 + np.exp(-raw_score))
            # Scale to [0, 100]
            scaled_score = prob * 100
            return round(scaled_score)
        except Exception as e:
            print(f"[!] FRS prediction failed: {e}")
            return None

    def save_model(self, weights, bias):
        try:
            os.makedirs(MODELS_DIR, exist_ok=True)
            np.save(FRS_WEIGHTS_PATH, weights)
            np.save(FRS_BIAS_PATH, bias)
            self.weights = weights
            self.bias = bias
        except Exception as e:
            print(f"[!] Failed to save FRS model: {e}")
