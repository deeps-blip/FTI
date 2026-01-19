def build_feature_vector(summary):
    return {
        "has_network": int("network_communication" in summary["behavioral_intent"]["observed_function_purposes"]),
        "has_persistence": int("persistence" in summary["behavioral_intent"]["observed_function_purposes"]),
        "has_crypto": int("crypto" in summary["behavioral_intent"]["observed_function_purposes"]),
        "packed": int(summary.get("packed_or_obfuscated", False)),
        "risk_score": summary["risk_score"]
    }
