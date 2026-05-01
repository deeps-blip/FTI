import numpy as np

# Fixed feature dimension: 10
# 1. Intent: network_communication
# 2. Intent: persistence
# 3. Intent: credential_access
# 4. Obfuscation: packed_or_obfuscated
# 5. Behavior flow detected
# 6. Dynamic: network
# 7. Dynamic: process_injection
# 8. Dynamic: privilege
# 9. Dynamic: file_modification
# 10. Dynamic: execution

def extract_features(intents, obfuscation, behavior_flow, dynamic_findings):
    vector = np.zeros(10)
    
    # 1-3: Intents
    purposes = set()
    if intents:
        for i in intents:
            purposes.update(i.get("purposes", []))
            
    vector[0] = 1.0 if "network_communication" in purposes else 0.0
    vector[1] = 1.0 if "persistence" in purposes else 0.0
    vector[2] = 1.0 if "credential_access" in purposes else 0.0
    
    # 4: Obfuscation
    vector[3] = 1.0 if obfuscation.get("packed_or_obfuscated") else 0.0
    
    # 5: Behavior Flow
    vector[4] = 1.0 if behavior_flow else 0.0
    
    # 6-10: Dynamic Findings
    if dynamic_findings:
        vector[5] = float(dynamic_findings.get("network", 0))
        vector[6] = float(dynamic_findings.get("process_injection", 0))
        vector[7] = float(dynamic_findings.get("privilege", 0))
        vector[8] = float(dynamic_findings.get("file_modification", 0))
        vector[9] = float(dynamic_findings.get("execution", 0))
        
    return vector

def extract_label_from_verdict(verdict):
    """
    Returns 1 for malicious (high_risk_malware, suspicious_artifact)
    and 0 for benign (low_confidence_threat)
    """
    if verdict in ["high_risk_malware", "suspicious_artifact"]:
        return 1
    return 0

def build_feature_vector(summary):
    """Backward compatibility for existing code if needed"""
    return {
        "has_network": int("network_communication" in summary.get("behavioral_intent", {}).get("observed_function_purposes", [])),
        "has_persistence": int("persistence" in summary.get("behavioral_intent", {}).get("observed_function_purposes", [])),
        "has_crypto": int("crypto" in summary.get("behavioral_intent", {}).get("observed_function_purposes", [])),
        "packed": int(summary.get("packed_or_obfuscated", False)),
        "risk_score": summary.get("risk_score", 0)
    }
